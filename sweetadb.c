//  THis mimics or atleast trys to "Samsung Galaxy S21 Ultra fingerprint"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

// ADB protocol values
#define A_CNXN  0x4e584e43u
#define A_OKAY  0x59414b4fu
#define A_CLSE  0x45534c43u
#define A_WRTE  0x45545257u
#define A_OPEN  0x4e45504fu
#define A_AUTH  0x48545541u

#define AUTH_TOKEN      1
#define AUTH_SIGNATURE  2
#define AUTH_RSAPUBLICKEY 3

#define ADB_VERSION 0x01000000u
#define ADB_MAXDATA 0x00040000u

#define MAX_STREAMS     32
#define MAX_CMDS        4096
#define MAX_IP_LEN      INET_ADDRSTRLEN
#define LOG_DIR         "mimic"
#define SESSION_DIR     "mimic/sessions"
#define PAYLOAD_DIR     "mimic/payloads"
typedef struct {
    uint32_t command;
    uint32_t arg0;
    uint32_t arg1;
    uint32_t data_length;
    uint32_t data_crc32;
    uint32_t magic;        // 0xFFFFFFFF 
} __attribute__((packed)) adb_msg;
typedef enum {
    ST_FREE = 0,
    ST_SHELL,
    ST_SYNC,
    ST_TCP,
    ST_JDWP,
    ST_OTHER
} stream_type;
typedef struct {
    uint32_t    local_id;
    uint32_t    remote_id;
    stream_type type;
    char        service[64];
} stream_t;
typedef struct {
    int         sock;
    char        ip[MAX_IP_LEN];
    uint16_t    port;
    struct timeval  conn_start;
    struct timeval  last_packet;
    stream_t    streams[MAX_STREAMS];
    int         nstreams;
    FILE       *session_fp;
    char        session_path[256];
    FILE       *json_fp;
    uint32_t    seq;
    int         auth_done;
    uint8_t     auth_token[20];
} conn_ctx;
static pthread_mutex_t g_ip_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE           *g_json_fp   = NULL;
static uint32_t g_crc32_table[256];
static void init_crc32_table(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc32_table[i] = c;
    }
}
static uint32_t crc32(const uint8_t *data, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = g_crc32_table[(c ^ data[i]) & 0xFF] ^ (c >> 8);
    return ~c;
}
static void mkdir_p(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = '\0'; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}
static double ms_since(const struct timeval *tv_base) {
    struct timeval now;
    gettimeofday(&now, NULL);
    return (now.tv_sec  - tv_base->tv_sec ) * 1000.0
         + (now.tv_usec - tv_base->tv_usec) / 1000.0;
}
static double ms_between(const struct timeval *a, const struct timeval *b) {
    return (b->tv_sec  - a->tv_sec ) * 1000.0
         + (b->tv_usec - a->tv_usec) / 1000.0;
}
static void update_ip_tracker(const char *ip) {
    char path[256];
    snprintf(path, sizeof(path), "%s/all_ips.txt", LOG_DIR);
    pthread_mutex_lock(&g_ip_mutex);
    FILE *f = fopen(path, "r");
    char  lines[65536] = {0};
    size_t llen = 0;
    if (f) {
        llen = fread(lines, 1, sizeof(lines) - 1, f);
        fclose(f);
    }
    char search[MAX_IP_LEN + 8];
    snprintf(search, sizeof(search), "%s ->", ip);
    char *pos = strstr(lines, search);
    if (pos) {
        char *arrow = strstr(pos, "-> ");
        if (arrow) {
            arrow += 3;
            int cnt = atoi(arrow);
            cnt++;
            char newcount[16];
            int nc = snprintf(newcount, sizeof(newcount), "%d", cnt);
            char *end = arrow;
            while (*end >= '0' && *end <= '9') end++;
            int oldnc = (int)(end - arrow);
            if (nc != oldnc) {
                memmove(arrow + nc, end, strlen(end) + 1);
                llen = llen + (nc - oldnc);
            }
            memcpy(arrow, newcount, nc);
        }
    } else {
        char entry[64];
        int elen = snprintf(entry, sizeof(entry), "%s -> 1\n", ip);
        if (llen + elen < (int)sizeof(lines)) {
            memcpy(lines + llen, entry, elen + 1);
            llen += elen;
        }
    }
    f = fopen(path, "w");
    if (f) { fwrite(lines, 1, llen, f); fclose(f); }
    pthread_mutex_unlock(&g_ip_mutex);
}
static FILE *open_session_file(const char *ip, char *out_path, size_t out_len) {
    int session_num = 0;
    char candidate[256];
    do {
        session_num++;
        snprintf(candidate, sizeof(candidate), "%s/%s_%04d.txt",
                 SESSION_DIR, ip, session_num);
    } while (access(candidate, F_OK) == 0 && session_num < 9999);
    snprintf(out_path, out_len, "%s", candidate);
    FILE *fp = fopen(out_path, "w");
    if (fp) {
        time_t now = time(NULL);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));
        fprintf(fp, "====================================================\n");
        fprintf(fp, "  ADB Honeypot — Session Log\n");
        fprintf(fp, "  IP      : %s\n", ip);
        fprintf(fp, "  Started : %s\n", ts);
        fprintf(fp, "====================================================\n\n");
        fflush(fp);
    }
    return fp;
}
static void log_command(conn_ctx *ctx,
                        const char *command_str,
                        const uint8_t *raw_data, uint32_t raw_len,
                        double base_ms, double jitter_ms)
{
    if (!ctx->session_fp) return;
    fprintf(ctx->session_fp, "%s -> %s\n", ctx->ip, command_str);
    if (raw_len > 0) {
        fprintf(ctx->session_fp, "[");
        uint32_t print_len = raw_len < 128 ? raw_len : 128;
        for (uint32_t i = 0; i < print_len; i++) {
            fprintf(ctx->session_fp, "%02x", raw_data[i]);
            if (i < print_len - 1) fprintf(ctx->session_fp, " ");
        }
        if (raw_len > 128) fprintf(ctx->session_fp, " ...(+%u bytes)", raw_len - 128);
        fprintf(ctx->session_fp, "]  %.2f+%.2f ms\n", base_ms, jitter_ms);
    } else {
        fprintf(ctx->session_fp, "[<no data>]  %.2f+%.2f ms\n", base_ms, jitter_ms);
    }
    fprintf(ctx->session_fp, "\n");
    fflush(ctx->session_fp);
}
static void log_json_event(conn_ctx *ctx,
                           const char *event_type,
                           const char *detail,
                           double elapsed_ms)
{
    if (!g_json_fp) return;
    time_t now = time(NULL);
    char escaped[1024] = {0};
    size_t ei = 0;
    for (size_t i = 0; detail && detail[i] && ei < sizeof(escaped) - 4; i++) {
        unsigned char c = (unsigned char)detail[i];
        if (c == '"')       { escaped[ei++] = '\\'; escaped[ei++] = '"'; }
        else if (c == '\\') { escaped[ei++] = '\\'; escaped[ei++] = '\\'; }
        else if (c < 0x20)  { ei += snprintf(escaped + ei, sizeof(escaped)-ei, "\\u%04x", c); }
        else                { escaped[ei++] = c; }
    }

    pthread_mutex_lock(&g_ip_mutex);
    fprintf(g_json_fp,
        "{\"ts\":%ld,\"ip\":\"%s\",\"port\":%u,\"seq\":%u,"
        "\"event\":\"%s\",\"detail\":\"%s\",\"elapsed_ms\":%.2f}\n",
        (long)now, ctx->ip, ctx->port, ctx->seq,
        event_type, escaped, elapsed_ms);
    fflush(g_json_fp);
    pthread_mutex_unlock(&g_ip_mutex);
}
static void dump_payload(conn_ctx *ctx, uint32_t stream_id,
                         const uint8_t *data, uint32_t len) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s_%ld_%u.bin",
             PAYLOAD_DIR, ctx->ip, (long)time(NULL), stream_id);
    FILE *f = fopen(path, "wb");
    if (f) { fwrite(data, 1, len, f); fclose(f); }
}
static int read_exact(int fd, void *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, (char*)buf + got, n - got);
        if (r <= 0) return -1;
        got += r;
    }
    return 0;
}
static int write_exact(int fd, const void *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, (const char*)buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += w;
    }
    return 0;
}
static int send_adb_msg(int sock,
                        uint32_t cmd, uint32_t arg0, uint32_t arg1,
                        const uint8_t *data, uint32_t data_len) {
    adb_msg m;
    m.command     = cmd;
    m.arg0        = arg0;
    m.arg1        = arg1;
    m.data_length = data_len;
    m.data_crc32  = data_len ? crc32(data, data_len) : 0;
    m.magic       = cmd ^ 0xFFFFFFFFu;
    if (write_exact(sock, &m, sizeof(m)) < 0) return -1;
    if (data_len && write_exact(sock, data, data_len) < 0) return -1;
    return 0;
}
static stream_t *find_stream(conn_ctx *ctx, uint32_t remote_id) {
    for (int i = 0; i < MAX_STREAMS; i++)
        if (ctx->streams[i].type != ST_FREE &&
            ctx->streams[i].remote_id == remote_id)
            return &ctx->streams[i];
    return NULL;
}

static stream_t *alloc_stream(conn_ctx *ctx) {
    for (int i = 0; i < MAX_STREAMS; i++)
        if (ctx->streams[i].type == ST_FREE)
            return &ctx->streams[i];
    return NULL;
}

static void free_stream(stream_t *s) {
    memset(s, 0, sizeof(*s));
    s->type = ST_FREE;
}
typedef struct { const char *probe; const char *response; } fake_resp_t;

static const fake_resp_t FAKE_RESPONSES[] = {
    { "id",
      "uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),"
      "1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),"
      "3003(inet),3006(net_bw_stats) context=u:r:shell:s0\n" },
    { "whoami",     "root\n" },
    { "uname",
      "Linux localhost 5.10.168-android13-4-00001-g31e18296e4eb-ab9648830 "
      "#1 SMP PREEMPT Thu Jan  1 00:00:00 UTC 1970\n" },
    { "cat /proc/version",
      "Linux version 5.10.168-android13 (clang version 14.0.7) "
      "#1 SMP PREEMPT\n" },
    { "getprop ro.build.version.release",  "14\n" },
    { "getprop ro.product.model",          "SM-G998B\n" },
    { "getprop ro.product.brand",          "samsung\n" },
    { "getprop ro.serialno",               "R5CW30XXXXX\n" },
    { "getprop",
      "ro.build.version.release=14\n"
      "ro.build.version.sdk=34\n"
      "ro.product.model=SM-G998B\n"
      "ro.product.brand=samsung\n"
      "ro.product.name=SM-G998B\n"
      "ro.product.device=p3s\n"
      "ro.serialno=R5CW30XXXXX\n"
      "ro.build.id=UQ1A.240105.004\n" },
    { "pm list packages",
      "package:com.android.settings\n"
      "package:com.android.phone\n"
      "package:com.samsung.android.app.smartcapture\n"
      "package:com.google.android.gms\n"
      "package:com.android.vending\n" },
    { "ls /data/local/tmp",   "" },
    { "ls /sdcard",
      "Alarms\nAndroid\nDCIM\nDocuments\nDownload\nMovies\nMusic\nNotifications\nPictures\nRingtones\n" },
    { "cat /etc/hosts",
      "127.0.0.1       localhost\n"
      "::1             ip6-localhost\n" },
    { "netstat",
      "Active Internet connections\n"
      "Proto Recv-Q Send-Q Local Address      Foreign Address    State\n"
      "tcp        0      0 0.0.0.0:5555       0.0.0.0:*          LISTEN\n" },
    { "ps",
      "USER           PID  PPID  VSZ   RSS  WCHAN   ADDR S NAME\n"
      "root             1     0  2040   912  SyS_epo  0 S init\n"
      "root          1234     1 12340  4096  unix_gc  0 S adbd\n" },
    { "mount",
      "/dev/block/dm-2 on / type ext4 (ro,relatime)\n"
      "tmpfs on /dev type tmpfs (rw,nosuid,noexec,relatime)\n"
      "tmpfs on /data/local/tmp type tmpfs (rw,nosuid,nodev,relatime)\n" },
    { "ifconfig",
      "wlan0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
      "        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255\n"
      "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
      "        inet 127.0.0.1  netmask 255.0.0.0\n" },
    { "cat /proc/cpuinfo",
      "Processor       : AArch64 Processor rev 14 (aarch64)\n"
      "Hardware        : Qualcomm Technologies, Inc LAHAINA\n"
      "model name      : Cortex-A78\n" },
    { "df",
      "Filesystem      Size  Used Avail Use% Mounted on\n"
      "/data           236G   18G  218G   8% /data\n" },
    { "env",
      "PATH=/sbin:/vendor/bin:/system/sbin:/system/bin:/system/xbin\n"
      "ANDROID_ROOT=/system\n"
      "SHELL=/system/bin/sh\n"
      "USER=root\n" },
    { "cat /proc/net/arp",
      "IP address       HW type  Flags  HW address          Mask  Device\n"
      "192.168.1.1      0x1      0x2    aa:bb:cc:dd:ee:ff   *     wlan0\n" },
    { NULL, NULL }
};
static const char *get_fake_response(const char *cmd) {
    for (int i = 0; FAKE_RESPONSES[i].probe; i++)
        if (strstr(cmd, FAKE_RESPONSES[i].probe))
            return FAKE_RESPONSES[i].response;
    return "";
}
static void handle_open(conn_ctx *ctx, const adb_msg *msg,
                        const uint8_t *data,
                        double base_ms, double jitter_ms)
{
    if (!data) return;
    char service[256];
    snprintf(service, sizeof(service), "%.*s",
             (int)msg->data_length, (const char*)data);

    stream_t *s = alloc_stream(ctx);
    if (!s) {
        send_adb_msg(ctx->sock, A_CLSE, msg->arg0, 0, NULL, 0);
        return;
    }
    s->remote_id = 0x1000 + (uint32_t)(s - ctx->streams);
    s->local_id  = msg->arg0;
    snprintf(s->service, sizeof(s->service), "%s", service);
    if (strncmp(service, "shell", 5) == 0)      s->type = ST_SHELL;
    else if (strncmp(service, "sync:", 5) == 0)  s->type = ST_SYNC;
    else if (strncmp(service, "tcp:", 4) == 0)   s->type = ST_TCP;
    else if (strncmp(service, "jdwp:", 5) == 0)  s->type = ST_JDWP;
    else                                          s->type = ST_OTHER;
    send_adb_msg(ctx->sock, A_OKAY, s->local_id, s->remote_id, NULL, 0);
    char detail[320];
    snprintf(detail, sizeof(detail), "OPEN service=%s local=%u remote=%u",
             service, s->local_id, s->remote_id);
    log_command(ctx, detail, data, msg->data_length, base_ms, jitter_ms);
    log_json_event(ctx, "stream_open", detail, ms_since(&ctx->conn_start));
    if (s->type == ST_SHELL) {
        const char *prompt = "# ";
        send_adb_msg(ctx->sock, A_WRTE, s->remote_id, s->local_id,
                     (const uint8_t*)prompt, (uint32_t)strlen(prompt));
    }
}
static void handle_write(conn_ctx *ctx, const adb_msg *msg,
                         const uint8_t *data,
                         double base_ms, double jitter_ms)
{
    stream_t *s = find_stream(ctx, msg->arg0);
    if (!s) return;
    send_adb_msg(ctx->sock, A_OKAY, s->local_id, s->remote_id, NULL, 0);
    if (!data || msg->data_length == 0) return;
    dump_payload(ctx, s->remote_id, data, msg->data_length);
    if (s->type == ST_SHELL) {
        char cmd[1024] = {0};
        uint32_t cmdlen = msg->data_length < sizeof(cmd)-1
                          ? msg->data_length : sizeof(cmd)-1;
        memcpy(cmd, data, cmdlen);
        for (int i = cmdlen-1; i >= 0 && (cmd[i]=='\n'||cmd[i]=='\r'); i--)
            cmd[i] = '\0';

        char label[1100];
        snprintf(label, sizeof(label), "SHELL_CMD: %s", cmd);
        log_command(ctx, label, data, msg->data_length, base_ms, jitter_ms);
        log_json_event(ctx, "shell_command", label,
                       ms_since(&ctx->conn_start));
        const char *resp = get_fake_response(cmd);
        char full_resp[2048];
        snprintf(full_resp, sizeof(full_resp), "%s# ", resp);
        send_adb_msg(ctx->sock, A_WRTE,
                     s->remote_id, s->local_id,
                     (const uint8_t*)full_resp,
                     (uint32_t)strlen(full_resp));
    }
    else if (s->type == ST_SYNC) {
        char label[256] = "SYNC_DATA";
        if (msg->data_length >= 4) {
            char sync_cmd[5] = {0};
            memcpy(sync_cmd, data, 4);
            snprintf(label, sizeof(label), "SYNC_CMD: %.4s", sync_cmd);
            if (memcmp(data, "SEND", 4) == 0) {
                snprintf(label, sizeof(label),
                         "SYNC_SEND (file push): %.*s",
                         (int)(msg->data_length > 8 ? msg->data_length - 8 : 0),
                         data + 8);
            }
        }
        log_command(ctx, label, data, msg->data_length, base_ms, jitter_ms);
        log_json_event(ctx, "sync_data", label,
                       ms_since(&ctx->conn_start));
        uint8_t sync_ok[8] = {'O','K','A','Y', 0,0,0,0};
        send_adb_msg(ctx->sock, A_WRTE,
                     s->remote_id, s->local_id,
                     sync_ok, sizeof(sync_ok));
    }
    else {
        char label[256];
        snprintf(label, sizeof(label), "STREAM_DATA service=%s len=%u",
                 s->service, msg->data_length);
        log_command(ctx, label, data, msg->data_length, base_ms, jitter_ms);
        log_json_event(ctx, "stream_data", label,
                       ms_since(&ctx->conn_start));
    }
}
static void handle_auth(conn_ctx *ctx, const adb_msg *msg,
                        const uint8_t *data,
                        double base_ms, double jitter_ms)
{
    char label[512];
    if (msg->arg0 == AUTH_TOKEN) {
        snprintf(label, sizeof(label), "AUTH_TOKEN (challenge from client)");
        send_adb_msg(ctx->sock, A_AUTH, AUTH_TOKEN, 0,
                     ctx->auth_token, sizeof(ctx->auth_token));
    } else if (msg->arg0 == AUTH_SIGNATURE) {
        snprintf(label, sizeof(label), "AUTH_SIGNATURE len=%u", msg->data_length);
        const char *banner =
            "device::ro.product.name=SM-G998B;"
            "ro.product.model=SM-G998B;"
            "ro.product.device=p3s;"
            "features=cmd,shell,dev,stat,ls,sync,send_recv\n";
        send_adb_msg(ctx->sock, A_CNXN, ADB_VERSION, ADB_MAXDATA,
                     (const uint8_t*)banner, (uint32_t)strlen(banner));
        ctx->auth_done = 1;
    } else if (msg->arg0 == AUTH_RSAPUBLICKEY) {
        snprintf(label, sizeof(label), "AUTH_RSAPUBLICKEY len=%u", msg->data_length);
        dump_payload(ctx, 0xFFFF0000u, data, msg->data_length);
        const char *banner =
            "device::ro.product.name=SM-G998B;"
            "ro.product.model=SM-G998B;"
            "features=cmd,shell,dev,stat,ls,sync,send_recv\n";
        send_adb_msg(ctx->sock, A_CNXN, ADB_VERSION, ADB_MAXDATA,
                     (const uint8_t*)banner, (uint32_t)strlen(banner));
        ctx->auth_done = 1;
    } else {
        snprintf(label, sizeof(label), "AUTH_UNKNOWN type=%u len=%u",
                 msg->arg0, msg->data_length);
    }
    log_command(ctx, label, data, msg->data_length, base_ms, jitter_ms);
    log_json_event(ctx, "auth", label, ms_since(&ctx->conn_start));
}
static void *handle_connection(void *arg) {
    conn_ctx *ctx = (conn_ctx*)arg;
    gettimeofday(&ctx->conn_start, NULL);
    ctx->last_packet = ctx->conn_start;
    srand((unsigned)time(NULL) ^ (unsigned)(uintptr_t)arg);
    for (int i = 0; i < 20; i++)
        ctx->auth_token[i] = (uint8_t)(rand() & 0xFF);
    ctx->session_fp = open_session_file(ctx->ip, ctx->session_path,
                                        sizeof(ctx->session_path));
    update_ip_tracker(ctx->ip);
    adb_msg msg;
    uint8_t *data = NULL;
    if (read_exact(ctx->sock, &msg, sizeof(msg)) < 0) goto done;
    if (msg.data_length > 0 && msg.data_length <= ADB_MAXDATA) {
        data = malloc(msg.data_length + 1);
        if (!data) goto done;
        if (read_exact(ctx->sock, data, msg.data_length) < 0) { free(data); goto done; }
        data[msg.data_length] = '\0';
    }
    if (msg.command == A_CNXN) {
        char label[512];
        snprintf(label, sizeof(label), "CNXN version=0x%08X maxdata=0x%08X banner=%.*s",
                 msg.arg0, msg.arg1,
                 data ? (int)msg.data_length : 0,
                 data ? (char*)data : "");
        log_command(ctx, label, data, msg.data_length, 0.0, 0.0);
        log_json_event(ctx, "cnxn", label, 0.0);
        if (data) { free(data); data = NULL; }
        const char *banner =
            "device::ro.product.name=SM-G998B;"
            "ro.product.model=SM-G998B;"
            "ro.product.device=p3s;"
            "ro.product.brand=samsung;"
            "ro.build.version.release=14;"
            "ro.build.version.sdk=34;"
            "features=cmd,shell,dev,stat,ls,sync,send_recv\n";
        send_adb_msg(ctx->sock, A_CNXN, ADB_VERSION, ADB_MAXDATA,
                     (const uint8_t*)banner, (uint32_t)strlen(banner));
    } else if (msg.command == A_AUTH) {
        double base = 0.0, jitter = 0.0;
        handle_auth(ctx, &msg, data, base, jitter);
        if (data) { free(data); data = NULL; }
    } else {
        if (data) free(data);
        goto done;
    }
    while (1) {
        struct timeval pkt_time;
        gettimeofday(&pkt_time, NULL);
        double base_ms   = ms_between(&ctx->last_packet, &pkt_time);
        ctx->last_packet = pkt_time;
        if (read_exact(ctx->sock, &msg, sizeof(msg)) < 0) break;
        struct timeval after_hdr;
        gettimeofday(&after_hdr, NULL);
        double jitter_ms = ms_between(&pkt_time, &after_hdr);
        data = NULL;
        if (msg.data_length > 0 && msg.data_length <= ADB_MAXDATA) {
            data = malloc(msg.data_length + 1);
            if (!data) break;
            if (read_exact(ctx->sock, data, msg.data_length) < 0) { free(data); break; }
            data[msg.data_length] = '\0';
        }
        ctx->seq++;
        switch (msg.command) {
            case A_OPEN:
                handle_open(ctx, &msg, data, base_ms, jitter_ms);
                break;
            case A_WRTE:
                handle_write(ctx, &msg, data, base_ms, jitter_ms);
                break;
            case A_CLSE: {
                stream_t *s = find_stream(ctx, msg.arg0);
                if (s) {
                    char label[128];
                    snprintf(label, sizeof(label),
                             "STREAM_CLOSE service=%s", s->service);
                    log_command(ctx, label, NULL, 0, base_ms, jitter_ms);
                    log_json_event(ctx, "stream_close", label,
                                   ms_since(&ctx->conn_start));
                    send_adb_msg(ctx->sock, A_CLSE,
                                 s->local_id, s->remote_id, NULL, 0);
                    free_stream(s);
                }
                break;
            }
            case A_AUTH:
                handle_auth(ctx, &msg, data, base_ms, jitter_ms);
                break;
            case A_OKAY:
                break;
            default: {
                char label[128];
                snprintf(label, sizeof(label),
                         "UNKNOWN_CMD 0x%08X", msg.command);
                log_command(ctx, label, data, msg.data_length, base_ms, jitter_ms);
                log_json_event(ctx, "unknown_cmd", label,
                               ms_since(&ctx->conn_start));
                break;
            }
        }

        if (data) { free(data); data = NULL; }
    }
done:
    if (data) free(data);
    if (ctx->session_fp) {
        time_t now = time(NULL);
        char ts[64];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));
        double total = ms_since(&ctx->conn_start);
        fprintf(ctx->session_fp,
                "\n====================================================\n"
                "  Session ended: %s\n"
                "  Duration     : %.0f ms\n"
                "  Packets rcvd : %u\n"
                "====================================================\n",
                ts, total, ctx->seq);
        fclose(ctx->session_fp);
    }
    close(ctx->sock);
    free(ctx);
    return NULL;
}
int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 5555;
    init_crc32_table();
    mkdir_p(LOG_DIR);
    mkdir_p(SESSION_DIR);
    mkdir_p(PAYLOAD_DIR);
    char json_path[256];
    snprintf(json_path, sizeof(json_path), "%s/events.jsonl", LOG_DIR);
    g_json_fp = fopen(json_path, "a");
    if (!g_json_fp) {
        perror("Cannot open events.jsonl");
        return 1;
    }
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { perror("socket"); return 1; }
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(port);
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(srv, 64) < 0) {
        perror("listen"); return 1;
    }
    printf("ADB Honeypot\n");
    printf("  Listening on port : %d\n", port);
    printf("  Logs directory    : ./%s/\n", LOG_DIR);
    printf("  Per-IP sessions   : ./%s/<ip>_NNNN.txt\n", SESSION_DIR);
    printf("  IP tracker        : ./%s/all_ips.txt\n", LOG_DIR);
    printf("  JSON events       : ./%s/events.jsonl\n", LOG_DIR);
    printf("  Payload dumps     : ./%s/\n\n", PAYLOAD_DIR); // basicaly does not work but what ev
    while (1) {
        struct sockaddr_in cli_addr;
        socklen_t cli_len = sizeof(cli_addr);
        int client = accept(srv, (struct sockaddr*)&cli_addr, &cli_len);
        if (client < 0) continue;
        conn_ctx *ctx = calloc(1, sizeof(conn_ctx));
        if (!ctx) { close(client); continue; }
        ctx->sock = client;
        ctx->port = ntohs(cli_addr.sin_port);
        inet_ntop(AF_INET, &cli_addr.sin_addr, ctx->ip, sizeof(ctx->ip));
        ctx->json_fp = g_json_fp;
        pthread_t tid;
        if (pthread_create(&tid, NULL, handle_connection, ctx) != 0) {
            free(ctx); close(client);
        } else {
            pthread_detach(tid);
        }
    }
    fclose(g_json_fp);
    close(srv);
    return 0;
}