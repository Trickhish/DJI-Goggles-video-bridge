#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <dirent.h>

/* ── Configuration ─────────────────────────────────────────────────── */
#define GADGET_PATH  "/sys/kernel/config/usb_gadget/dji"
#define FFS_MNT      "/dev/ffs-dji"
#define PC_PORT      5600
#define PORT_VIDEO   0x574A
#define PORT_DUML    0x7530
#define NODE_APP     0x02
#define RX_BUF_SZ    (256 * 1024)   /* 256 KB rx accumulation buffer  */
#define PIPE_CAP     (16  * 1024)   /* 16 KB video pipe = ~21 ms @ 6M */

/* ── FunctionFS event types ────────────────────────────────────────── */
#define FFS_BIND    0
#define FFS_UNBIND  1
#define FFS_ENABLE  2
#define FFS_DISABLE 3
#define FFS_SETUP   4

/* ── AOA bRequest codes ────────────────────────────────────────────── */
#define AOA_GET_PROTOCOL    51
#define AOA_SEND_STRING     52
#define AOA_START_ACCESSORY 53

/* FunctionFS event: usb_ctrlrequest (8B) + type (1B) + pad (3B) */
typedef struct __attribute__((packed)) {
    uint8_t  bRequestType;
    uint8_t  bRequest;
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;
    uint8_t  type;
    uint8_t  _pad[3];
} ffs_event_t;

/* ── Global state ──────────────────────────────────────────────────── */
static volatile int g_running     = 1;
static volatile int g_enabled     = 0;
static volatile int g_vid_started = 0;
static volatile uint16_t g_seq    = 1;

static int g_ep0    = -1;
static int g_epout  = -1;   /* bulk OUT: goggles → Pi  */
static int g_epin   = -1;   /* bulk IN:  Pi → goggles  */
static int g_tcpsrv = -1;
static int g_tcpcli = -1;
static int g_vpipe[2] = {-1, -1};  /* video pipe [0]=rd [1]=wr */

static pthread_mutex_t g_epin_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_cli_mtx  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_enb_mtx  = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_enb_cv   = PTHREAD_COND_INITIALIZER;

/* ── CRC ────────────────────────────────────────────────────────────── */
static uint8_t crc8(const uint8_t *d, int n)
{
    uint8_t c = 0x77;
    while (n--) {
        uint8_t b = *d++;
        for (int i = 0; i < 8; i++) {
            uint8_t m = (c ^ b) & 1;
            c >>= 1; if (m) c ^= 0x8C;
            b >>= 1;
        }
    }
    return c;
}

static uint16_t crc16(const uint8_t *d, int n)
{
    uint16_t c = 0x3692;
    while (n--) {
        uint8_t b = *d++;
        for (int i = 0; i < 8; i++) {
            uint16_t m = (c ^ b) & 1;
            c >>= 1; if (m) c ^= 0x8408;
            b >>= 1;
        }
    }
    return c;
}

/* ── Sysfs helpers ─────────────────────────────────────────────────── */
static void fs_write(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return;
    write(fd, val, strlen(val));
    close(fd);
}

static void mkpath(const char *p)
{
    char t[256]; snprintf(t, sizeof t, "%s", p);
    for (char *s = t + 1; *s; s++)
        if (*s == '/') { *s = '\0'; mkdir(t, 0755); *s = '/'; }
    mkdir(t, 0755);
}

/* ── Gadget lifecycle ──────────────────────────────────────────────── */
static void gadget_destroy(void)
{
    fs_write(GADGET_PATH "/UDC", "");
    system("umount " FFS_MNT " 2>/dev/null");
    system("rm -f '" GADGET_PATH "/configs/c.1/ffs.dji'");
    system("rmdir " GADGET_PATH "/configs/c.1/strings/0x409 "
                   GADGET_PATH "/configs/c.1 "
                   GADGET_PATH "/functions/ffs.dji "
                   GADGET_PATH "/strings/0x409 "
                   GADGET_PATH " 2>/dev/null");
}

static void gadget_create(uint16_t vid, uint16_t pid)
{
    char v[32];
    mkpath(GADGET_PATH "/strings/0x409");
    mkpath(GADGET_PATH "/configs/c.1/strings/0x409");
    mkpath(GADGET_PATH "/functions/ffs.dji");
    mkdir(FFS_MNT, 0755);

    snprintf(v, sizeof v, "0x%04x", vid); fs_write(GADGET_PATH "/idVendor",  v);
    snprintf(v, sizeof v, "0x%04x", pid); fs_write(GADGET_PATH "/idProduct", v);
    fs_write(GADGET_PATH "/bcdUSB",   "0x0200");
    fs_write(GADGET_PATH "/bcdDevice","0x0100");
    fs_write(GADGET_PATH "/strings/0x409/manufacturer", "Google Inc.");
    fs_write(GADGET_PATH "/strings/0x409/product",      "Android");
    fs_write(GADGET_PATH "/strings/0x409/serialnumber", "0123456789ABCDEF");
    fs_write(GADGET_PATH "/configs/c.1/bmAttributes",   "0x80");
    fs_write(GADGET_PATH "/configs/c.1/MaxPower",        "500");
    fs_write(GADGET_PATH "/configs/c.1/strings/0x409/configuration", "DJI");

    if (access(GADGET_PATH "/configs/c.1/ffs.dji", F_OK) != 0)
        symlink(GADGET_PATH "/functions/ffs.dji",
                GADGET_PATH "/configs/c.1/ffs.dji");

    system("mount -t functionfs dji " FFS_MNT " 2>/dev/null");
}

static void gadget_bind(void)
{
    DIR *d = opendir("/sys/class/udc/");
    if (!d) { fprintf(stderr, "[gadget] no UDC found\n"); return; }
    struct dirent *e; char udc[64] = "";
    while ((e = readdir(d)))
        if (e->d_name[0] != '.') { strncpy(udc, e->d_name, 63); break; }
    closedir(d);
    if (!udc[0]) { fprintf(stderr, "[gadget] no UDC\n"); return; }
    fs_write(GADGET_PATH "/UDC", udc);
    printf("[gadget] bound → %s\n", udc);
}

/* ── FunctionFS descriptors (pre-built binary) ─────────────────────── */
/*
 *  Header : magic=1, total_len=62, fs_count=3, hs_count=3
 *  FS     : interface(9) + EP1-OUT-64(7) + EP2-IN-64(7)
 *  HS     : interface(9) + EP1-OUT-512(7) + EP2-IN-512(7)
 */
static const uint8_t FFS_DESCS[] = {
    0x01,0x00,0x00,0x00, 0x3E,0x00,0x00,0x00,
    0x03,0x00,0x00,0x00, 0x03,0x00,0x00,0x00,
    /* FS interface */
    0x09,0x04,0x00,0x00,0x02,0xFF,0xFF,0x00,0x00,
    /* FS EP1 OUT bulk 64 */
    0x07,0x05,0x01,0x02,0x40,0x00,0x00,
    /* FS EP2 IN  bulk 64 */
    0x07,0x05,0x81,0x02,0x40,0x00,0x00,
    /* HS interface */
    0x09,0x04,0x00,0x00,0x02,0xFF,0xFF,0x00,0x00,
    /* HS EP1 OUT bulk 512 */
    0x07,0x05,0x01,0x02,0x00,0x02,0x00,
    /* HS EP2 IN  bulk 512 */
    0x07,0x05,0x81,0x02,0x00,0x02,0x00,
};
static const uint8_t FFS_STRS[] = {
    0x02,0x00,0x00,0x00, 0x10,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,
};

/* ── DUML TX ────────────────────────────────────────────────────────── */
static int duml_build(uint8_t dst, uint8_t ct, uint8_t cs, uint8_t ci,
                      const uint8_t *pay, int plen, uint8_t *buf)
{
    int ilen = 13 + plen;
    uint8_t *in = buf + 8;

    in[0] = 0x55;
    uint16_t lv = (uint16_t)((1u << 10) | (unsigned)ilen);
    in[1] = lv & 0xFF; in[2] = (lv >> 8) & 0xFF;
    in[3] = crc8(in, 3);
    in[4] = NODE_APP; in[5] = dst;
    uint16_t s = g_seq++;
    in[6] = s & 0xFF; in[7] = (s >> 8) & 0xFF;
    in[8] = ct; in[9] = cs; in[10] = ci;
    if (plen > 0) memcpy(in + 11, pay, plen);
    uint16_t c = crc16(in, ilen - 2);
    in[ilen-2] = c & 0xFF; in[ilen-1] = (c >> 8) & 0xFF;

    buf[0]=0x55; buf[1]=0xCC;
    buf[2] = PORT_DUML & 0xFF; buf[3] = (PORT_DUML >> 8) & 0xFF;
    buf[4] = ilen & 0xFF;      buf[5] = (ilen >> 8) & 0xFF;
    buf[6] = 0; buf[7] = 0;
    return 8 + ilen;
}

static void send_duml(uint8_t dst, uint8_t ct, uint8_t cs, uint8_t ci,
                      const uint8_t *pay, int plen)
{
    uint8_t buf[512];
    int n = duml_build(dst, ct, cs, ci, pay, plen, buf);
    pthread_mutex_lock(&g_epin_mtx);
    if (g_epin >= 0) write(g_epin, buf, n);
    pthread_mutex_unlock(&g_epin_mtx);
}

/* ── Magic / video-start payloads ──────────────────────────────────── */
static const uint8_t M99[] = {
    0x02,0x02,0x00,0x00,0xD5,0x07,0x00,0x00,
    0x00,0x00,0x00,0x13,0x00,0x0D,0x00,
    0x63,0x61,0x6D,0x63,0x61,0x70,0x5F,
    0x63,0x6F,0x6D,0x6D,0x6F,0x6E,
    0x00,0x00,0x00,0x00,
};
static const uint8_t M88[] = {
    0x17,0x00,0x00,0x23,0x00,
    0x41,0x50,0x50,
    0x00,0x00,0x00,0x00,0x00,0x02,
};

static void send_magic(void)
{
    send_duml(0x28, 0x40, 0x00, 0x99, M99, sizeof M99);
    send_duml(0x3C, 0x40, 0x00, 0x88, M88, sizeof M88);
}

static void *keepalive_fn(void *unused)
{
    (void)unused;
    while (g_running) {
        sleep(5);
        if (g_running && g_vid_started) send_magic();
    }
    return NULL;
}

static void *vidstart_fn(void *unused)
{
    (void)unused;
    usleep(100000);
    printf("[session] video start sequence\n");

    send_magic();                              usleep(200000);

    uint8_t on = 0x01;
    send_duml(0x0E, 0x40, 0x09, 0x09, &on, 1); usleep(200000);
    send_duml(0x0E, 0x40, 0x09, 0x1A, &on, 1); usleep(100000);

    uint8_t lv[48]; memset(lv, 0, sizeof lv);
    lv[0]=0x01; lv[4]=0x37;
    send_duml(0x59, 0x40, 0x07, 0x1E, lv, sizeof lv); usleep(200000);

    send_duml(0x09, 0x40, 0x09, 0x06, &on, 1); usleep(100000);
    send_duml(0x0E, 0x40, 0x09, 0x06, &on, 1); usleep(100000);

    send_magic();
    return NULL;
}

/* ── Video pipe → TCP ──────────────────────────────────────────────── */
static void push_video(const uint8_t *d, int n)
{
    /* Non-blocking: drop tail if pipe full */
    while (n > 0) {
        ssize_t w = write(g_vpipe[1], d, n);
        if (w < 0) break;
        d += w; n -= (int)w;
    }
}

static void *tcp_sender_fn(void *unused)
{
    (void)unused;
    static uint8_t tb[65536];
    while (g_running) {
        ssize_t r = read(g_vpipe[0], tb, sizeof tb);
        if (r <= 0) { usleep(1000); continue; }

        pthread_mutex_lock(&g_cli_mtx);
        int fd = g_tcpcli;
        pthread_mutex_unlock(&g_cli_mtx);

        if (fd < 0) continue;
        if (send(fd, tb, (size_t)r, MSG_NOSIGNAL) < 0) {
            pthread_mutex_lock(&g_cli_mtx);
            close(g_tcpcli); g_tcpcli = -1;
            pthread_mutex_unlock(&g_cli_mtx);
            printf("[tcp] client disconnected\n");
        }
    }
    return NULL;
}

static void *tcp_accept_fn(void *unused)
{
    (void)unused;
    struct sockaddr_in a; socklen_t al = sizeof a;
    while (g_running) {
        int conn = accept(g_tcpsrv, (struct sockaddr *)&a, &al);
        if (conn < 0) { if (errno == EINTR) continue; usleep(10000); continue; }
        int f = 1; setsockopt(conn, IPPROTO_TCP, TCP_NODELAY, &f, sizeof f);
        int sndbuf = 32768;
        setsockopt(conn, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
        printf("[tcp] client connected\n");
        pthread_mutex_lock(&g_cli_mtx);
        if (g_tcpcli >= 0) close(g_tcpcli);
        g_tcpcli = conn;
        pthread_mutex_unlock(&g_cli_mtx);
    }
    return NULL;
}

/* ── DUML RX dispatch ──────────────────────────────────────────────── */
static void dispatch_duml(const uint8_t *inner, int ilen)
{
    if (ilen < 11 || inner[0] != 0x55) {
        if (ilen > 4) push_video(inner, ilen);
        return;
    }

    uint8_t src = inner[4];
    uint8_t ct  = inner[8];
    uint8_t cs  = inner[9];
    uint8_t ci  = inner[10];
    const uint8_t *pay = inner + 11;
    int plen = (ilen > 13) ? ilen - 13 : 0;

    /* Raw H.264 Annex-B in payload */
    if (plen > 4 && pay[0]==0 && pay[1]==0 && pay[2]==0 && pay[3]==1) {
        push_video(pay, plen);
        return;
    }

    /* ACK if requested */
    if (ct & 0x40) {
        uint8_t ack = 0x00;
        send_duml(src, 0x20, cs, ci, &ack, 1);
    }

    /* Session-start trigger */
    if (cs == 0x09 && ci == 0x08) {
        if (!(ct & 0x40)) {
            uint8_t ack = 0x00;
            send_duml(src, 0x20, 0x09, 0x08, &ack, 1);
        }
        if (!g_vid_started) {
            g_vid_started = 1;
            pthread_t t;
            pthread_create(&t, NULL, vidstart_fn, NULL);
            pthread_detach(t);
        }
    }
}

/* ── Probe thread: nudge goggles if silent after 1 s ───────────────── */
static void *probe_fn(void *unused)
{
    (void)unused;
    sleep(1);
    if (!g_vid_started) {
        printf("[probe] silent — sending session probe\n");
        uint8_t z = 0;
        send_duml(0x09, 0x40, 0x09, 0x08, &z, 1); usleep(500000);
        send_duml(0xFF, 0x40, 0x09, 0x08, &z, 1);
    }
    return NULL;
}

/* ── Bulk RX loop ──────────────────────────────────────────────────── */
static void *bulk_rx_fn(void *unused)
{
    (void)unused;
    static uint8_t buf[RX_BUF_SZ];
    int blen = 0;

    while (g_running) {
        /* Wait for ENABLE */
        pthread_mutex_lock(&g_enb_mtx);
        while (g_running && !g_enabled)
            pthread_cond_wait(&g_enb_cv, &g_enb_mtx);
        pthread_mutex_unlock(&g_enb_mtx);
        if (!g_running) break;

        /* Wait for endpoint files (up to 2 s) */
        for (int i = 0; i < 20; i++) {
            if (access(FFS_MNT "/ep1", F_OK) == 0 &&
                access(FFS_MNT "/ep2", F_OK) == 0) break;
            usleep(100000);
        }
        g_epout = open(FFS_MNT "/ep1", O_RDONLY);
        pthread_mutex_lock(&g_epin_mtx);
        g_epin  = open(FFS_MNT "/ep2", O_WRONLY);
        pthread_mutex_unlock(&g_epin_mtx);

        if (g_epout < 0 || g_epin < 0) {
            fprintf(stderr, "[rx] failed to open endpoints\n");
            sleep(1); continue;
        }
        printf("[rx] endpoints open\n");
        blen = 0;

        /* Probe if goggles are silent */
        pthread_t probe;
        pthread_create(&probe, NULL, probe_fn, NULL);
        pthread_detach(probe);

        /* ── Hot loop ─────────────────────────────────────────────── */
        while (g_running && g_enabled) {
            ssize_t r = read(g_epout, buf + blen, sizeof(buf) - blen);
            if (r < 0) {
                if (errno == EINTR) continue;
                break;
            }
            blen += (int)r;

            int pos = 0;
            while (pos < blen) {
                if (blen - pos < 2) break;
                /* Scan for 55 CC framing */
                if (buf[pos] != 0x55 || buf[pos+1] != 0xCC) { pos++; continue; }
                if (blen - pos < 8) break;
                uint16_t port = (uint16_t)(buf[pos+2] | (buf[pos+3] << 8));
                uint16_t ilen = (uint16_t)(buf[pos+4] | (buf[pos+5] << 8));
                if (ilen == 0) { pos++; continue; }
                if (blen - pos < 8 + ilen) break;

                const uint8_t *inner = buf + pos + 8;
                if (port == PORT_VIDEO)
                    push_video(inner, ilen);
                else if (port == PORT_DUML)
                    dispatch_duml(inner, ilen);
                else
                    push_video(inner, ilen);   /* unknown port → forward */

                pos += 8 + ilen;
            }

            /* Compact: move leftover bytes to front */
            if (pos > 0) {
                blen -= pos;
                if (blen > 0) memmove(buf, buf + pos, blen);
            }
        }
        /* ─────────────────────────────────────────────────────────── */

        close(g_epout); g_epout = -1;
        pthread_mutex_lock(&g_epin_mtx);
        close(g_epin); g_epin = -1;
        pthread_mutex_unlock(&g_epin_mtx);
        g_vid_started = 0;
        printf("[rx] disconnected, waiting for reconnect\n");
    }
    return NULL;
}

/* ── ep0 event loop ────────────────────────────────────────────────── */
static void *ep0_fn(void *unused)
{
    (void)unused;
    ffs_event_t ev;

    while (g_running) {
        ssize_t r = read(g_ep0, &ev, sizeof ev);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r < (ssize_t)sizeof ev) continue;

        switch (ev.type) {
        case FFS_BIND:   printf("[ep0] BIND\n");   break;
        case FFS_UNBIND: printf("[ep0] UNBIND\n"); break;

        case FFS_ENABLE:
            printf("[ep0] ENABLE\n");
            pthread_mutex_lock(&g_enb_mtx);
            g_enabled = 1;
            pthread_cond_signal(&g_enb_cv);
            pthread_mutex_unlock(&g_enb_mtx);
            break;

        case FFS_DISABLE:
            printf("[ep0] DISABLE\n");
            pthread_mutex_lock(&g_enb_mtx);
            g_enabled = 0;
            pthread_mutex_unlock(&g_enb_mtx);
            break;

        case FFS_SETUP:
            if (ev.bRequest == AOA_GET_PROTOCOL) {
                uint8_t v[2] = {0x02, 0x00};
                write(g_ep0, v, 2);

            } else if (ev.bRequest == AOA_SEND_STRING) {
                /* Goggles send us a string — read it then ACK */
                if (ev.wLength > 0) {
                    uint8_t tmp[256];
                    read(g_ep0, tmp, ev.wLength < sizeof tmp ? ev.wLength : sizeof tmp);
                }
                write(g_ep0, "", 0);

            } else if (ev.bRequest == AOA_START_ACCESSORY) {
                write(g_ep0, "", 0);   /* ACK — already in AOA mode */
            }
            break;
        }
    }
    return NULL;
}

/* ── Signal handler ────────────────────────────────────────────────── */
static void on_signal(int s) { (void)s; g_running = 0; }

/* ── Periodic stats ────────────────────────────────────────────────── */
static void *stats_fn(void *unused)
{
    (void)unused;
    while (g_running) {
        sleep(10);
        if (g_vid_started) printf("[stats] stream active\n");
    }
    return NULL;
}

/* ── Main ──────────────────────────────────────────────────────────── */
int main(void)
{
    if (geteuid() != 0) { fprintf(stderr, "Run as root\n"); return 1; }
    setvbuf(stdout, NULL, _IOLBF, 0);  /* line-buffered stdout */

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    /* Video pipe — non-blocking write end */
    if (pipe(g_vpipe) < 0) { perror("pipe"); return 1; }
    fcntl(g_vpipe[1], F_SETFL, O_NONBLOCK);
    /* Set pipe capacity (Linux-specific; ignore error on older kernels) */
    fcntl(g_vpipe[0], F_SETPIPE_SZ, PIPE_CAP);

    /* TCP server */
    g_tcpsrv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(g_tcpsrv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    struct sockaddr_in sa = {
        .sin_family      = AF_INET,
        .sin_port        = htons(PC_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };
    bind(g_tcpsrv, (struct sockaddr *)&sa, sizeof sa);
    listen(g_tcpsrv, 1);
    printf("[tcp] listening on :%d\n", PC_PORT);

    /* Gadget setup — start directly in AOA mode */
    gadget_destroy();
    usleep(300000);
    gadget_create(0x18d1, 0x2d00);

    /* Open ep0, write FunctionFS descriptors and strings */
    g_ep0 = open(FFS_MNT "/ep0", O_RDWR);
    if (g_ep0 < 0) { perror("open ep0"); return 1; }
    write(g_ep0, FFS_DESCS, sizeof FFS_DESCS);
    write(g_ep0, FFS_STRS,  sizeof FFS_STRS);
    printf("[ffs] descriptors written\n");

    gadget_bind();

    /* Start threads */
    pthread_t t_ep0, t_rx, t_acc, t_snd, t_ka, t_stats;
    pthread_create(&t_ep0,   NULL, ep0_fn,       NULL);
    pthread_create(&t_rx,    NULL, bulk_rx_fn,   NULL);
    pthread_create(&t_acc,   NULL, tcp_accept_fn,NULL);
    pthread_create(&t_snd,   NULL, tcp_sender_fn,NULL);
    pthread_create(&t_ka,    NULL, keepalive_fn, NULL);
    pthread_create(&t_stats, NULL, stats_fn,     NULL);

    printf("[ready] Connect DJI Goggles USB-C → Pi Zero micro-USB\n");
    printf("[ready] ffplay tcp://PI_IP:%d -vcodec h264 -fflags nobuffer"
           " -flags low_delay -probesize 32 -framedrop\n\n", PC_PORT);

    while (g_running) usleep(200000);

    puts("\nStopping...");
    gadget_destroy();
    return 0;
}
