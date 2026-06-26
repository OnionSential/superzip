#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define NAME  "SuperZip-MIX"
#define MAGIC "MX03"

static int squash(int d) {
    static const int t[33] = {1,2,3,6,10,16,27,45,73,120,194,310,488,747,1101,1546,
        2047,2549,2994,3348,3607,3785,3901,3975,4022,4050,4068,4079,4085,4089,4092,4093,4094};
    if (d >  2047) return 4095;
    if (d < -2047) return 0;
    int w = d & 127; d = (d >> 7) + 16;
    return (t[d] * (128 - w) + t[d + 1] * w + 64) >> 7;
}
static int strt[4096];
static void init_stretch(void) {
    int pi = 0;
    for (int x = -2047; x <= 2047; x++) { int i = squash(x); for (int j = pi; j <= i; j++) strt[j] = x; pi = i + 1; }
    for (int j = pi; j < 4096; j++) strt[j] = 2047;
}
static inline int stretch(int p) { return strt[p]; }
static inline int clamp2047(int x) { return x < -2047 ? -2047 : (x > 2047 ? 2047 : x); }

#define NCTX 7
#define CBITS 22
#define CSIZE (1u << CBITS)

static const uint64_t OMASK[NCTX] = {
    0ULL, 0xFFULL, 0xFFFFULL, 0xFFFFFFULL, 0xFFFFFFFFULL,
    0xFFFFFFFFFFULL, 0xFFFFFFFFFFFFULL
};
static uint16_t *ct[NCTX];
static uint64_t hist = 0;

typedef struct {
    uint32_t *table;
    int tbits;
    int minlen;
    size_t mpos;
    int mlen;
} MatchModel;

static const uint8_t *buf;
static size_t cur_i = 0;
static MatchModel mm[2];

static uint32_t mm_hash(MatchModel *M, size_t i) {
    uint32_t h = 0;
    for (size_t j = i + 1 - M->minlen; j <= i; j++) h = h * 0x9E3779B1u + buf[j] + 1;
    return h & ((1u << M->tbits) - 1);
}

static int mm_predict(MatchModel *M, int node, int bitpos) {
    if (M->mlen <= 0 || M->mpos >= cur_i) return 0;
    int e = buf[M->mpos], k = bitpos;
    if ((node ^ (1 << k)) != (e >> (8 - k))) return 0;
    int pb = (e >> (7 - k)) & 1;
    int conf = (M->mlen < 28 ? M->mlen : 28) * 64;
    return pb ? conf : -conf;
}

static void mm_update(MatchModel *M, size_t i, int c) {
    if (M->mlen > 0 && M->mpos < cur_i && buf[M->mpos] == c) { M->mpos++; if (M->mlen < 65535) M->mlen++; }
    else M->mlen = 0;
    if ((int)(i + 1) >= M->minlen) {
        uint32_t h = mm_hash(M, i);
        if (M->mlen == 0) {
            uint32_t cand = M->table[h];
            if (cand) { M->mpos = cand - 1; M->mlen = M->minlen; if (M->mpos >= i + 1) M->mlen = 0; }
        }
        M->table[h] = (uint32_t)(i + 2);
    }
}

#define APM_CTX 256
#define APM_BK  33
static uint16_t *apm_t;
static int apm_idx;

static void apm_init_table(void) {
    apm_t = malloc(APM_CTX * APM_BK * sizeof(uint16_t));
    for (int cx = 0; cx < APM_CTX; cx++)
        for (int j = 0; j < APM_BK; j++)
            apm_t[cx * APM_BK + j] = (uint16_t)squash((j - 16) * 128);
    int seg = s >> 7; if (seg > APM_BK - 2) seg = APM_BK - 2;
    int w = s & 127;
    int base = cx * APM_BK + seg;
    int lo = apm_t[base], hi = apm_t[base + 1];
    apm_idx = (w < 64) ? base : base + 1;
    int p2 = (lo * (128 - w) + hi * w) >> 7;
    if (p2 < 1) p2 = 1;
    if (p2 > 4094) p2 = 4094;
    return p2;
}
static void apm_update(int y) {
    int v = apm_t[apm_idx];
    v += ((y << 12) - v) >> 6;
    apm_t[apm_idx] = (uint16_t)v;
}

#define NIN (NCTX + 2)
#define MIXSHIFT 10
static int64_t mixw[NIN];
static int st[NIN], idx[NCTX], last_p;


static int predict(int node, int bitpos) {
    for (int m = 0; m < NCTX; m++) {
        uint64_t c = (hist & OMASK[m]) + 1;
        uint64_t h64 = (c + (uint64_t)m * 0x9E3779B97F4A7C15ULL) * 0xff51afd7ed558ccdULL;
        h64 ^= h64 >> 33;
        uint32_t h = (uint32_t)h64 ^ ((uint32_t)node * 0x9E3779B1u);
        uint32_t id = h & (CSIZE - 1);
        idx[m] = id;
        st[m] = stretch(ct[m][id]);
    }
    st[NCTX]     = mm_predict(&mm[0], node, bitpos);
    st[NCTX + 1] = mm_predict(&mm[1], node, bitpos);

    int64_t dot = 0; for (int i = 0; i < NIN; i++) dot += (int64_t)st[i] * mixw[i];
    int s = clamp2047((int)(dot >> 16));
    int p = squash(s);
    if (p < 1) p = 1;
    if (p > 4094) p = 4094;
    last_p = p;

    int cx = (int)(hist & 0xFF);
    int p2 = apm_apply(p, cx);
    return p2;
}
static void update_models(int y) {
    int err = (y << 12) - last_p;
    for (int i = 0; i < NIN; i++) {
        mixw[i] += ((int64_t)st[i] * err) >> MIXSHIFT;
        if (mixw[i] >  (1 << 24)) mixw[i] =  (1 << 24);
        if (mixw[i] < -(1 << 24)) mixw[i] = -(1 << 24);
    }
    for (int m = 0; m < NCTX; m++) {
        int pp = ct[m][idx[m]]; pp += ((y << 12) - pp) >> 5; ct[m][idx[m]] = (uint16_t)pp;
    }
    apm_update(y);
}
static void post_byte(size_t i, int c) {
    mm_update(&mm[0], i, c);
    mm_update(&mm[1], i, c);
    hist = (hist << 8) | (uint64_t)c;
}

typedef struct { uint8_t *out; size_t pos; uint32_t x1, x2; } ENC;
static inline void enc_bit(ENC *e, int bit, int p) {
    uint32_t r = e->x2 - e->x1;
    uint32_t xmid = e->x1 + (r >> 12) * p + (((r & 0xfff) * p) >> 12);
    if (bit) e->x2 = xmid; else e->x1 = xmid + 1;
    while (((e->x1 ^ e->x2) & 0xff000000u) == 0) { e->out[e->pos++] = e->x2 >> 24; e->x1 <<= 8; e->x2 = (e->x2 << 8) | 0xff; }
}
static void enc_flush(ENC *e) { for (int i = 0; i < 4; i++) { e->out[e->pos++] = e->x1 >> 24; e->x1 <<= 8; } }
typedef struct { const uint8_t *in; size_t pos, len; uint32_t x1, x2, x; } DEC;
static inline uint32_t dget(DEC *d) { return d->pos < d->len ? d->in[d->pos++] : 0; }
static void dec_init(DEC *d) { d->x1 = 0; d->x2 = 0xffffffffu; d->x = 0; for (int i = 0; i < 4; i++) d->x = (d->x << 8) | dget(d); }
static inline int dec_bit(DEC *d, int p) {
    uint32_t r = d->x2 - d->x1;
    uint32_t xmid = d->x1 + (r >> 12) * p + (((r & 0xfff) * p) >> 12);
    int bit = (d->x <= xmid);
    if (bit) d->x2 = xmid; else d->x1 = xmid + 1;
    while (((d->x1 ^ d->x2) & 0xff000000u) == 0) { d->x1 <<= 8; d->x2 = (d->x2 << 8) | 0xff; d->x = (d->x << 8) | dget(d); }
    return bit;
}

static void all_init(void) {
    init_stretch();
    for (int m = 0; m < NCTX; m++) { ct[m] = malloc(CSIZE * sizeof(uint16_t)); for (uint32_t i = 0; i < CSIZE; i++) ct[m][i] = 2048; }
    mm[0].tbits = 22; mm[0].minlen = 6; mm[0].table = calloc(1u << mm[0].tbits, sizeof(uint32_t));
    mm[1].tbits = 20; mm[1].minlen = 4; mm[1].table = calloc(1u << mm[1].tbits, sizeof(uint32_t));
    mm[0].mpos = mm[1].mpos = 0; mm[0].mlen = mm[1].mlen = 0;
    apm_init_table();
    hist = 0; cur_i = 0;
    for (int i = 0; i < NIN; i++) mixw[i] = 0;
}
static void all_free(void) { for (int m = 0; m < NCTX; m++) free(ct[m]); free(mm[0].table); free(mm[1].table); free(apm_t); }

size_t mix_compress(const uint8_t *src, size_t len, uint8_t *out) {
    all_init(); buf = src;
    size_t op = 0; memcpy(out, MAGIC, 4); op = 4;
    uint64_t orig = len; for (int i = 0; i < 8; i++) out[op++] = (orig >> (8 * i)) & 0xff;
    ENC e = { out + op, 0, 0, 0xffffffffu };
    for (size_t i = 0; i < len; i++) {
        cur_i = i;
        int c = src[i], node = 1;
        for (int b = 0; b < 8; b++) {
            int bit = (c >> (7 - b)) & 1;
            int p = predict(node, b);
            enc_bit(&e, bit, p);
            update_models(bit);
            node = (node << 1) | bit;
        }
        post_byte(i, c);
    }
    enc_flush(&e);
    all_free();
    return op + e.pos;
}
size_t mix_decompress(const uint8_t *in, size_t inlen, uint8_t *out) {
    if (memcmp(in, MAGIC, 4) != 0) { fprintf(stderr, "Не " NAME "-архив\n"); exit(1); }
    size_t ip = 4; uint64_t orig = 0; for (int i = 0; i < 8; i++) orig |= (uint64_t)in[ip++] << (8 * i);
    all_init(); buf = out;
    DEC d = { in + ip, 0, inlen - ip, 0, 0, 0 }; dec_init(&d);
    for (uint64_t i = 0; i < orig; i++) {
        cur_i = i;
        int node = 1;
        for (int b = 0; b < 8; b++) {
            int p = predict(node, b);
            int bit = dec_bit(&d, p);
            update_models(bit);
            node = (node << 1) | bit;
        }
        int c = node & 0xff; out[i] = (uint8_t)c;
        post_byte(i, c);
    }
    all_free();
    return orig;
}

static uint8_t *read_file(const char *p, size_t *sz) {
    FILE *f = fopen(p, "rb"); if (!f) { perror(p); exit(1); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(n ? n : 1); if (fread(b, 1, n, f) != (size_t)n) { perror("read"); exit(1); }
    fclose(f); *sz = n; return b;
}
static void write_file(const char *p, const uint8_t *b, size_t sz) {
    FILE *f = fopen(p, "wb"); if (!f) { perror(p); exit(1); } fwrite(b, 1, sz, f); fclose(f);
}
int main(int argc, char **argv) {
    if (argc != 4 || (argv[1][0] != 'c' && argv[1][0] != 'd')) {
        fprintf(stderr, "%s — использование: %s c|d вход выход\n", NAME, argv[0]); return 1;
    }
    size_t in_size; uint8_t *in = read_file(argv[2], &in_size);
    if (argv[1][0] == 'c') {
        uint8_t *out = malloc(in_size * 2 + 64);
        size_t out_size = mix_compress(in, in_size, out);
        write_file(argv[3], out, out_size);
        printf("%s: сжато %zu -> %zu байт (%.1f%%)\n", NAME, in_size, out_size,
               in_size ? 100.0 * out_size / in_size : 0.0);
        free(out);
    } else {
        uint64_t orig = 0; for (int i = 0; i < 8; i++) orig |= (uint64_t)in[4 + i] << (8 * i);
        uint8_t *out = malloc(orig ? orig : 1);
        size_t out_size = mix_decompress(in, in_size, out);
        write_file(argv[3], out, out_size);
        printf("%s: распаковано -> %zu байт\n", NAME, out_size);
        free(out);
    }
    free(in); return 0;
}
