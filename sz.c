
#define NAME   "SuperZip"
#define MAGIC  "SZ02" 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MIN_MATCH   3
#define MAX_MATCH   258
#define MAX_DIST    65535
#define HASH_BITS   17
#define HASH_SIZE   (1u << HASH_BITS)
#define NIL         0xFFFFFFFFu
#define CHAIN_LIMIT 128

#define LITLEN_SYMS 512
#define DIST_SYMS   17
#define MAXBITS     15

typedef struct { uint8_t *b; size_t pos; int nbits; uint8_t cur; } BW;
static void bw_bit(BW *w, int bit) {
    w->cur |= (uint8_t)(bit & 1) << w->nbits;
    if (++w->nbits == 8) { w->b[w->pos++] = w->cur; w->cur = 0; w->nbits = 0; }
}
static void bw_bits(BW *w, uint32_t v, int n) {
    for (int i = 0; i < n; i++) bw_bit(w, (v >> i) & 1);
}
static void bw_code(BW *w, uint32_t code, int len) {
    for (int i = len - 1; i >= 0; i--) bw_bit(w, (code >> i) & 1);
}
static void bw_flush(BW *w) { if (w->nbits) { w->b[w->pos++] = w->cur; w->cur = 0; w->nbits = 0; } }

typedef struct { const uint8_t *b; size_t pos; int nbits; uint8_t cur; } BR;
static int br_bit(BR *r) {
    if (r->nbits == 0) { r->cur = r->b[r->pos++]; r->nbits = 8; }
    int bit = r->cur & 1; r->cur >>= 1; r->nbits--; return bit;
}
static uint32_t br_bits(BR *r, int n) {
    uint32_t v = 0; for (int i = 0; i < n; i++) v |= (uint32_t)br_bit(r) << i; return v;
}

static void huff_lengths(const uint32_t *freq, int n, uint8_t *len_out) {
    for (int i = 0; i < n; i++) len_out[i] = 0;
    int used = 0;
    for (int i = 0; i < n; i++) if (freq[i]) used++;
    if (used == 0) return;
    if (used == 1) { for (int i = 0; i < n; i++) if (freq[i]) { len_out[i] = 1; break; } return; }

    int maxn = 2 * used;
    uint64_t *w   = malloc(maxn * sizeof(uint64_t));
    int      *par = malloc(maxn * sizeof(int));
    int      *leaf= malloc(used * sizeof(int));
    int total = 0;
    for (int i = 0; i < n; i++) if (freq[i]) { w[total] = freq[i]; par[total] = -1; leaf[total] = i; total++; }
    int leaves = total, active = total;
    while (active > 1) {
        int a = -1, b = -1;
        for (int i = 0; i < total; i++) if (par[i] == -1) {
            if (a < 0 || w[i] < w[a]) { b = a; a = i; }
            else if (b < 0 || w[i] < w[b]) { b = i; }
        }
        w[total] = w[a] + w[b]; par[total] = -1; par[a] = par[b] = total; total++; active--;
    }

    int depth[64] = {0}; uint8_t raw[LITLEN_SYMS];
    for (int i = 0; i < leaves; i++) {
        int d = 0, node = i; while (par[node] != -1) { node = par[node]; d++; }
        raw[i] = (uint8_t)d;
    }

    int bl[MAXBITS + 2] = {0}, overflow = 0;
    for (int i = 0; i < leaves; i++) {
        int b = raw[i]; if (b > MAXBITS) { b = MAXBITS; overflow++; } bl[b]++;
    }
    while (overflow > 0) {
        int bits = MAXBITS - 1; while (bl[bits] == 0) bits--;
        bl[bits]--; bl[bits + 1] += 2; bl[MAXBITS]--; overflow -= 2;
    }
    (void)depth;
    int *order = malloc(leaves * sizeof(int));
    for (int i = 0; i < leaves; i++) order[i] = i;
    for (int i = 0; i < leaves; i++)
        for (int j = i + 1; j < leaves; j++)
            if (w[order[j]] < w[order[i]]) { int t = order[i]; order[i] = order[j]; order[j] = t; }

    int p = 0;
    for (int bits = MAXBITS; bits >= 1; bits--)
        for (int k = 0; k < bl[bits]; k++) len_out[leaf[order[p++]]] = (uint8_t)bits;

    free(order); free(w); free(par); free(leaf);
}

static void huff_codes(const uint8_t *len, int n, uint32_t *code) {
    int bl_count[MAXBITS + 1] = {0};
    for (int i = 0; i < n; i++) if (len[i]) bl_count[len[i]]++;
    uint32_t next[MAXBITS + 1] = {0}, c = 0;
    for (int bits = 1; bits <= MAXBITS; bits++) { c = (c + bl_count[bits - 1]) << 1; next[bits] = c; }
    for (int i = 0; i < n; i++) { code[i] = len[i] ? next[len[i]]++ : 0; }
}

typedef struct { int count[MAXBITS + 1]; int *symbol; } Huff;
static void huff_build_dec(Huff *h, const uint8_t *len, int n) {
    for (int i = 0; i <= MAXBITS; i++) h->count[i] = 0;
    for (int i = 0; i < n; i++) h->count[len[i]]++;
    h->count[0] = 0;
    int offs[MAXBITS + 2]; offs[1] = 0;
    for (int i = 1; i <= MAXBITS; i++) offs[i + 1] = offs[i] + h->count[i];
    h->symbol = malloc(n * sizeof(int));
    for (int i = 0; i < n; i++) if (len[i]) h->symbol[offs[len[i]]++] = i;
}
static int huff_decode(Huff *h, BR *r) {
    int code = 0, first = 0, index = 0;
    for (int len = 1; len <= MAXBITS; len++) {
        code |= br_bit(r);
        int cnt = h->count[len];
        if (code - first < cnt) return h->symbol[index + (code - first)];
        index += cnt; first += cnt; first <<= 1; code <<= 1;
    }
    return -1;
}

static uint32_t head[HASH_SIZE];
static uint32_t *lz_prev;
static inline uint32_t hash3(const uint8_t *p) {
    uint32_t v = ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
    return (v * 2654435761u) >> (32 - HASH_BITS);
}
static inline void lz_insert(const uint8_t *s, size_t pos, size_t len) {
    if (pos + MIN_MATCH <= len) { uint32_t h = hash3(&s[pos]); lz_prev[pos] = head[h]; head[h] = (uint32_t)pos; }
}
static inline int bitlen(uint32_t x) { int n = 0; while (x) { n++; x >>= 1; } return n; }

static size_t rle_encode(const uint8_t *src, int n, uint8_t *dst) {
    size_t o = 0; int i = 0;
    while (i < n) {
        int v = src[i], run = 1;
        while (i + run < n && src[i + run] == v && run < 255) run++;
        dst[o++] = (uint8_t)v; dst[o++] = (uint8_t)run; i += run;
    }
    return o;
}
static void rle_decode(const uint8_t *src, size_t srclen, uint8_t *dst, int n) {
    size_t i = 0; int o = 0;
    while (o < n && i + 1 < srclen) {
        int v = src[i++], run = src[i++];
        while (run-- > 0 && o < n) dst[o++] = (uint8_t)v;
    }
}

static int g_chain = 128;
static int g_lazy  = 1;

static uint32_t lz_find(const uint8_t *s, size_t ip, size_t len, uint32_t *out_dist) {
    uint32_t best_len = 0, best_dist = 0;
    *out_dist = 0;
    if (ip + MIN_MATCH > len) return 0;
    uint32_t h = hash3(&s[ip]), cand = head[h];
    uint32_t maxl = (len - ip < MAX_MATCH) ? (uint32_t)(len - ip) : MAX_MATCH;
    int chain = g_chain;
    while (cand != NIL && chain-- > 0) {
        if (ip - cand > MAX_DIST) break;
        uint32_t l = 0; while (l < maxl && s[cand + l] == s[ip + l]) l++;
        if (l > best_len) { best_len = l; best_dist = (uint32_t)(ip - cand); if (l >= maxl) break; }
        cand = lz_prev[cand];
    }
    *out_dist = best_dist;
    return best_len;
}

size_t compress(const uint8_t *src, size_t len, uint8_t *out, int level) {
    if      (level <= 2) { g_chain = 32;   g_lazy = 0; }
    else if (level <= 4) { g_chain = 64;   g_lazy = 0; }
    else if (level <= 6) { g_chain = 128;  g_lazy = 1; }
    else if (level <= 8) { g_chain = 512;  g_lazy = 1; }
    else                 { g_chain = 4096; g_lazy = 1; }

    for (uint32_t i = 0; i < HASH_SIZE; i++) head[i] = NIL;
    lz_prev = malloc((len ? len : 1) * sizeof(uint32_t));

    uint16_t *ll   = malloc((len + 1) * sizeof(uint16_t));
    uint32_t *dval = malloc((len + 1) * sizeof(uint32_t));
    size_t nt = 0, ip = 0;
    uint32_t flit[LITLEN_SYMS] = {0}, fdist[DIST_SYMS] = {0};

    while (ip < len) {
        if (ip + MIN_MATCH > len) {
            ll[nt] = src[ip]; dval[nt] = 0; flit[src[ip]]++; nt++; ip++; continue;
        }
        uint32_t d1, len1 = lz_find(src, ip, len, &d1);
        lz_insert(src, ip, len);

        if (g_lazy && len1 >= MIN_MATCH && len1 < MAX_MATCH && ip + 1 + MIN_MATCH <= len) {
            uint32_t d2, len2 = lz_find(src, ip + 1, len, &d2);
            if (len2 > len1) {
                ll[nt] = src[ip]; dval[nt] = 0; flit[src[ip]]++; nt++; ip++; continue;
            }
        }

        if (len1 >= MIN_MATCH) {
            uint16_t sym = (uint16_t)(256 + (len1 - MIN_MATCH));
            ll[nt] = sym; dval[nt] = d1; flit[sym]++; fdist[bitlen(d1)]++; nt++;
            size_t end = ip + len1; ip++;
            while (ip < end) lz_insert(src, ip++, len);
        } else {
            ll[nt] = src[ip]; dval[nt] = 0; flit[src[ip]]++; nt++; ip++;
        }
    }
    free(lz_prev);

    uint8_t llen[LITLEN_SYMS], dlen[DIST_SYMS];
    uint32_t lcode[LITLEN_SYMS], dcode[DIST_SYMS];
    huff_lengths(flit, LITLEN_SYMS, llen);
    huff_lengths(fdist, DIST_SYMS, dlen);
    huff_codes(llen, LITLEN_SYMS, lcode);
    huff_codes(dlen, DIST_SYMS, dcode);

    uint8_t lrle[LITLEN_SYMS * 2], drle[DIST_SYMS * 2];
    size_t lrl = rle_encode(llen, LITLEN_SYMS, lrle);
    size_t drl = rle_encode(dlen, DIST_SYMS, drle);

    size_t op = 0;
    memcpy(out + op, MAGIC, 4); op += 4;
    uint64_t orig = len; for (int i = 0; i < 8; i++) out[op++] = (orig >> (8 * i)) & 0xFF;
    out[op++] = lrl & 0xFF; out[op++] = (lrl >> 8) & 0xFF;
    memcpy(out + op, lrle, lrl); op += lrl;
    out[op++] = drl & 0xFF; out[op++] = (drl >> 8) & 0xFF;
    memcpy(out + op, drle, drl); op += drl;

    BW w = { out + op, 0, 0, 0 };
    for (size_t i = 0; i < nt; i++) {
        uint16_t sym = ll[i];
        bw_code(&w, lcode[sym], llen[sym]);
        if (sym >= 256) {
            int slot = bitlen(dval[i]);
            bw_code(&w, dcode[slot], dlen[slot]);
            bw_bits(&w, dval[i] - (1u << (slot - 1)), slot - 1);
        }
    }
    bw_flush(&w);
    op += w.pos;

    free(ll); free(dval);
    return op;
}

size_t decompress(const uint8_t *in, size_t in_len, uint8_t *out) {
    size_t ip = 0;
    if (memcmp(in, MAGIC, 4) != 0) { fprintf(stderr, "Не " NAME "-архив\n"); exit(1); }
    ip += 4;
    uint64_t orig = 0; for (int i = 0; i < 8; i++) orig |= (uint64_t)in[ip++] << (8 * i);
    uint8_t llen[LITLEN_SYMS] = {0}, dlen[DIST_SYMS] = {0};
    size_t lrl = in[ip] | (in[ip + 1] << 8); ip += 2;
    rle_decode(in + ip, lrl, llen, LITLEN_SYMS); ip += lrl;
    size_t drl = in[ip] | (in[ip + 1] << 8); ip += 2;
    rle_decode(in + ip, drl, dlen, DIST_SYMS); ip += drl;

    Huff hl, hd;
    huff_build_dec(&hl, llen, LITLEN_SYMS);
    huff_build_dec(&hd, dlen, DIST_SYMS);

    BR r = { in + ip, 0, 0, 0 };
    size_t op = 0;
    while (op < orig) {
        int sym = huff_decode(&hl, &r);
        if (sym < 256) { out[op++] = (uint8_t)sym; }
        else {
            uint32_t mlen = (sym - 256) + MIN_MATCH;
            int slot = huff_decode(&hd, &r);
            uint32_t dist = (1u << (slot - 1)) + br_bits(&r, slot - 1);
            size_t from = op - dist;
            for (uint32_t i = 0; i < mlen; i++) out[op + i] = out[from + i];
            op += mlen;
        }
    }
    free(hl.symbol); free(hd.symbol);
    (void)in_len;
    return op;
}

static uint8_t *read_file(const char *p, size_t *sz) {
    FILE *f = fopen(p, "rb"); if (!f) { perror(p); exit(1); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(n ? n : 1); if (fread(b, 1, n, f) != (size_t)n) { perror("read"); exit(1); }
    fclose(f); *sz = n; return b;
}
static void write_file(const char *p, const uint8_t *b, size_t sz) {
    FILE *f = fopen(p, "wb"); if (!f) { perror(p); exit(1); }
    fwrite(b, 1, sz, f); fclose(f);
}
int main(int argc, char **argv) {
    if (argc < 4 || (argv[1][0] != 'c' && argv[1][0] != 'd')) {
        fprintf(stderr, "%s — использование:\n  %s c вход выход [уровень 1-9]\n  %s d архив выход\n",
                NAME, argv[0], argv[0]); return 1;
    }
    size_t in_size; uint8_t *in = read_file(argv[2], &in_size);
    if (argv[1][0] == 'c') {
        int level = (argc >= 5) ? atoi(argv[4]) : 6;
        if (level < 1) level = 1;
        if (level > 9) level = 9;
        uint8_t *out = malloc(in_size * 2 + 4 + 8 + LITLEN_SYMS + DIST_SYMS + 64);
        size_t out_size = compress(in, in_size, out, level);
        write_file(argv[3], out, out_size);
        printf("%s: сжато %zu -> %zu байт (%.1f%%)  [уровень %d%s]\n", NAME, in_size, out_size,
               in_size ? 100.0 * out_size / in_size : 0.0, level, g_lazy ? ", lazy" : "");
        free(out);
    } else {
        uint64_t orig = 0; for (int i = 0; i < 8; i++) orig |= (uint64_t)in[4 + i] << (8 * i);
        uint8_t *out = malloc(orig ? orig : 1);
        size_t out_size = decompress(in, in_size, out);
        write_file(argv[3], out, out_size);
        printf("%s: распаковано -> %zu байт\n", NAME, out_size);
        free(out);
    }
    free(in); return 0;
}
