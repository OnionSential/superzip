
#define _WIN32_WINNT 0x0600
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <bcrypt.h>
#include <objbase.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#define SZ_NAME  "SuperZip"
#define SZ_MAGIC "SZ02"

#define MIN_MATCH   3
#define MAX_MATCH   258
#define MAX_DIST    65535
#define HASH_BITS   17
#define HASH_SIZE   (1u << HASH_BITS)
#define NIL         0xFFFFFFFFu
#define LITLEN_SYMS 512
#define DIST_SYMS   17
#define MAXBITS     15

typedef struct { uint8_t *b; size_t pos; int nbits; uint8_t cur; } BW;
static void bw_bit(BW *w,int bit){w->cur|=(uint8_t)(bit&1)<<w->nbits;if(++w->nbits==8){w->b[w->pos++]=w->cur;w->cur=0;w->nbits=0;}}
static void bw_bits(BW *w,uint32_t v,int n){for(int i=0;i<n;i++)bw_bit(w,(v>>i)&1);}
static void bw_code(BW *w,uint32_t code,int len){for(int i=len-1;i>=0;i--)bw_bit(w,(code>>i)&1);}
static void bw_flush(BW *w){if(w->nbits){w->b[w->pos++]=w->cur;w->cur=0;w->nbits=0;}}

typedef struct { const uint8_t *b; size_t pos; int nbits; uint8_t cur; } BR;
static int br_bit(BR *r){if(r->nbits==0){r->cur=r->b[r->pos++];r->nbits=8;}int bit=r->cur&1;r->cur>>=1;r->nbits--;return bit;}
static uint32_t br_bits(BR *r,int n){uint32_t v=0;for(int i=0;i<n;i++)v|=(uint32_t)br_bit(r)<<i;return v;}

static void huff_lengths(const uint32_t *freq,int n,uint8_t *len_out){
    for(int i=0;i<n;i++)len_out[i]=0;
    int used=0; for(int i=0;i<n;i++)if(freq[i])used++;
    if(used==0)return;
    if(used==1){for(int i=0;i<n;i++)if(freq[i]){len_out[i]=1;break;}return;}
    int maxn=2*used;
    uint64_t *w=malloc(maxn*sizeof(uint64_t));
    int *par=malloc(maxn*sizeof(int)),*leaf=malloc(used*sizeof(int));
    int total=0;
    for(int i=0;i<n;i++)if(freq[i]){w[total]=freq[i];par[total]=-1;leaf[total]=i;total++;}
    int leaves=total,active=total;
    while(active>1){
        int a=-1,b=-1;
        for(int i=0;i<total;i++)if(par[i]==-1){if(a<0||w[i]<w[a]){b=a;a=i;}else if(b<0||w[i]<w[b])b=i;}
        w[total]=w[a]+w[b];par[total]=-1;par[a]=par[b]=total;total++;active--;
    }
    int depth[64]={0}; uint8_t raw[LITLEN_SYMS];
    for(int i=0;i<leaves;i++){int d=0,node=i;while(par[node]!=-1){node=par[node];d++;}raw[i]=(uint8_t)d;}
    int bl[MAXBITS+2]={0},overflow=0;
    for(int i=0;i<leaves;i++){int b=raw[i];if(b>MAXBITS){b=MAXBITS;overflow++;}bl[b]++;}
    while(overflow>0){int bits=MAXBITS-1;while(bl[bits]==0)bits--;bl[bits]--;bl[bits+1]+=2;bl[MAXBITS]--;overflow-=2;}
    (void)depth;
    int *order=malloc(leaves*sizeof(int));
    for(int i=0;i<leaves;i++)order[i]=i;
    for(int i=0;i<leaves;i++)for(int j=i+1;j<leaves;j++)if(w[order[j]]<w[order[i]]){int t=order[i];order[i]=order[j];order[j]=t;}
    int p=0;
    for(int bits=MAXBITS;bits>=1;bits--)for(int k=0;k<bl[bits];k++)len_out[leaf[order[p++]]]=(uint8_t)bits;
    free(order);free(w);free(par);free(leaf);
}
static void huff_codes(const uint8_t *len,int n,uint32_t *code){
    int bl_count[MAXBITS+1]={0};
    for(int i=0;i<n;i++)if(len[i])bl_count[len[i]]++;
    uint32_t next[MAXBITS+1]={0},c=0;
    for(int bits=1;bits<=MAXBITS;bits++){c=(c+bl_count[bits-1])<<1;next[bits]=c;}
    for(int i=0;i<n;i++){code[i]=len[i]?next[len[i]]++:0;}
}
typedef struct {int count[MAXBITS+1];int *symbol;} Huff;
static void huff_build_dec(Huff *h,const uint8_t *len,int n){
    for(int i=0;i<=MAXBITS;i++)h->count[i]=0;
    for(int i=0;i<n;i++)h->count[len[i]]++;
    h->count[0]=0;
    int offs[MAXBITS+2];offs[1]=0;
    for(int i=1;i<=MAXBITS;i++)offs[i+1]=offs[i]+h->count[i];
    h->symbol=malloc(n*sizeof(int));
    for(int i=0;i<n;i++)if(len[i])h->symbol[offs[len[i]]++]=i;
}
static int huff_decode(Huff *h,BR *r){
    int code=0,first=0,index=0;
    for(int len=1;len<=MAXBITS;len++){
        code|=br_bit(r);int cnt=h->count[len];
        if(code-first<cnt)return h->symbol[index+(code-first)];
        index+=cnt;first+=cnt;first<<=1;code<<=1;
    }
    return -1;
}
static uint32_t head[HASH_SIZE];
static uint32_t *lz_prev;
static inline uint32_t hash3(const uint8_t *p){uint32_t v=((uint32_t)p[0]<<16)|((uint32_t)p[1]<<8)|p[2];return(v*2654435761u)>>(32-HASH_BITS);}
static inline void lz_insert(const uint8_t *s,size_t pos,size_t len){if(pos+MIN_MATCH<=len){uint32_t h=hash3(&s[pos]);lz_prev[pos]=head[h];head[h]=(uint32_t)pos;}}
static inline int bitlen(uint32_t x){int n=0;while(x){n++;x>>=1;}return n;}
static size_t rle_encode(const uint8_t *src,int n,uint8_t *dst){size_t o=0;int i=0;while(i<n){int v=src[i],run=1;while(i+run<n&&src[i+run]==v&&run<255)run++;dst[o++]=(uint8_t)v;dst[o++]=(uint8_t)run;i+=run;}return o;}
static void rle_decode(const uint8_t *src,size_t srclen,uint8_t *dst,int n){size_t i=0;int o=0;while(o<n&&i+1<srclen){int v=src[i++],run=src[i++];while(run-->0&&o<n)dst[o++]=(uint8_t)v;}}
static int g_chain=128,g_lazy=1;
static uint32_t lz_find(const uint8_t *s,size_t ip,size_t len,uint32_t *od){
    uint32_t bl=0,bd=0;*od=0;if(ip+MIN_MATCH>len)return 0;
    uint32_t h=hash3(&s[ip]),cand=head[h];
    uint32_t maxl=(len-ip<MAX_MATCH)?(uint32_t)(len-ip):MAX_MATCH;
    int chain=g_chain;
    while(cand!=NIL&&chain-->0){if(ip-cand>MAX_DIST)break;uint32_t l=0;while(l<maxl&&s[cand+l]==s[ip+l])l++;if(l>bl){bl=l;bd=(uint32_t)(ip-cand);if(l>=maxl)break;}cand=lz_prev[cand];}
    *od=bd;return bl;
}
static size_t sz_compress(const uint8_t *src,size_t len,uint8_t *out,int level){
    if(level<=2){g_chain=32;g_lazy=0;}else if(level<=4){g_chain=64;g_lazy=0;}else if(level<=6){g_chain=128;g_lazy=1;}else if(level<=8){g_chain=512;g_lazy=1;}else{g_chain=4096;g_lazy=1;}
    for(uint32_t i=0;i<HASH_SIZE;i++)head[i]=NIL;
    lz_prev=malloc((len?len:1)*sizeof(uint32_t));
    uint16_t *ll=malloc((len+1)*sizeof(uint16_t));
    uint32_t *dval=malloc((len+1)*sizeof(uint32_t));
    size_t nt=0,ip=0;
    uint32_t flit[LITLEN_SYMS]={0},fdist[DIST_SYMS]={0};
    while(ip<len){
        if(ip+MIN_MATCH>len){ll[nt]=src[ip];dval[nt]=0;flit[src[ip]]++;nt++;ip++;continue;}
        uint32_t d1,len1=lz_find(src,ip,len,&d1);
        lz_insert(src,ip,len);
        if(g_lazy&&len1>=MIN_MATCH&&len1<MAX_MATCH&&ip+1+MIN_MATCH<=len){uint32_t d2,len2=lz_find(src,ip+1,len,&d2);if(len2>len1){ll[nt]=src[ip];dval[nt]=0;flit[src[ip]]++;nt++;ip++;continue;}}
        if(len1>=MIN_MATCH){uint16_t sym=(uint16_t)(256+(len1-MIN_MATCH));ll[nt]=sym;dval[nt]=d1;flit[sym]++;fdist[bitlen(d1)]++;nt++;size_t end=ip+len1;ip++;while(ip<end)lz_insert(src,ip++,len);}
        else{ll[nt]=src[ip];dval[nt]=0;flit[src[ip]]++;nt++;ip++;}
    }
    free(lz_prev);
    uint8_t llen[LITLEN_SYMS],dlen[DIST_SYMS];uint32_t lcode[LITLEN_SYMS],dcode[DIST_SYMS];
    huff_lengths(flit,LITLEN_SYMS,llen);huff_lengths(fdist,DIST_SYMS,dlen);
    huff_codes(llen,LITLEN_SYMS,lcode);huff_codes(dlen,DIST_SYMS,dcode);
    uint8_t lrle[LITLEN_SYMS*2],drle[DIST_SYMS*2];
    size_t lrl=rle_encode(llen,LITLEN_SYMS,lrle),drl=rle_encode(dlen,DIST_SYMS,drle);
    size_t op=0;
    memcpy(out+op,SZ_MAGIC,4);op+=4;
    uint64_t orig=len;for(int i=0;i<8;i++)out[op++]=(orig>>(8*i))&0xFF;
    out[op++]=lrl&0xFF;out[op++]=(lrl>>8)&0xFF;memcpy(out+op,lrle,lrl);op+=lrl;
    out[op++]=drl&0xFF;out[op++]=(drl>>8)&0xFF;memcpy(out+op,drle,drl);op+=drl;
    BW w={out+op,0,0,0};
    for(size_t i=0;i<nt;i++){uint16_t sym=ll[i];bw_code(&w,lcode[sym],llen[sym]);if(sym>=256){int slot=bitlen(dval[i]);bw_code(&w,dcode[slot],dlen[slot]);bw_bits(&w,dval[i]-(1u<<(slot-1)),slot-1);}}
    bw_flush(&w);op+=w.pos;
    free(ll);free(dval);return op;
}
static size_t sz_decompress(const uint8_t *in,size_t in_len,uint8_t *out){
    size_t ip=4;
    uint64_t orig=0;for(int i=0;i<8;i++)orig|=(uint64_t)in[ip++]<<(8*i);
    uint8_t llen[LITLEN_SYMS]={0},dlen[DIST_SYMS]={0};
    size_t lrl=in[ip]|(in[ip+1]<<8);ip+=2;rle_decode(in+ip,lrl,llen,LITLEN_SYMS);ip+=lrl;
    size_t drl=in[ip]|(in[ip+1]<<8);ip+=2;rle_decode(in+ip,drl,dlen,DIST_SYMS);ip+=drl;
    Huff hl,hd;huff_build_dec(&hl,llen,LITLEN_SYMS);huff_build_dec(&hd,dlen,DIST_SYMS);
    BR r={in+ip,0,0,0};size_t op=0;
    while(op<orig){
        int sym=huff_decode(&hl,&r);
        if(sym<256){out[op++]=(uint8_t)sym;}
        else{uint32_t mlen=(sym-256)+MIN_MATCH;int slot=huff_decode(&hd,&r);uint32_t dist=(1u<<(slot-1))+br_bits(&r,slot-1);size_t from=op-dist;for(uint32_t i=0;i<mlen;i++)out[op+i]=out[from+i];op+=mlen;}
    }
    free(hl.symbol);free(hd.symbol);(void)in_len;return op;
}

#define MX_MAGIC "MX03"

static int mx_squash(int d) {
    static const int t[33] = {1,2,3,6,10,16,27,45,73,120,194,310,488,747,1101,1546,
        2047,2549,2994,3348,3607,3785,3901,3975,4022,4050,4068,4079,4085,4089,4092,4093,4094};
    if (d >  2047) return 4095;
    if (d < -2047) return 0;
    int w = d & 127; d = (d >> 7) + 16;
    return (t[d] * (128 - w) + t[d + 1] * w + 64) >> 7;
}
static int mx_strt[4096];
static void mx_init_stretch(void) {
    int pi = 0;
    for (int x = -2047; x <= 2047; x++) { int i = mx_squash(x); for (int j = pi; j <= i; j++) mx_strt[j] = x; pi = i + 1; }
    for (int j = pi; j < 4096; j++) mx_strt[j] = 2047;
}
static inline int mx_stretch(int p) { return mx_strt[p]; }
static inline int mx_clamp2047(int x) { return x < -2047 ? -2047 : (x > 2047 ? 2047 : x); }

#define MX_NCTX 7
#define MX_CBITS 22
#define MX_CSIZE (1u << MX_CBITS)
static const uint64_t mx_omask[MX_NCTX] = {
    0ULL, 0xFFULL, 0xFFFFULL, 0xFFFFFFULL, 0xFFFFFFFFULL,
    0xFFFFFFFFFFULL, 0xFFFFFFFFFFFFULL
};
static uint16_t *mx_ct[MX_NCTX];
static uint64_t mx_hist = 0;

typedef struct {
    uint32_t *table;
    int tbits;
    int minlen;
    size_t mpos;
    int mlen;
} MxMatchModel;

static const uint8_t *mx_buf;
static size_t mx_cur_i = 0;
static MxMatchModel mx_mm[2];

static uint32_t mx_mm_hash(MxMatchModel *M, size_t i) {
    uint32_t h = 0;
    for (size_t j = i + 1 - M->minlen; j <= i; j++) h = h * 0x9E3779B1u + mx_buf[j] + 1;
    return h & ((1u << M->tbits) - 1);
}
static int mx_mm_predict(MxMatchModel *M, int node, int bitpos) {
    if (M->mlen <= 0 || M->mpos >= mx_cur_i) return 0;
    int e = mx_buf[M->mpos], k = bitpos;
    if ((node ^ (1 << k)) != (e >> (8 - k))) return 0;
    int pb = (e >> (7 - k)) & 1;
    int conf = (M->mlen < 28 ? M->mlen : 28) * 64;
    return pb ? conf : -conf;
}
static void mx_mm_update(MxMatchModel *M, size_t i, int c) {
    if (M->mlen > 0 && M->mpos < mx_cur_i && mx_buf[M->mpos] == c) { M->mpos++; if (M->mlen < 65535) M->mlen++; }
    else M->mlen = 0;
    if ((int)(i + 1) >= M->minlen) {
        uint32_t h = mx_mm_hash(M, i);
        if (M->mlen == 0) {
            uint32_t cand = M->table[h];
            if (cand) { M->mpos = cand - 1; M->mlen = M->minlen; if (M->mpos >= i + 1) M->mlen = 0; }
        }
        M->table[h] = (uint32_t)(i + 2);
    }
}

#define MX_APM_CTX 256
#define MX_APM_BK  33
static uint16_t *mx_apm_t;
static int mx_apm_idx;

static void mx_apm_init_table(void) {
    mx_apm_t = malloc(MX_APM_CTX * MX_APM_BK * sizeof(uint16_t));
    for (int cx = 0; cx < MX_APM_CTX; cx++)
        for (int j = 0; j < MX_APM_BK; j++)
            mx_apm_t[cx * MX_APM_BK + j] = (uint16_t)mx_squash((j - 16) * 128);
}
static int mx_apm_apply(int pr, int cx) {
    int s = mx_stretch(pr) + 2048;
    int seg = s >> 7; if (seg > MX_APM_BK - 2) seg = MX_APM_BK - 2;
    int w = s & 127;
    int base = cx * MX_APM_BK + seg;
    int lo = mx_apm_t[base], hi = mx_apm_t[base + 1];
    mx_apm_idx = (w < 64) ? base : base + 1;
    int p2 = (lo * (128 - w) + hi * w) >> 7;
    if (p2 < 1) p2 = 1;
    if (p2 > 4094) p2 = 4094;
    return p2;
}
static void mx_apm_update(int y) {
    int v = mx_apm_t[mx_apm_idx];
    v += ((y << 12) - v) >> 6;
    mx_apm_t[mx_apm_idx] = (uint16_t)v;
}

#define MX_NIN (MX_NCTX + 2)
#define MX_MIXSHIFT 10
static int64_t mx_mixw[MX_NIN];
static int mx_st[MX_NIN], mx_idx[MX_NCTX], mx_last_p;

static int mx_predict(int node, int bitpos) {
    for (int m = 0; m < MX_NCTX; m++) {
        uint64_t c = (mx_hist & mx_omask[m]) + 1;
        uint64_t h64 = (c + (uint64_t)m * 0x9E3779B97F4A7C15ULL) * 0xff51afd7ed558ccdULL;
        h64 ^= h64 >> 33;
        uint32_t h = (uint32_t)h64 ^ ((uint32_t)node * 0x9E3779B1u);
        uint32_t id = h & (MX_CSIZE - 1);
        mx_idx[m] = id;
        mx_st[m] = mx_stretch(mx_ct[m][id]);
    }
    mx_st[MX_NCTX]     = mx_mm_predict(&mx_mm[0], node, bitpos);
    mx_st[MX_NCTX + 1] = mx_mm_predict(&mx_mm[1], node, bitpos);

    int64_t dot = 0; for (int i = 0; i < MX_NIN; i++) dot += (int64_t)mx_st[i] * mx_mixw[i];
    int s = mx_clamp2047((int)(dot >> 16));
    int p = mx_squash(s);
    if (p < 1) p = 1;
    if (p > 4094) p = 4094;
    mx_last_p = p;

    int cx = (int)(mx_hist & 0xFF);
    int p2 = mx_apm_apply(p, cx);
    return p2;
}
static void mx_update_models(int y) {
    int err = (y << 12) - mx_last_p;
    for (int i = 0; i < MX_NIN; i++) {
        mx_mixw[i] += ((int64_t)mx_st[i] * err) >> MX_MIXSHIFT;
        if (mx_mixw[i] >  (1 << 24)) mx_mixw[i] =  (1 << 24);
        if (mx_mixw[i] < -(1 << 24)) mx_mixw[i] = -(1 << 24);
    }
    for (int m = 0; m < MX_NCTX; m++) {
        int pp = mx_ct[m][mx_idx[m]]; pp += ((y << 12) - pp) >> 5; mx_ct[m][mx_idx[m]] = (uint16_t)pp;
    }
    mx_apm_update(y);
}
static void mx_post_byte(size_t i, int c) {
    mx_mm_update(&mx_mm[0], i, c);
    mx_mm_update(&mx_mm[1], i, c);
    mx_hist = (mx_hist << 8) | (uint64_t)c;
}

typedef struct { uint8_t *out; size_t pos; uint32_t x1, x2; } MxENC;
static inline void mx_enc_bit(MxENC *e, int bit, int p) {
    uint32_t r = e->x2 - e->x1;
    uint32_t xmid = e->x1 + (r >> 12) * p + (((r & 0xfff) * p) >> 12);
    if (bit) e->x2 = xmid; else e->x1 = xmid + 1;
    while (((e->x1 ^ e->x2) & 0xff000000u) == 0) { e->out[e->pos++] = e->x2 >> 24; e->x1 <<= 8; e->x2 = (e->x2 << 8) | 0xff; }
}
static void mx_enc_flush(MxENC *e) { for (int i = 0; i < 4; i++) { e->out[e->pos++] = e->x1 >> 24; e->x1 <<= 8; } }
typedef struct { const uint8_t *in; size_t pos, len; uint32_t x1, x2, x; } MxDEC;
static inline uint32_t mx_dget(MxDEC *d) { return d->pos < d->len ? d->in[d->pos++] : 0; }
static void mx_dec_init(MxDEC *d) { d->x1 = 0; d->x2 = 0xffffffffu; d->x = 0; for (int i = 0; i < 4; i++) d->x = (d->x << 8) | mx_dget(d); }
static inline int mx_dec_bit(MxDEC *d, int p) {
    uint32_t r = d->x2 - d->x1;
    uint32_t xmid = d->x1 + (r >> 12) * p + (((r & 0xfff) * p) >> 12);
    int bit = (d->x <= xmid);
    if (bit) d->x2 = xmid; else d->x1 = xmid + 1;
    while (((d->x1 ^ d->x2) & 0xff000000u) == 0) { d->x1 <<= 8; d->x2 = (d->x2 << 8) | 0xff; d->x = (d->x << 8) | mx_dget(d); }
    return bit;
}

static void mx_all_init(void) {
    mx_init_stretch();
    for (int m = 0; m < MX_NCTX; m++) { mx_ct[m] = malloc(MX_CSIZE * sizeof(uint16_t)); for (uint32_t i = 0; i < MX_CSIZE; i++) mx_ct[m][i] = 2048; }
    mx_mm[0].tbits = 22; mx_mm[0].minlen = 6; mx_mm[0].table = calloc(1u << mx_mm[0].tbits, sizeof(uint32_t));
    mx_mm[1].tbits = 20; mx_mm[1].minlen = 4; mx_mm[1].table = calloc(1u << mx_mm[1].tbits, sizeof(uint32_t));
    mx_mm[0].mpos = mx_mm[1].mpos = 0; mx_mm[0].mlen = mx_mm[1].mlen = 0;
    mx_apm_init_table();
    mx_hist = 0; mx_cur_i = 0;
    for (int i = 0; i < MX_NIN; i++) mx_mixw[i] = 0;
}
static void mx_all_free(void) { for (int m = 0; m < MX_NCTX; m++) free(mx_ct[m]); free(mx_mm[0].table); free(mx_mm[1].table); free(mx_apm_t); }

static size_t mix_compress(const uint8_t *src, size_t len, uint8_t *out) {
    mx_all_init(); mx_buf = src;
    size_t op = 0; memcpy(out, MX_MAGIC, 4); op = 4;
    uint64_t orig = len; for (int i = 0; i < 8; i++) out[op++] = (orig >> (8 * i)) & 0xff;
    MxENC e = { out + op, 0, 0, 0xffffffffu };
    for (size_t i = 0; i < len; i++) {
        mx_cur_i = i;
        int c = src[i], node = 1;
        for (int b = 0; b < 8; b++) {
            int bit = (c >> (7 - b)) & 1;
            int p = mx_predict(node, b);
            mx_enc_bit(&e, bit, p);
            mx_update_models(bit);
            node = (node << 1) | bit;
        }
        mx_post_byte(i, c);
    }
    mx_enc_flush(&e);
    mx_all_free();
    return op + e.pos;
}
static size_t mix_decompress(const uint8_t *in, size_t inlen, uint8_t *out) {

    size_t ip = 4; uint64_t orig = 0; for (int i = 0; i < 8; i++) orig |= (uint64_t)in[ip++] << (8 * i);
    mx_all_init(); mx_buf = out;
    MxDEC d = { in + ip, 0, inlen - ip, 0, 0, 0 }; mx_dec_init(&d);
    for (uint64_t i = 0; i < orig; i++) {
        mx_cur_i = i;
        int node = 1;
        for (int b = 0; b < 8; b++) {
            int p = mx_predict(node, b);
            int bit = mx_dec_bit(&d, p);
            mx_update_models(bit);
            node = (node << 1) | bit;
        }
        int c = node & 0xff; out[i] = (uint8_t)c;
        mx_post_byte(i, c);
    }
    mx_all_free();
    return orig;
}

typedef struct { wchar_t rel[MAX_PATH]; wchar_t full[MAX_PATH]; uint64_t size; } FEntry;
static FEntry *g_entries = NULL;
static int g_entry_count = 0, g_entry_cap = 0;

static void add_entry(const wchar_t *rel, const wchar_t *full, uint64_t size) {
    if (g_entry_count >= g_entry_cap) {
        g_entry_cap = g_entry_cap ? g_entry_cap * 2 : 64;
        g_entries = realloc(g_entries, g_entry_cap * sizeof(FEntry));
    }
    wcsncpy(g_entries[g_entry_count].rel, rel, MAX_PATH - 1);
    wcsncpy(g_entries[g_entry_count].full, full, MAX_PATH - 1);
    g_entries[g_entry_count].size = size;
    g_entry_count++;
}

static void walk_dir(const wchar_t *root_full, const wchar_t *rel_prefix) {
    wchar_t pattern[MAX_PATH];
    _snwprintf(pattern, MAX_PATH, L"%s\\*", root_full);
    WIN32_FIND_DATA fd;
    HANDLE h = FindFirstFile(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        wchar_t full[MAX_PATH], rel[MAX_PATH];
        _snwprintf(full, MAX_PATH, L"%s\\%s", root_full, fd.cFileName);
        if (rel_prefix[0])
            _snwprintf(rel, MAX_PATH, L"%s\\%s", rel_prefix, fd.cFileName);
        else
            wcsncpy(rel, fd.cFileName, MAX_PATH - 1);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk_dir(full, rel);
        } else {
            uint64_t size = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            add_entry(rel, full, size);
        }
    } while (FindNextFile(h, &fd));
    FindClose(h);
}

static void ensure_dirs_for(const wchar_t *filepath) {
    wchar_t tmp[MAX_PATH];
    wcsncpy(tmp, filepath, MAX_PATH - 1);
    tmp[MAX_PATH - 1] = 0;
    for (wchar_t *p = tmp + 1; *p; p++) {
        if (*p == L'\\') {
            *p = 0;
            CreateDirectory(tmp, NULL);
            *p = L'\\';
        }
    }
}

static int unpack_folder(const uint8_t *payload, size_t paysize, const wchar_t *destroot, uint32_t *out_count) {
    if (paysize < 4) return 0;
    size_t p = 0;
    uint32_t cnt = payload[0] | (payload[1] << 8) | (payload[2] << 16) | ((uint32_t)payload[3] << 24);
    p += 4;
    CreateDirectory(destroot, NULL);
    for (uint32_t i = 0; i < cnt; i++) {
        if (p + 2 > paysize) return 0;
        uint16_t plen = payload[p] | (payload[p + 1] << 8); p += 2;
        if (p + plen > paysize) return 0;
        wchar_t rel[MAX_PATH];
        int nchars = plen / 2; if (nchars >= MAX_PATH) nchars = MAX_PATH - 1;
        memcpy(rel, payload + p, (size_t)nchars * 2); rel[nchars] = 0;
        p += plen;
        if (p + 8 > paysize) return 0;
        uint64_t sz = 0; for (int k = 0; k < 8; k++) sz |= (uint64_t)payload[p + k] << (8 * k);
        p += 8;
        if (p + sz > paysize) return 0;

        wchar_t full[MAX_PATH];
        _snwprintf(full, MAX_PATH, L"%s\\%s", destroot, rel);
        ensure_dirs_for(full);
        FILE *f = _wfopen(full, L"wb");
        if (f) { if (sz > 0) fwrite(payload + p, 1, (size_t)sz, f); fclose(f); }
        p += (size_t)sz;
    }
    *out_count = cnt;
    return 1;
}

static HWND hPath, hTrack, hLevelTxt, hStatus, hProgress, hMethod, hPassword, hCancel;

#define PBKDF2_ITERATIONS 200000

typedef struct {
    int enabled;
    BCRYPT_ALG_HANDLE hAes;
    BCRYPT_KEY_HANDLE hKey;
    uint8_t nonce[8];
    uint64_t block_ctr;
    uint8_t keystream[16];
    int ks_pos;
} Cipher;

static void cipher_apply(Cipher *c, uint8_t *data, size_t len) {
    if (!c->enabled) return;
    size_t i = 0;
    while (i < len) {
        if (c->ks_pos == 0) {
            uint8_t ctrblock[16];
            memcpy(ctrblock, c->nonce, 8);
            for (int k = 0; k < 8; k++) ctrblock[8 + k] = (uint8_t)((c->block_ctr >> (8 * (7 - k))) & 0xFF);
            ULONG outlen = 0;
            BCryptEncrypt(c->hKey, ctrblock, 16, NULL, NULL, 0, c->keystream, 16, &outlen, 0);
            c->block_ctr++;
        }
        size_t take = 16 - (size_t)c->ks_pos;
        if (take > len - i) take = len - i;
        for (size_t k = 0; k < take; k++) data[i + k] ^= c->keystream[c->ks_pos + (int)k];
        c->ks_pos = (int)((c->ks_pos + (int)take) % 16);
        i += take;
    }
}

static int password_to_utf8(const wchar_t *pw, char *out, int outcap) {
    int n = WideCharToMultiByte(CP_UTF8, 0, pw, -1, out, outcap - 1, NULL, NULL);
    return (n > 0) ? n - 1 : 0;   /* минус завершающий 0 */
}

static int cipher_derive_key(Cipher *c, const wchar_t *password, const uint8_t *salt) {
    char pwUtf8[256];
    int pwlen = password_to_utf8(password, pwUtf8, sizeof(pwUtf8));
    if (pwlen <= 0) return 0;

    BCRYPT_ALG_HANDLE hPrf;
    if (BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
        return 0;
    uint8_t key[32];
    NTSTATUS st = BCryptDeriveKeyPBKDF2(hPrf, (PUCHAR)pwUtf8, (ULONG)pwlen,
                                        (PUCHAR)salt, 16, PBKDF2_ITERATIONS, key, 32, 0);
    BCryptCloseAlgorithmProvider(hPrf, 0);
    SecureZeroMemory(pwUtf8, sizeof(pwUtf8));
    if (st != 0) return 0;

    if (BCryptOpenAlgorithmProvider(&c->hAes, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return 0;
    if (BCryptSetProperty(c->hAes, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_ECB,
                           sizeof(BCRYPT_CHAIN_MODE_ECB), 0) != 0) { BCryptCloseAlgorithmProvider(c->hAes,0); return 0; }
    NTSTATUS kst = BCryptGenerateSymmetricKey(c->hAes, &c->hKey, NULL, 0, key, 32, 0);
    SecureZeroMemory(key, sizeof(key));
    if (kst != 0) { BCryptCloseAlgorithmProvider(c->hAes, 0); return 0; }
    return 1;
}

static int cipher_init_encrypt(Cipher *c, const wchar_t *password, uint8_t *salt_out, uint8_t *nonce_out) {
    memset(c, 0, sizeof(*c));
    if (!password || !password[0]) { c->enabled = 0; return 1; }
    BCryptGenRandom(NULL, salt_out, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, nonce_out, 8, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    memcpy(c->nonce, nonce_out, 8);
    if (!cipher_derive_key(c, password, salt_out)) return 0;
    c->enabled = 1;
    return 1;
}
static int cipher_init_decrypt(Cipher *c, const wchar_t *password, const uint8_t *salt, const uint8_t *nonce) {
    memset(c, 0, sizeof(*c));
    if (!password || !password[0]) return 0;
    memcpy(c->nonce, nonce, 8);
    if (!cipher_derive_key(c, password, salt)) return 0;
    c->enabled = 1;
    return 1;
}
static void cipher_close(Cipher *c) {
    if (c->hKey) BCryptDestroyKey(c->hKey);
    if (c->hAes) BCryptCloseAlgorithmProvider(c->hAes, 0);
    c->hKey = NULL; c->hAes = NULL;
}

#define CHUNK_SIZE (16u * 1024 * 1024)   /* 16 МБ — компромисс память/скорость */
#define IO_BUF     (1u * 1024 * 1024)    /* 1 МБ — буфер чтения/записи файлов  */
#define MAX_THREADS 6                     /* потолок параллелизма — чтобы не раздуть память */

static uint32_t crc32_buf(const uint8_t *data, size_t len) {
    static uint32_t table[256]; static int ready = 0;
    if (!ready) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        ready = 1;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}
static int g_crc_fail = 0;

static int detect_thread_count(void) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    int n = (int)si.dwNumberOfProcessors;
    if (n < 1) n = 1;
    if (n > MAX_THREADS) n = MAX_THREADS;
    return n;
}

typedef struct {
    const uint8_t *src; size_t srclen;
    uint8_t *dst; size_t dstlen;
    int method, level;
} CompressJob;
static DWORD WINAPI compress_job_proc(LPVOID param) {
    CompressJob *j = (CompressJob*)param;
    j->dstlen = (j->method == 1) ? mix_compress(j->src, j->srclen, j->dst)
                                  : sz_compress(j->src, j->srclen, j->dst, j->level);
    return 0;
}

typedef struct {
    FILE *out;
    uint8_t *buf[MAX_THREADS];
    size_t len[MAX_THREADS];
    int cur;
    int level, method, nthreads;
    Cipher cipher;
} ChunkWriter;

static void cw_init(ChunkWriter *w, FILE *out, int level, int method, Cipher *cipher) {
    w->out = out; w->level = level; w->method = method;
    w->nthreads = detect_thread_count();
    for (int i = 0; i < w->nthreads; i++) { w->buf[i] = malloc(CHUNK_SIZE); w->len[i] = 0; }
    w->cur = 0;
    w->cipher = *cipher;
}

static void cw_flush_batch(ChunkWriter *w, int n) {
    if (n <= 0) return;
    CompressJob jobs[MAX_THREADS];
    HANDLE threads[MAX_THREADS];
    uint8_t *comp[MAX_THREADS];
    for (int i = 0; i < n; i++) {
        comp[i] = malloc(w->len[i] * 2 + 8192);
        jobs[i].src = w->buf[i]; jobs[i].srclen = w->len[i];
        jobs[i].dst = comp[i]; jobs[i].dstlen = 0;
        jobs[i].method = w->method; jobs[i].level = w->level;
        threads[i] = CreateThread(NULL, 0, compress_job_proc, &jobs[i], 0, NULL);
    }
    WaitForMultipleObjects(n, threads, TRUE, INFINITE);
    for (int i = 0; i < n; i++) CloseHandle(threads[i]);
    for (int i = 0; i < n; i++) {
        size_t cs = jobs[i].dstlen;
        uint32_t crc = crc32_buf(w->buf[i], w->len[i]);
        uint8_t lb[8] = { (uint8_t)(cs & 0xFF), (uint8_t)((cs >> 8) & 0xFF),
                           (uint8_t)((cs >> 16) & 0xFF), (uint8_t)((cs >> 24) & 0xFF),
                           (uint8_t)(crc & 0xFF), (uint8_t)((crc >> 8) & 0xFF),
                           (uint8_t)((crc >> 16) & 0xFF), (uint8_t)((crc >> 24) & 0xFF) };

        cipher_apply(&w->cipher, lb, 8);
        cipher_apply(&w->cipher, comp[i], cs);
        fwrite(lb, 1, 8, w->out);
        fwrite(comp[i], 1, cs, w->out);
        free(comp[i]);
        w->len[i] = 0;
    }
}
static void cw_write(ChunkWriter *w, const uint8_t *data, size_t n) {
    while (n > 0) {
        size_t space = CHUNK_SIZE - w->len[w->cur];
        size_t take = (n < space) ? n : space;
        memcpy(w->buf[w->cur] + w->len[w->cur], data, take);
        w->len[w->cur] += take; data += take; n -= take;
        if (w->len[w->cur] == CHUNK_SIZE) {
            w->cur++;
            if (w->cur == w->nthreads) { cw_flush_batch(w, w->nthreads); w->cur = 0; }
        }
    }
}
static void cw_close(ChunkWriter *w) {
    int n = w->cur + (w->len[w->cur] > 0 ? 1 : 0);
    cw_flush_batch(w, n);
    for (int i = 0; i < w->nthreads; i++) free(w->buf[i]);
}

typedef struct {
    const uint8_t *src; size_t srclen;
    uint8_t *dst;
} DecompressJob;
static DWORD WINAPI decompress_job_proc(LPVOID param) {
    DecompressJob *j = (DecompressJob*)param;
    if (memcmp(j->src, "MX03", 4) == 0) mix_decompress(j->src, j->srclen, j->dst);
    else sz_decompress(j->src, j->srclen, j->dst);
    return 0;
}

typedef struct {
    FILE *in;
    uint8_t *buf[MAX_THREADS];
    size_t len[MAX_THREADS];
    size_t pos;
    int cur, filled, nthreads;
    int has_crc;
    Cipher cipher;
} ChunkReader;

static void cr_init(ChunkReader *r, FILE *in, int has_crc, Cipher *cipher) {
    r->in = in; r->nthreads = detect_thread_count(); r->has_crc = has_crc;
    for (int i = 0; i < r->nthreads; i++) { r->buf[i] = NULL; r->len[i] = 0; }
    r->pos = 0; r->cur = 0; r->filled = 0;
    r->cipher = *cipher;
    g_crc_fail = 0;
}
static int cr_fill_batch(ChunkReader *r) {
    uint8_t *craw[MAX_THREADS]; size_t clen[MAX_THREADS]; uint32_t expect_crc[MAX_THREADS];
    int hdrsize = r->has_crc ? 8 : 4;
    int n = 0;
    for (; n < r->nthreads; n++) {
        uint8_t lb[8];
        if (fread(lb, 1, (size_t)hdrsize, r->in) != (size_t)hdrsize) break;
        cipher_apply(&r->cipher, lb, (size_t)hdrsize);
        uint32_t cl = lb[0] | (lb[1] << 8) | (lb[2] << 16) | ((uint32_t)lb[3] << 24);
        expect_crc[n] = r->has_crc ? (lb[4] | (lb[5] << 8) | (lb[6] << 16) | ((uint32_t)lb[7] << 24)) : 0;

        if (cl < 12 || cl > 64u * 1024 * 1024) { g_crc_fail = 1; break; }
        craw[n] = malloc(cl);
        if (fread(craw[n], 1, cl, r->in) != cl) { free(craw[n]); break; }
        cipher_apply(&r->cipher, craw[n], cl);
        clen[n] = cl;
    }
    if (n == 0) return 0;

    DecompressJob jobs[MAX_THREADS]; HANDLE threads[MAX_THREADS];
    int bad = 0;
    for (int i = 0; i < n; i++) {
        uint64_t orig = 0; for (int k = 0; k < 8; k++) orig |= (uint64_t)craw[i][4 + k] << (8 * k);
        if (orig > 64u * 1024 * 1024) { orig = 0; bad = 1; g_crc_fail = 1; }
        free(r->buf[i]);
        r->buf[i] = malloc(orig ? (size_t)orig : 1);
        r->len[i] = (size_t)orig;
        jobs[i].src = craw[i]; jobs[i].srclen = clen[i]; jobs[i].dst = r->buf[i];
        threads[i] = (orig > 0) ? CreateThread(NULL, 0, decompress_job_proc, &jobs[i], 0, NULL) : NULL;
    }
    (void)bad;
    for (int i = 0; i < n; i++) if (threads[i]) WaitForMultipleObjects(1, &threads[i], TRUE, INFINITE);
    for (int i = 0; i < n; i++) {
        if (threads[i]) CloseHandle(threads[i]);
        free(craw[i]);
        if (r->has_crc && crc32_buf(r->buf[i], r->len[i]) != expect_crc[i]) g_crc_fail = 1;
    }

    r->filled = n; r->cur = 0; r->pos = 0;
    return 1;
}
static int cr_read(ChunkReader *r, uint8_t *dst, size_t n) {
    while (n > 0) {
        if (r->cur >= r->filled) { if (!cr_fill_batch(r)) return 0; }
        size_t avail = r->len[r->cur] - r->pos;
        size_t take = (n < avail) ? n : avail;
        memcpy(dst, r->buf[r->cur] + r->pos, take);
        dst += take; n -= take; r->pos += take;
        if (r->pos == r->len[r->cur]) { r->cur++; r->pos = 0; }
    }
    return 1;
}
static void cr_close(ChunkReader *r) { for (int i = 0; i < r->nthreads; i++) free(r->buf[i]); }

static void cw_write_u64(ChunkWriter *w, uint64_t v) {
    uint8_t b[8]; for (int k = 0; k < 8; k++) b[k] = (uint8_t)((v >> (8 * k)) & 0xFF);
    cw_write(w, b, 8);
}
static int cr_read_u64(ChunkReader *r, uint64_t *v) {
    uint8_t b[8]; if (!cr_read(r, b, 8)) return 0;
    uint64_t x = 0; for (int k = 0; k < 8; k++) x |= (uint64_t)b[k] << (8 * k);
    *v = x; return 1;
}

static int g_busy = 0;
static volatile int g_cancel_requested = 0;

static void pump_messages(void) {
    MSG m;
    while (PeekMessage(&m, NULL, 0, 0, PM_REMOVE)) { TranslateMessage(&m); DispatchMessage(&m); }
}

static void stream_copy_in(ChunkWriter *cw, FILE *fin, uint64_t total, HWND hwnd, uint64_t *done, uint64_t grand_total) {
    static uint8_t iobuf[IO_BUF];
    uint64_t remain = total;
    while (remain > 0) {
        if (g_cancel_requested) break;
        size_t take = (remain < IO_BUF) ? (size_t)remain : IO_BUF;
        size_t got = fread(iobuf, 1, take, fin);
        if (got == 0) break;
        cw_write(cw, iobuf, got);
        remain -= got; *done += got;
        if (grand_total > 0) {
            int pct = (int)((*done * 100) / grand_total);
            SendMessage(hProgress, PBM_SETPOS, pct, 0);
            UpdateWindow(hwnd);
        }
        pump_messages();
    }
}
static void stream_copy_out(ChunkReader *cr, FILE *fout, uint64_t total, HWND hwnd, uint64_t *done, uint64_t grand_total) {
    static uint8_t iobuf[IO_BUF];
    uint64_t remain = total;
    while (remain > 0) {
        if (g_cancel_requested) break;
        size_t take = (remain < IO_BUF) ? (size_t)remain : IO_BUF;
        if (!cr_read(cr, iobuf, take)) break;
        fwrite(iobuf, 1, take, fout);
        remain -= take;
        if (done) *done += take;
        if (grand_total > 0 && done) {
            int pct = (int)((*done * 100) / grand_total);
            SendMessage(hProgress, PBM_SETPOS, pct, 0);
            UpdateWindow(hwnd);
        }
        pump_messages();
    }
}

#define IDC_PATH       101
#define IDC_BROWSE     102
#define IDC_LEVEL      103
#define IDC_LEVELTXT   104
#define IDC_COMPRESS   105
#define IDC_DECOMPRESS 106
#define IDC_STATUS     107
#define IDC_PROGRESS   108
#define IDC_BROWSE_DIR 109
#define IDC_METHOD     110
#define IDC_PASSWORD   111
#define IDC_CANCEL     112

static WCHAR g_path[MAX_PATH] = L"";
static int g_autorun = 0;
static HBRUSH g_hbrGround = NULL;
static HBRUSH g_hbrPanel2 = NULL;

static const wchar_t *level_name(int l){
    if(l<=2)return L"скоростной";
    if(l<=4)return L"быстрый";
    if(l<=6)return L"нормальный";
    if(l<=8)return L"максимум";
    return L"ультра";
}

static int wread(const wchar_t *p, uint8_t **buf, size_t *sz){
    FILE *f=_wfopen(p,L"rb"); if(!f)return 0;
    fseek(f,0,SEEK_END);long n=ftell(f);fseek(f,0,SEEK_SET);
    uint8_t *b=malloc(n?(size_t)n:1);
    if(n>0&&fread(b,1,(size_t)n,f)!=(size_t)n){fclose(f);free(b);return 0;}
    fclose(f);*buf=b;*sz=(size_t)n;return 1;
}
static int wwrite(const wchar_t *p, const uint8_t *b, size_t sz){
    FILE *f=_wfopen(p,L"wb");if(!f)return 0;fwrite(b,1,sz,f);fclose(f);return 1;
}

static void do_browse(HWND hwnd){
    WCHAR file[MAX_PATH]=L"";
    OPENFILENAME ofn; memset(&ofn,0,sizeof(ofn));
    ofn.lStructSize=sizeof(ofn); ofn.hwndOwner=hwnd;
    ofn.lpstrFile=file; ofn.nMaxFile=MAX_PATH;
    ofn.lpstrFilter=L"Все файлы\0*.*\0\0"; ofn.nFilterIndex=1;
    ofn.Flags=OFN_PATHMUSTEXIST|OFN_FILEMUSTEXIST;
    if(GetOpenFileName(&ofn)){
        wcsncpy(g_path,file,MAX_PATH-1);
        SetWindowText(hPath,g_path);
        SetWindowText(hStatus,L"Файл выбран. Нажми Сжать или Распаковать.");
    }
}

static void do_browse_folder(HWND hwnd){
    BROWSEINFO bi; memset(&bi,0,sizeof(bi));
    bi.hwndOwner=hwnd;
    bi.lpszTitle=L"Выбери папку для сжатия";
    bi.ulFlags=BIF_RETURNONLYFSDIRS|BIF_NEWDIALOGSTYLE;
    LPITEMIDLIST pidl=SHBrowseForFolder(&bi);
    if(pidl){
        WCHAR folder[MAX_PATH];
        if(SHGetPathFromIDList(pidl,folder)){
            wcsncpy(g_path,folder,MAX_PATH-1);
            SetWindowText(hPath,g_path);
            SetWindowText(hStatus,L"Папка выбрана. Нажми Сжать.");
        }
        CoTaskMemFree(pidl);
    }
}

static void do_compress(HWND hwnd){
    if(!g_path[0]){MessageBox(hwnd,L"Сначала выбери файл или папку.",L"SuperZip",MB_ICONWARNING);return;}
    if(g_busy) return;
    g_busy = 1;
    g_cancel_requested = 0;
    EnableWindow(hCancel, TRUE);
    int level=(int)SendMessage(hTrack,TBM_GETPOS,0,0);
    int method=(int)SendMessage(hMethod,CB_GETCURSEL,0,0);
    if(method<0) method=0;
    SetWindowText(hStatus,L"Сжимаю...");
    SendMessage(hProgress,PBM_SETPOS,0,0);
    UpdateWindow(hwnd);

    DWORD attr = GetFileAttributes(g_path);
    int is_dir = (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);

    WCHAR outpath[MAX_PATH];
    wcsncpy(outpath,g_path,MAX_PATH-5);
    outpath[MAX_PATH-5]=0;
    wcsncat(outpath,L".sz",4);

    FILE *fout = _wfopen(outpath, L"wb");
    if (!fout) { MessageBox(hwnd, L"Не могу создать файл результата.", L"SuperZip", MB_ICONERROR); EnableWindow(hCancel,FALSE); g_busy=0; return; }

    WCHAR password[256]; GetWindowText(hPassword, password, 256);
    uint8_t salt[16], nonce[8];
    Cipher cipher;
    if (!cipher_init_encrypt(&cipher, password, salt, nonce)) {
        MessageBox(hwnd, L"Не получилось настроить шифрование.", L"SuperZip", MB_ICONERROR);
        fclose(fout); _wremove(outpath); EnableWindow(hCancel,FALSE); g_busy=0; return;
    }
    if (cipher.enabled) {
        fwrite("SZE5", 1, 4, fout);
        fwrite(salt, 1, 16, fout);
        fwrite(nonce, 1, 8, fout);
    } else {
        fwrite("SZ05", 1, 4, fout);
    }

    ChunkWriter cw; cw_init(&cw, fout, level, method, &cipher);
    uint64_t done = 0;

    if (is_dir) {
        if (g_entries) { free(g_entries); g_entries = NULL; g_entry_cap = 0; }
        g_entry_count = 0;
        walk_dir(g_path, L"");
        if (g_entry_count == 0) {
            MessageBox(hwnd, L"Папка пуста — нечего сжимать.", L"SuperZip", MB_ICONWARNING);
            cw_close(&cw); cipher_close(&cipher); fclose(fout); _wremove(outpath); EnableWindow(hCancel,FALSE); g_busy=0; return;
        }
        uint64_t grand_total = 0;
        for (int i = 0; i < g_entry_count; i++) grand_total += g_entries[i].size;

        uint8_t kind = 1; cw_write(&cw, &kind, 1);
        uint32_t cnt = (uint32_t)g_entry_count;
        uint8_t cb[4] = { (uint8_t)(cnt&0xFF),(uint8_t)((cnt>>8)&0xFF),(uint8_t)((cnt>>16)&0xFF),(uint8_t)((cnt>>24)&0xFF) };
        cw_write(&cw, cb, 4);

        for (int i = 0; i < g_entry_count && !g_cancel_requested; i++) {
            uint16_t plen = (uint16_t)(wcslen(g_entries[i].rel) * sizeof(wchar_t));
            uint8_t pb[2] = { (uint8_t)(plen&0xFF), (uint8_t)((plen>>8)&0xFF) };
            cw_write(&cw, pb, 2);
            cw_write(&cw, (const uint8_t*)g_entries[i].rel, plen);
            cw_write_u64(&cw, g_entries[i].size);

            FILE *fin = _wfopen(g_entries[i].full, L"rb");
            if (fin) { stream_copy_in(&cw, fin, g_entries[i].size, hwnd, &done, grand_total); fclose(fin); }
        }
    } else {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        uint64_t fsz = 0;
        if (GetFileAttributesEx(g_path, GetFileExInfoStandard, &fad))
            fsz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;

        uint8_t kind = 0; cw_write(&cw, &kind, 1);
        cw_write_u64(&cw, fsz);

        FILE *fin = _wfopen(g_path, L"rb");
        if (!fin) { MessageBox(hwnd,L"Не могу открыть файл.",L"SuperZip",MB_ICONERROR); cw_close(&cw); cipher_close(&cipher); fclose(fout); _wremove(outpath); EnableWindow(hCancel,FALSE); g_busy=0; return; }
        stream_copy_in(&cw, fin, fsz, hwnd, &done, fsz);
        fclose(fin);
    }

    cw_close(&cw);
    cipher_close(&cipher);
    fclose(fout);

    if (g_cancel_requested) {
        _wremove(outpath);
        SetWindowText(hStatus, L"Отменено пользователем.");
        SendMessage(hProgress, PBM_SETPOS, 0, 0);
        EnableWindow(hCancel, FALSE);
        g_busy = 0;
        return;
    }
    SendMessage(hProgress,PBM_SETPOS,100,0);

    uint64_t out_size = 0;
    { WIN32_FILE_ATTRIBUTE_DATA outfad;
      if (GetFileAttributesEx(outpath, GetFileExInfoStandard, &outfad))
          out_size = ((uint64_t)outfad.nFileSizeHigh << 32) | outfad.nFileSizeLow; }

    WCHAR msg[512];
    int pct = done ? (int)((out_size*100)/done) : 0;
    const wchar_t *method_name = (method==1) ? L"Mix (контекст+смеситель)" : L"LZ77+Хаффман";
    WCHAR levelline[64];
    if (method==1) wcscpy(levelline, L"Mix — без уровней");
    else _snwprintf(levelline,64,L"%d — %s",level,level_name(level));
    if (is_dir) {
        _snwprintf(msg,512,
            L"Готово!\r\n"
            L"Папка:            %d файл(ов), %llu байт\r\n"
            L"После сжатия:     %llu байт (%d%% от исходного)\r\n"
            L"Метод:            %s\r\n"
            L"Уровень:          %s\r\n"
            L"Результат:        %s",
            g_entry_count, (unsigned long long)done, (unsigned long long)out_size, pct, method_name, levelline, outpath);
    } else {
        _snwprintf(msg,512,
            L"Готово!\r\n"
            L"Исходный размер:  %llu байт\r\n"
            L"После сжатия:     %llu байт (%d%% от исходного)\r\n"
            L"Метод:            %s\r\n"
            L"Уровень:          %s\r\n"
            L"Результат:        %s",
            (unsigned long long)done, (unsigned long long)out_size, pct, method_name, levelline, outpath);
    }
    SetWindowText(hStatus,msg);
    EnableWindow(hCancel, FALSE);
    g_busy = 0;
}

static void do_decompress(HWND hwnd){
    if(!g_path[0]){MessageBox(hwnd,L"Сначала выбери файл.",L"SuperZip",MB_ICONWARNING);return;}
    if(g_busy) return;
    g_busy = 1;
    g_cancel_requested = 0;
    EnableWindow(hCancel, TRUE);
    SetWindowText(hStatus,L"Распаковываю...");
    SendMessage(hProgress,PBM_SETPOS,0,0);
    UpdateWindow(hwnd);

    FILE *fchk = _wfopen(g_path, L"rb");
    if(!fchk){ MessageBox(hwnd,L"Не могу открыть файл.",L"SuperZip",MB_ICONERROR); EnableWindow(hCancel,FALSE); g_busy=0; return; }
    char magic[4];
    int gotmagic = (fread(magic,1,4,fchk)==4);
    fclose(fchk);
    if(!gotmagic){ MessageBox(hwnd,L"Файл пуст или повреждён.",L"SuperZip",MB_ICONERROR); EnableWindow(hCancel,FALSE); g_busy=0; return; }

    WCHAR outpath[MAX_PATH];
    size_t plen=wcslen(g_path);
    if(plen>3 && _wcsicmp(g_path+plen-3,L".sz")==0){
        wcsncpy(outpath,g_path,plen-3); outpath[plen-3]=0;
    } else {
        wcsncpy(outpath,g_path,MAX_PATH-5); outpath[MAX_PATH-5]=0;
        wcsncat(outpath,L".out",5);
    }
    WCHAR msg[512];

    if (memcmp(magic,"SZ04",4)==0 || memcmp(magic,"SZ05",4)==0 || memcmp(magic,"SZE5",4)==0) {
        int encrypted = memcmp(magic,"SZE5",4)==0;
        int has_crc = encrypted || memcmp(magic,"SZ05",4)==0;
        FILE *fin = _wfopen(g_path, L"rb");
        if(!fin){ MessageBox(hwnd,L"Не могу открыть файл.",L"SuperZip",MB_ICONERROR); EnableWindow(hCancel,FALSE); g_busy=0; return; }

        Cipher cipher; memset(&cipher, 0, sizeof(cipher));
        if (encrypted) {
            uint8_t salt[16], nonce[8];
            fseek(fin, 4, SEEK_SET);
            if (fread(salt,1,16,fin)!=16 || fread(nonce,1,8,fin)!=8) {
                MessageBox(hwnd,L"Архив повреждён.",L"SuperZip",MB_ICONERROR); fclose(fin); EnableWindow(hCancel,FALSE); g_busy=0; return;
            }
            WCHAR password[256]; GetWindowText(hPassword, password, 256);
            if (!password[0]) {
                MessageBox(hwnd,L"Этот архив зашифрован — введи пароль в поле выше.",L"SuperZip",MB_ICONWARNING);
                fclose(fin); EnableWindow(hCancel,FALSE); g_busy=0; return;
            }
            if (!cipher_init_decrypt(&cipher, password, salt, nonce)) {
                MessageBox(hwnd,L"Не получилось настроить расшифровку.",L"SuperZip",MB_ICONERROR);
                fclose(fin); EnableWindow(hCancel,FALSE); g_busy=0; return;
            }
        } else {
            fseek(fin, 4, SEEK_SET);
        }

        ChunkReader cr; cr_init(&cr, fin, has_crc, &cipher);
        uint8_t kind;
        if(!cr_read(&cr,&kind,1)){
            MessageBox(hwnd,L"Архив повреждён.",L"SuperZip",MB_ICONERROR);
            cr_close(&cr); cipher_close(&cipher); fclose(fin); EnableWindow(hCancel,FALSE); g_busy=0; return;
        }

        if (kind==0) {
            uint64_t total=0;
            if(!cr_read_u64(&cr,&total)){
                MessageBox(hwnd,L"Архив повреждён.",L"SuperZip",MB_ICONERROR);
                cr_close(&cr); cipher_close(&cipher); fclose(fin); EnableWindow(hCancel,FALSE); g_busy=0; return;
            }
            FILE *fout=_wfopen(outpath,L"wb");
            if(!fout){
                MessageBox(hwnd,L"Не могу записать результат.",L"SuperZip",MB_ICONERROR);
                cr_close(&cr); cipher_close(&cipher); fclose(fin); EnableWindow(hCancel,FALSE); g_busy=0; return;
            }
            uint64_t done=0;
            stream_copy_out(&cr, fout, total, hwnd, &done, total);
            fclose(fout);
            SendMessage(hProgress,PBM_SETPOS,100,0);
            if (g_cancel_requested) {
                _wremove(outpath);
                wcscpy(msg, L"Отменено пользователем.");
            } else if (g_crc_fail && encrypted)
                _snwprintf(msg,512,L"ВНИМАНИЕ: неверный пароль (или архив повреждён)!\r\nРезультат всё равно записан, но он, скорее всего, мусор.\r\nРезультат: %s",
                           outpath);
            else if (g_crc_fail)
                _snwprintf(msg,512,L"ВНИМАНИЕ: контрольная сумма не совпала — архив повреждён!\r\nРезультат всё равно записан, но проверь его.\r\nРаспаковано: %llu байт\r\nРезультат: %s",
                           (unsigned long long)total, outpath);
            else
                _snwprintf(msg,512,L"Готово!\r\nРаспаковано: %llu байт\r\nРезультат: %s",
                           (unsigned long long)total, outpath);
            SetWindowText(hStatus,msg);
        } else if (kind==1) {
            uint8_t cb[4];
            if(!cr_read(&cr,cb,4)){
                MessageBox(hwnd,L"Архив повреждён.",L"SuperZip",MB_ICONERROR);
                cr_close(&cr); cipher_close(&cipher); fclose(fin); EnableWindow(hCancel,FALSE); g_busy=0; return;
            }
            uint32_t cnt = cb[0]|(cb[1]<<8)|(cb[2]<<16)|((uint32_t)cb[3]<<24);
            CreateDirectory(outpath,NULL);
            uint32_t extracted=0;
            for(uint32_t i=0;i<cnt && !g_cancel_requested;i++){
                uint8_t pb[2];
                if(!cr_read(&cr,pb,2)) break;
                uint16_t pl = pb[0]|(pb[1]<<8);
                wchar_t rel[MAX_PATH]; int nchars=pl/2; if(nchars>=MAX_PATH) nchars=MAX_PATH-1;
                if(!cr_read(&cr,(uint8_t*)rel,(size_t)nchars*2)) break;
                rel[nchars]=0;
                uint64_t fsz=0;
                if(!cr_read_u64(&cr,&fsz)) break;

                wchar_t full[MAX_PATH];
                _snwprintf(full,MAX_PATH,L"%s\\%s",outpath,rel);
                ensure_dirs_for(full);
                FILE *fo=_wfopen(full,L"wb");
                if(fo){
                    uint64_t done=0;
                    stream_copy_out(&cr, fo, fsz, hwnd, &done, fsz);
                    fclose(fo);
                    extracted++;
                }
                SendMessage(hProgress,PBM_SETPOS,(int)(((i+1)*100)/(cnt?cnt:1)),0);
                pump_messages();
            }
            if (g_cancel_requested)
                _snwprintf(msg,512,L"Отменено пользователем.\r\nУспело распаковаться файлов: %u\r\nПапка (неполная): %s",
                           (unsigned int)extracted, outpath);
            else if (g_crc_fail && encrypted)
                _snwprintf(msg,512,L"ВНИМАНИЕ: неверный пароль (или архив повреждён)!\r\nРаспаковано файлов: %u\r\nПапка: %s\r\nСодержимое, скорее всего, мусор.",
                           (unsigned int)extracted, outpath);
            else if (g_crc_fail)
                _snwprintf(msg,512,L"ВНИМАНИЕ: контрольная сумма не совпала — архив повреждён!\r\nРаспаковано файлов: %u\r\nПапка: %s\r\nПроверь содержимое — что-то может быть некорректным.",
                           (unsigned int)extracted, outpath);
            else
                _snwprintf(msg,512,L"Готово!\r\nРаспаковано файлов: %u\r\nПапка: %s",
                           (unsigned int)extracted, outpath);
            SetWindowText(hStatus,msg);
        } else {
            MessageBox(hwnd,L"Архив повреждён (неизвестный тип данных).",L"SuperZip",MB_ICONERROR);
        }
        cr_close(&cr);
        cipher_close(&cipher);
        fclose(fin);
    }
    else if (memcmp(magic,"SZ02",4)==0 || memcmp(magic,"SZ03",4)==0) {
        int legacy = memcmp(magic,"SZ02",4)==0;
        uint8_t *in; size_t in_size;
        if(!wread(g_path,&in,&in_size)){MessageBox(hwnd,L"Не могу открыть файл.",L"SuperZip",MB_ICONERROR); EnableWindow(hCancel,FALSE); g_busy=0; return;}
        SendMessage(hProgress,PBM_SETPOS,30,0); UpdateWindow(hwnd);
        uint64_t orig=0;for(int i=0;i<8;i++)orig|=(uint64_t)in[4+i]<<(8*i);
        uint8_t *out=malloc(orig?(size_t)orig:1);
        sz_decompress(in,in_size,out);
        SendMessage(hProgress,PBM_SETPOS,80,0); UpdateWindow(hwnd);

        if (legacy) {
            if(!wwrite(outpath,out,(size_t)orig)){
                MessageBox(hwnd,L"Не могу записать результат.",L"SuperZip",MB_ICONERROR);
            } else {
                SendMessage(hProgress,PBM_SETPOS,100,0);
                _snwprintf(msg,512,L"Готово! (старый формат архива)\r\nАрхив: %zu байт\r\nРаспаковано: %llu байт\r\nРезультат: %s",
                           in_size,(unsigned long long)orig,outpath);
                SetWindowText(hStatus,msg);
            }
        } else if (orig >= 1 && out[0] == 0) {
            if(!wwrite(outpath,out+1,(size_t)orig-1)){
                MessageBox(hwnd,L"Не могу записать результат.",L"SuperZip",MB_ICONERROR);
            } else {
                SendMessage(hProgress,PBM_SETPOS,100,0);
                _snwprintf(msg,512,L"Готово!\r\nАрхив: %zu байт\r\nРаспаковано: %llu байт\r\nРезультат: %s",
                           in_size,(unsigned long long)(orig-1),outpath);
                SetWindowText(hStatus,msg);
            }
        } else if (orig >= 1 && out[0] == 1) {
            uint32_t count = 0;
            if (!unpack_folder(out + 1, (size_t)orig - 1, outpath, &count)) {
                MessageBox(hwnd, L"Архив повреждён.", L"SuperZip", MB_ICONERROR);
            } else {
                SendMessage(hProgress,PBM_SETPOS,100,0);
                _snwprintf(msg,512,L"Готово!\r\nРаспаковано файлов: %u\r\nПапка: %s",(unsigned int)count, outpath);
                SetWindowText(hStatus,msg);
            }
        } else {
            MessageBox(hwnd,L"Архив повреждён (неизвестный тип данных внутри).",L"SuperZip",MB_ICONERROR);
        }
        free(in);free(out);
    }
    else {
        MessageBox(hwnd,L"Этот файл не похож на .sz архив SuperZip.\r\nВозможно, ты выбрал уже распакованный файл?",L"SuperZip",MB_ICONERROR);
    }
    EnableWindow(hCancel,FALSE); g_busy = 0;
}

static void update_level_text(int pos){
    WCHAR buf[64];
    _snwprintf(buf,64,L"Уровень %d — %s",pos,level_name(pos));
    SetWindowText(hLevelTxt,buf);
}

#define HEADER_H 52

static LRESULT CALLBACK WndProc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE: {
        HFONT hf=(HFONT)GetStockObject(DEFAULT_GUI_FONT);
        g_hbrGround = CreateSolidBrush(RGB(20,20,20));
        g_hbrPanel2 = CreateSolidBrush(RGB(42,42,42));

        HICON hib=(HICON)LoadImage(NULL,L"app_icon.ico",IMAGE_ICON,32,32,LR_LOADFROMFILE);
        if(hib) SendMessage(hwnd,WM_SETICON,ICON_BIG,(LPARAM)hib);
        HICON his=(HICON)LoadImage(NULL,L"app_icon.ico",IMAGE_ICON,16,16,LR_LOADFROMFILE);
        if(his) SendMessage(hwnd,WM_SETICON,ICON_SMALL,(LPARAM)his);

        DragAcceptFiles(hwnd, TRUE);

        HWND h;
        int y = HEADER_H + 10;
        h=CreateWindow(L"STATIC",L"Файл или папка (можно перетащить сюда):",WS_VISIBLE|WS_CHILD,10,y,400,18,hwnd,NULL,NULL,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hf,TRUE);

        hPath=CreateWindow(L"EDIT",L"",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_READONLY|ES_AUTOHSCROLL,10,y+21,438,24,hwnd,(HMENU)IDC_PATH,NULL,NULL);
        SendMessage(hPath,WM_SETFONT,(WPARAM)hf,TRUE);

        h=CreateWindow(L"BUTTON",L"Обзор файла...",WS_VISIBLE|WS_CHILD|BS_OWNERDRAW,10,y+49,213,24,hwnd,(HMENU)IDC_BROWSE,NULL,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hf,TRUE);
        h=CreateWindow(L"BUTTON",L"Обзор папки...",WS_VISIBLE|WS_CHILD|BS_OWNERDRAW,235,y+49,213,24,hwnd,(HMENU)IDC_BROWSE_DIR,NULL,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hf,TRUE);

        h=CreateWindow(L"STATIC",L"Метод сжатия:",WS_VISIBLE|WS_CHILD,10,y+83,120,18,hwnd,NULL,NULL,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hf,TRUE);
        hMethod=CreateWindow(L"COMBOBOX",L"",WS_VISIBLE|WS_CHILD|CBS_DROPDOWNLIST|WS_VSCROLL,
            135,y+80,313,200,hwnd,(HMENU)IDC_METHOD,NULL,NULL);
        SendMessage(hMethod,WM_SETFONT,(WPARAM)hf,TRUE);
        SendMessage(hMethod,CB_ADDSTRING,0,(LPARAM)L"LZ77 + Хаффман (быстрее)");
        SendMessage(hMethod,CB_ADDSTRING,0,(LPARAM)L"Mix: контекст + смеситель (сильнее жмёт, медленнее)");
        SendMessage(hMethod,CB_SETCURSEL,0,0);

        h=CreateWindow(L"STATIC",L"Пароль (необязательно, пусто — без шифрования):",WS_VISIBLE|WS_CHILD,10,y+113,400,18,hwnd,NULL,NULL,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hf,TRUE);
        hPassword=CreateWindow(L"EDIT",L"",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_PASSWORD|ES_AUTOHSCROLL,
            10,y+134,438,24,hwnd,(HMENU)IDC_PASSWORD,NULL,NULL);
        SendMessage(hPassword,WM_SETFONT,(WPARAM)hf,TRUE);

        h=CreateWindow(L"STATIC",L"Уровень сжатия (1 — быстро, 9 — максимум):",WS_VISIBLE|WS_CHILD,10,y+145,340,18,hwnd,NULL,NULL,NULL);
        SendMessage(h,WM_SETFONT,(WPARAM)hf,TRUE);

        hTrack=CreateWindowEx(0,TRACKBAR_CLASS,L"",WS_VISIBLE|WS_CHILD|TBS_AUTOTICKS|TBS_TOOLTIPS,10,y+165,250,30,hwnd,(HMENU)IDC_LEVEL,NULL,NULL);
        SendMessage(hTrack,TBM_SETRANGE,TRUE,MAKELONG(1,9));
        SendMessage(hTrack,TBM_SETTICFREQ,1,0);
        SendMessage(hTrack,TBM_SETPOS,TRUE,6);

        hLevelTxt=CreateWindow(L"STATIC",L"Уровень 6 — нормальный",WS_VISIBLE|WS_CHILD,268,y+172,180,18,hwnd,(HMENU)IDC_LEVELTXT,NULL,NULL);
        SendMessage(hLevelTxt,WM_SETFONT,(WPARAM)hf,TRUE);

        h=CreateWindow(L"BUTTON",L"▶  Сжать",WS_VISIBLE|WS_CHILD|BS_OWNERDRAW,10,y+207,200,36,hwnd,(HMENU)IDC_COMPRESS,NULL,NULL);
        h=CreateWindow(L"BUTTON",L"◀  Распаковать",WS_VISIBLE|WS_CHILD|BS_OWNERDRAW,220,y+207,228,36,hwnd,(HMENU)IDC_DECOMPRESS,NULL,NULL);

        hProgress=CreateWindowEx(0,PROGRESS_CLASS,L"",WS_VISIBLE|WS_CHILD,10,y+255,358,16,hwnd,(HMENU)IDC_PROGRESS,NULL,NULL);
        SendMessage(hProgress,PBM_SETRANGE,0,MAKELONG(0,100));

        hCancel=CreateWindow(L"BUTTON",L"Отмена",WS_VISIBLE|WS_CHILD|BS_OWNERDRAW,376,y+251,72,24,hwnd,(HMENU)IDC_CANCEL,NULL,NULL);
        EnableWindow(hCancel, FALSE);

        hStatus=CreateWindowEx(WS_EX_CLIENTEDGE,L"STATIC",L"Выбери файл или папку и нажми Сжать или Распаковать.",
            WS_VISIBLE|WS_CHILD,10,y+279,438,135,hwnd,(HMENU)IDC_STATUS,NULL,NULL);
        SendMessage(hStatus,WM_SETFONT,(WPARAM)hf,TRUE);
        return 0;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC dc=BeginPaint(hwnd,&ps);
        RECT rc; GetClientRect(hwnd,&rc);
        RECT header={0,0,rc.right,HEADER_H};
        HBRUSH hb=CreateSolidBrush(RGB(32,32,32));
        FillRect(dc,&header,hb);
        DeleteObject(hb);
        SetBkMode(dc,TRANSPARENT);

        HFONT fTitle=CreateFont(22,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FF_SWISS,L"Segoe UI");
        HFONT old=(HFONT)SelectObject(dc,fTitle);
        SetTextColor(dc,RGB(235,235,235));
        TextOut(dc,16,9,L"SuperZip",8);
        SelectObject(dc,old);
        DeleteObject(fTitle);

        HFONT fSub=CreateFont(13,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FF_SWISS,L"Segoe UI");
        old=(HFONT)SelectObject(dc,fSub);
        SetTextColor(dc,RGB(140,140,140));
        TextOut(dc,16,32,L"LZ77 + Хаффман + Mix",20);
        SelectObject(dc,old);
        DeleteObject(fSub);

        EndPaint(hwnd,&ps);
        return 0;
    }
    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT dis=(LPDRAWITEMSTRUCT)lp;
        int id = dis->CtlID;
        if(id==IDC_COMPRESS || id==IDC_DECOMPRESS || id==IDC_BROWSE || id==IDC_BROWSE_DIR || id==IDC_CANCEL){
            COLORREF bg, fg;
            int sel = (dis->itemState & ODS_SELECTED) != 0;
            int dis_state = (dis->itemState & ODS_DISABLED) != 0;
            if(id==IDC_COMPRESS){ bg = sel?RGB(185,48,48):RGB(220,60,60); fg = RGB(245,245,245); }
            else if(id==IDC_DECOMPRESS){ bg = sel?RGB(195,195,195):RGB(225,225,225); fg = RGB(25,25,25); }
            else if(id==IDC_CANCEL){
                if(dis_state){ bg = RGB(42,42,42); fg = RGB(100,100,100); }
                else { bg = sel?RGB(55,55,55):RGB(42,42,42); fg = RGB(220,60,60); }
            }
            else { bg = sel?RGB(58,58,58):RGB(42,42,42); fg = RGB(235,235,235); }

            HBRUSH hb=CreateSolidBrush(bg);
            FillRect(dis->hDC,&dis->rcItem,hb);
            DeleteObject(hb);
            if(id==IDC_CANCEL && !dis_state){
                HPEN pen=CreatePen(PS_SOLID,2,RGB(220,60,60));
                HPEN oldp=(HPEN)SelectObject(dis->hDC,pen);
                HBRUSH oldb=(HBRUSH)SelectObject(dis->hDC,(HBRUSH)GetStockObject(NULL_BRUSH));
                Rectangle(dis->hDC,dis->rcItem.left+1,dis->rcItem.top+1,dis->rcItem.right-1,dis->rcItem.bottom-1);
                SelectObject(dis->hDC,oldb); SelectObject(dis->hDC,oldp); DeleteObject(pen);
            }
            SetBkMode(dis->hDC,TRANSPARENT);
            SetTextColor(dis->hDC,fg);
            int fsz = (id==IDC_COMPRESS||id==IDC_DECOMPRESS) ? 15 : 13;
            HFONT hf2=CreateFont(fsz,0,0,0,FW_BOLD,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,
                CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FF_SWISS,L"Segoe UI");
            HFONT oldf=(HFONT)SelectObject(dis->hDC,hf2);
            WCHAR txt[64]; GetWindowText(dis->hwndItem,txt,64);
            RECT r=dis->rcItem;
            DrawText(dis->hDC,txt,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
            SelectObject(dis->hDC,oldf);
            DeleteObject(hf2);
            return TRUE;
        }
        return FALSE;
    }
    case WM_CTLCOLORSTATIC: {
        HDC hdc=(HDC)wp;
        SetTextColor(hdc, RGB(235,235,235));
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)g_hbrGround;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc=(HDC)wp;
        SetTextColor(hdc, RGB(235,235,235));
        SetBkColor(hdc, RGB(42,42,42));
        return (LRESULT)g_hbrPanel2;
    }
    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wp;
        UINT count = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0);
        WCHAR dropped[MAX_PATH];
        if (count > 0 && DragQueryFile(hDrop, 0, dropped, MAX_PATH) > 0) {
            wcsncpy(g_path, dropped, MAX_PATH - 1);
            g_path[MAX_PATH - 1] = 0;
            SetWindowText(hPath, g_path);
            DWORD attr = GetFileAttributes(g_path);
            int is_dir = (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
            if (count > 1) {
                SetWindowText(hStatus, L"Перетащено несколько объектов — взят только первый\r\n(выбор сразу нескольких файлов пока не поддерживается).");
            } else {
                SetWindowText(hStatus, is_dir ? L"Папка перетащена. Нажми Сжать."
                                               : L"Файл перетащен. Нажми Сжать или Распаковать.");
            }
        }
        DragFinish(hDrop);
        return 0;
    }
    case WM_HSCROLL:
        if((HWND)lp==hTrack)
            update_level_text((int)SendMessage(hTrack,TBM_GETPOS,0,0));
        return 0;
    case WM_COMMAND:
        if(HIWORD(wp)==BN_CLICKED){
            switch(LOWORD(wp)){
            case IDC_BROWSE:     do_browse(hwnd);     break;
            case IDC_BROWSE_DIR: do_browse_folder(hwnd); break;
            case IDC_COMPRESS:   do_compress(hwnd);   break;
            case IDC_DECOMPRESS: do_decompress(hwnd); break;
            case IDC_CANCEL:
                g_cancel_requested = 1;
                SetWindowText(hStatus, L"Отменяю... (закончится после текущего блока)");
                break;
            }
        } else if(LOWORD(wp)==IDC_METHOD && HIWORD(wp)==CBN_SELCHANGE){
            int m = (int)SendMessage(hMethod,CB_GETCURSEL,0,0);
            EnableWindow(hTrack, m==0);
            if(m==1) SetWindowText(hLevelTxt, L"не используется для Mix");
            else update_level_text((int)SendMessage(hTrack,TBM_GETPOS,0,0));
        }
        return 0;
    case WM_DESTROY:
        if(g_hbrGround){ DeleteObject(g_hbrGround); g_hbrGround=NULL; }
        if(g_hbrPanel2){ DeleteObject(g_hbrPanel2); g_hbrPanel2=NULL; }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProc(hwnd,msg,wp,lp);
}

int WINAPI WinMain(HINSTANCE hInst,HINSTANCE hPrev,LPSTR lpCmd,int nShow){
    (void)hPrev;(void)lpCmd;
    INITCOMMONCONTROLSEX icc;
    icc.dwSize=sizeof(icc); icc.dwICC=ICC_BAR_CLASSES|ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    int argcw=0;
    LPWSTR *argvw = CommandLineToArgvW(GetCommandLine(), &argcw);
    if (argvw && argcw >= 2) {
        wcsncpy(g_path, argvw[1], MAX_PATH-1);
        g_path[MAX_PATH-1]=0;
        g_autorun = 1;
    }
    if (argvw) LocalFree(argvw);

    const wchar_t CN[]=L"SuperZipWnd";
    WNDCLASSEX wc; memset(&wc,0,sizeof(wc));
    wc.cbSize=sizeof(wc); wc.lpfnWndProc=WndProc;
    wc.hInstance=hInst; wc.lpszClassName=CN;
    wc.hCursor=LoadCursor(NULL,IDC_ARROW);
    wc.hbrBackground=CreateSolidBrush(RGB(20,20,20));
    wc.hIcon=LoadIcon(NULL,IDI_APPLICATION);
    RegisterClassEx(&wc);

    HWND hwnd=CreateWindowEx(0,CN,L"SuperZip 1.0",
        (WS_OVERLAPPEDWINDOW&~WS_THICKFRAME&~WS_MAXIMIZEBOX),
        CW_USEDEFAULT,CW_USEDEFAULT,470,532,
        NULL,NULL,hInst,NULL);
    if(!hwnd)return 0;

    ShowWindow(hwnd,nShow);
    UpdateWindow(hwnd);

    if (g_autorun && g_path[0]) {
        SetWindowText(hPath, g_path);
        size_t pl = wcslen(g_path);
        if (pl > 3 && _wcsicmp(g_path + pl - 3, L".sz") == 0)
            do_decompress(hwnd);
        else
            do_compress(hwnd);
    }

    MSG m;
    while(GetMessage(&m,NULL,0,0)){
        TranslateMessage(&m);
        DispatchMessage(&m);
    }
    return 0;
}
