/*
 * Git: https://github.com/crypery
 * Author: https://crypery.com
 * License: GNU AGPL v3 (Affero GPL)
 */

/*
 * mini-acme.c - automatic ACME (RFC 8555) certificate management in pure C.
 *
 * C analog of creating-acme-certificates-with-go (golang.org/x/crypto/acme/autocert):
 *   - obtains and renews RSA 2048 certificates from Let's Encrypt for one or
 *     more domains (SAN) using the "http-01" challenge; wildcard domains
 *     (*.example.com) cannot be validated with http-01, so they are validated
 *     with the "dns-01" challenge (the program prints the required TXT record
 *     and waits until it becomes publicly resolvable);
 *   - keeps the ACME account key and issued certificates in a local cache
 *     directory (analog of autocert.DirCache("certs"));
 *   - serves the http-01 challenge on port 80 during validation
 *     (analog of Manager.HTTPHandler);
 *   - obtains the certificate once and saves it to the cache directory,
 *     then exits (no HTTPS server is started);
 *   - reuses a cached certificate if it is still valid for more than
 *     30 days (analog of Manager.RenewBefore: 30 days).
 *
 * JSON responses of the ACME server are parsed with the utilery json module.
 *
 * Usage:
 *   mini-acme [-domain <name>]... [-dir <acme-directory-url>] [-cache <dir>]
 *             [-email <addr>] [--apikey <key> --dns <provider>] [-h]
 *
 * Example:
 *   mini-acme -domain example.com -domain www.example.com
 *   wildcard (TXT record at the DNS provider, printed at runtime):
 *   mini-acme -domain example.com -domain '*.example.com'
 *   wildcard with automatic TXT record management (dynadot API):
 *   mini-acme -domain example.com -domain '*.example.com' --dns dynadot --apikey <key>
 *   for test
 *   mini-acme -domain example.com -dir https://acme-staging-v02.api.letsencrypt.org/directory
 *
 * Cross-platform: Windows (Winsock2/WinAPI) and POSIX (BSD sockets/pthreads).
 */

#include "tls.h"
#include "url.h"
#include "http.h"
#include "json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#endif

#define DEFAULT_ACME_DIR  "https://acme-v02.api.letsencrypt.org/directory"
#define DEFAULT_CACHE_DIR "certs"
#define DEFAULT_EMAIL     "admin@example.com"
#define RENEW_BEFORE_SEC  (30 * 86400)   /* renew 30 days before expiry */
#define CHAL_PORT         80
#define ACME_MAX_AUTHZ    8
#define MAX_DOMAINS       8   /* max -domain flags / SAN entries per certificate */

/* --- globals --- */

static volatile int g_stop = 0;
static char g_domain[256];
/* Grace period after the dns-01 TXT record is confirmed visible before
 * accepting the challenge: Let's Encrypt's validators query from other
 * resolvers that may still cache a negative (NODATA) answer for the name. */
#define DNS_PROPAGATION_WAIT_SEC 300

/* --- small platform helpers --- */

static void msleep(int ms) {
#ifdef _WIN32
    Sleep((DWORD)ms);
#else
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
#endif
}

static int get_hostname(char *out, size_t outsz) {
#ifdef _WIN32
    DWORD sz = (DWORD)outsz;
    return GetComputerNameA(out, &sz) ? 0 : -1;
#else
    return gethostname(out, outsz) == 0 ? 0 : -1;
#endif
}

/* Create a directory and all missing parents (split on '/' and '\') */
static void ensure_dir(const char *path) {
    char tmp[1024];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char save = *p;
            *p = '\0';
            if (tmp[0]) {
#ifdef _WIN32
                CreateDirectoryA(tmp, NULL);
#else
                mkdir(tmp, 0755);
#endif
            }
            *p = save;
        }
    }
    if (tmp[0]) {
#ifdef _WIN32
        CreateDirectoryA(tmp, NULL);
#else
        mkdir(tmp, 0755);
#endif
    }
}

static long read_file(const char *path, char *buf, size_t max_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t r = fread(buf, 1, max_len, f);
    fclose(f);
    return (long)r;
}

static int write_file(const char *path, const void *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t off = 0;
    while (off < len) {
        size_t w = fwrite((const char *)buf + off, 1, len - off, f);
        if (w == 0) { fclose(f); return -1; }
        off += w;
    }
    fclose(f);
    return 0;
}

/* --- base64 / base64url --- */

static const char B64_T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char B64URL_T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static int b64url_encode(const uint8_t *in, int len, char *out, int outsz) {
    int o = 0;
    for (int i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        int rem = len - i;
        if (rem > 1) v |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) v |= in[i + 2];
        if (o + 4 >= outsz) return -1;
        out[o++] = B64URL_T[(v >> 18) & 0x3F];
        out[o++] = B64URL_T[(v >> 12) & 0x3F];
        if (rem > 1) out[o++] = B64URL_T[(v >> 6) & 0x3F];
        if (rem > 2) out[o++] = B64URL_T[v & 0x3F];
    }
    if (o >= outsz) return -1;
    out[o] = '\0';
    return o;
}

static int b64_val(char c) {
    const char *p = strchr(B64_T, c);
    return p ? (int)(p - B64_T) : -1;
}

static int b64_decode(const char *in, int in_len, uint8_t *out, int max_out) {
    int o = 0, acc = 0, bits = 0;
    for (int i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (c == '=') break;
        int v = b64_val(c);
        if (v < 0) return -1;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o >= max_out) return -1;
            out[o++] = (uint8_t)((acc >> bits) & 0xFF);
        }
    }
    return o;
}

/* --- JSON helpers over the utilery json module --- */

/* String member of a JSON object (NULL if absent or not a string). */
static const char *jstr(const JsonValue *obj, const char *key) {
    if (!obj) return NULL;
    return json_string(json_get(obj, key));
}

/* Parse a JSON document; returns the root value or NULL. */
static JsonValue *jparse(const char *text) {
    return text ? json_parse_buf(text, strlen(text)) : NULL;
}

/* --- DER helpers (same scheme as tls.c / mini-cert.c) --- */

static int der_enc_len(uint8_t *out, int len) {
    if (len < 0x80) { out[0] = (uint8_t)len; return 1; }
    if (len < 0x100) { out[0] = 0x81; out[1] = (uint8_t)len; return 2; }
    if (len < 0x10000) { out[0] = 0x82; out[1] = (uint8_t)(len >> 8); out[2] = (uint8_t)(len & 0xFF); return 3; }
    return 0;
}

static int der_header(uint8_t *out, uint8_t tag, int content_len) {
    out[0] = tag;
    int l = der_enc_len(out + 1, content_len);
    return 1 + l;
}

static int der_push(uint8_t *out, int p, uint8_t tag, const uint8_t *content, int content_len) {
    int h = der_header(out + p, tag, content_len);
    if (content_len > 0) memcpy(out + p + h, content, (size_t)content_len);
    return p + h + content_len;
}

static int der_integer(uint8_t *out, const uint8_t *val, int len) {
    int vlen = len;
    if (val[0] & 0x80) vlen++;
    int h = der_header(out, 0x02, vlen);
    int p = h;
    if (vlen > len) out[p++] = 0x00;
    memcpy(out + p, val, (size_t)len);
    return p + len;
}

static int der_read_len(const uint8_t *in, int *p, int len) {
    if (*p + 1 > len) return -1;
    int l = in[(*p)++];
    if (l & 0x80) {
        int nb = l & 0x7F;
        if (nb < 1 || nb > 4 || *p + nb > len) return -1;
        l = 0;
        while (nb--) l = (l << 8) | in[(*p)++];
    }
    return l;
}

/* PKCS#1 RSAPrivateKey DER (same as mini-cert.c) */
static int build_private_pkcs1(const RSAKey *key, uint8_t *out) {
    uint8_t body[1200];
    int p = 0;
    uint8_t ver = 0;
    p += der_integer(body + p, &ver, 1);
    p += der_integer(body + p, key->n, key->n_len);
    p += der_integer(body + p, key->e, key->e_len);
    p += der_integer(body + p, key->d, sizeof(key->d));
    p += der_integer(body + p, key->p, sizeof(key->p));
    p += der_integer(body + p, key->q, sizeof(key->q));
    p += der_integer(body + p, key->dmp1, sizeof(key->dmp1));
    p += der_integer(body + p, key->dmq1, sizeof(key->dmq1));
    p += der_integer(body + p, key->iqmp, sizeof(key->iqmp));
    return der_push(out, 0, 0x30, body, p);
}

/* --- PEM helpers --- */

static char *pem_build(const char *label, const uint8_t *data, int len) {
    char *encoded = (char *)malloc((size_t)len * 4 / 3 + 8);
    if (!encoded) return NULL;
    int o = 0;
    for (int i = 0; i < len; i += 3) {
        uint32_t v = ((uint32_t)data[i] << 16);
        int rem = len - i;
        if (rem > 1) v |= ((uint32_t)data[i + 1] << 8);
        if (rem > 2) v |= (uint32_t)data[i + 2];
        encoded[o++] = B64_T[(v >> 18) & 0x3F];
        encoded[o++] = B64_T[(v >> 12) & 0x3F];
        encoded[o++] = rem > 1 ? B64_T[(v >> 6) & 0x3F] : '=';
        encoded[o++] = rem > 2 ? B64_T[v & 0x3F] : '=';
    }
    encoded[o] = '\0';
    size_t elen = (size_t)o;
    size_t lines = (elen + 63) / 64;
    size_t cap = 128 + elen + lines + 2 * strlen(label);
    char *pem = (char *)malloc(cap);
    if (!pem) { free(encoded); return NULL; }
    size_t po = 0;
    po += (size_t)snprintf(pem + po, cap - po, "-----BEGIN %s-----\n", label);
    for (size_t i = 0; i < elen; i += 64) {
        size_t n = (elen - i < 64) ? (elen - i) : 64;
        memcpy(pem + po, encoded + i, n);
        po += n;
        pem[po++] = '\n';
    }
    po += (size_t)snprintf(pem + po, cap - po, "-----END %s-----\n", label);
    free(encoded);
    return pem;
}

/* Extract the first CERTIFICATE block of a PEM string into DER. */
static int cert_first_der(const char *pem, uint8_t *out, int *out_len) {
    const char *b = strstr(pem, "-----BEGIN CERTIFICATE-----");
    if (!b) return -1;
    const char *e = strstr(b, "-----END CERTIFICATE-----");
    if (!e) return -1;
    int dl = b64_decode(b + 27, (int)(e - (b + 27)), out, TLS_RSA_MAX_CERT_SIZE);
    if (dl <= 0) return -1;
    *out_len = dl;
    return 0;
}

/* --- X.509 validity parsing (NotAfter) --- */

static time_t civil_to_epoch(int y, int m, int d, int hh, int mm, int ss) {
    if (m <= 2) y--;
    int era = (y >= 0 ? y : y - 399) / 400;
    int yoe = y - era * 400;
    int mp = (m + 9) % 12;
    int doy = (153 * mp + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long long days = (long long)era * 146097 + doe - 719468;
    return (time_t)(days * 86400LL + (long long)hh * 3600 + mm * 60 + ss);
}

static int parse_x509_time(const char *s, int len, uint8_t tag, time_t *out) {
    if (tag == 0x17) {
        if (len != 13) return -1;
        int yy = (s[0] - '0') * 10 + (s[1] - '0');
        int y = yy + (yy < 50 ? 2000 : 1900);
        int mo = (s[2] - '0') * 10 + (s[3] - '0');
        int d  = (s[4] - '0') * 10 + (s[5] - '0');
        int hh = (s[6] - '0') * 10 + (s[7] - '0');
        int mi = (s[8] - '0') * 10 + (s[9] - '0');
        int se = (s[10] - '0') * 10 + (s[11] - '0');
        *out = civil_to_epoch(y, mo, d, hh, mi, se);
        return 0;
    }
    if (tag == 0x18) {
        if (len != 15) return -1;
        int y  = (s[0] - '0') * 1000 + (s[1] - '0') * 100 + (s[2] - '0') * 10 + (s[3] - '0');
        int mo = (s[4] - '0') * 10 + (s[5] - '0');
        int d  = (s[6] - '0') * 10 + (s[7] - '0');
        int hh = (s[8] - '0') * 10 + (s[9] - '0');
        int mi = (s[10] - '0') * 10 + (s[11] - '0');
        int se = (s[12] - '0') * 10 + (s[13] - '0');
        *out = civil_to_epoch(y, mo, d, hh, mi, se);
        return 0;
    }
    return -1;
}

/* Walk the X.509 DER and return the NotAfter time. */
static int cert_not_after(const uint8_t *der, int len, time_t *out) {
    int p = 0;
    if (len < 4 || der[p] != 0x30) return -1;
    p++;
    int l = der_read_len(der, &p, len);
    if (l < 0) return -1;
    if (p >= len || der[p] != 0x30) return -1;          /* tbsCertificate */
    p++;
    l = der_read_len(der, &p, len);
    if (l < 0) return -1;
    if (p < len && der[p] == 0xA0) {                     /* version [0] (optional) */
        p++;
        int v = der_read_len(der, &p, len);
        if (v < 0 || p + v > len) return -1;
        p += v;
    }
    if (p >= len || der[p] != 0x02) return -1;           /* serialNumber */
    p++;
    int sl = der_read_len(der, &p, len);
    if (sl < 0 || p + sl > len) return -1;
    p += sl;
    if (p >= len || der[p] != 0x30) return -1;           /* signature */
    p++;
    int al = der_read_len(der, &p, len);
    if (al < 0 || p + al > len) return -1;
    p += al;
    if (p >= len || der[p] != 0x30) return -1;           /* issuer */
    p++;
    int il = der_read_len(der, &p, len);
    if (il < 0 || p + il > len) return -1;
    p += il;
    if (p >= len || der[p] != 0x30) return -1;           /* validity */
    p++;
    int vl = der_read_len(der, &p, len);
    if (vl < 0 || p + vl > len) return -1;
    if (p >= len) return -1;
    uint8_t tb = der[p];                                  /* notBefore */
    if (tb != 0x17 && tb != 0x18) return -1;
    p++;
    int nbl = der_read_len(der, &p, len);
    if (nbl < 0 || p + nbl > len) return -1;
    p += nbl;
    if (p >= len) return -1;
    uint8_t ta = der[p];                                  /* notAfter */
    if (ta != 0x17 && ta != 0x18) return -1;
    p++;
    int nal = der_read_len(der, &p, len);
    if (nal < 0 || p + nal > len) return -1;
    char tbuf[32];
    if (nal >= (int)sizeof(tbuf)) return -1;
    memcpy(tbuf, der + p, (size_t)nal);
    tbuf[nal] = '\0';
    return parse_x509_time(tbuf, nal, ta, out);
}

static int dns_equal_nocase(const char *a, const uint8_t *b, int blen) {
    int i = 0;
    if (!a || !b || blen < 0) return 0;
    for (; a[i] && i < blen; i++) {
        char ca = a[i], cb = (char)b[i];
        if (ca >= 'A' && ca <= 'Z') ca += (char)32;
        if (cb >= 'A' && cb <= 'Z') cb += (char)32;
        if (ca != cb) return 0;
    }
    return a[i] == '\0' && i == blen;
}

/* 1 if every requested domain is listed as dNSName in the leaf SAN.
 * Prevents silent reuse of a stale cached cert that does not cover
 * all requested domains (e.g. apex-only cache when apex+www asked). */
static int cert_san_covers(const uint8_t *der, int len,
                           const char *const *domains, int ndomains) {
    static const uint8_t SAN_OID[3] = { 0x55, 0x1d, 0x11 };
    static const uint8_t TBS_TAGS[6] = { 0x02, 0x30, 0x30, 0x30, 0x30, 0x30 };
    int found[MAX_DOMAINS] = { 0 };
    int p = 0, l, end, exts_end;
    if (!der || len < 4 || !domains || ndomains < 1 || ndomains > MAX_DOMAINS) return 0;
    if (der[p++] != 0x30) return 0;
    if (der_read_len(der, &p, len) < 0) return 0;
    if (p >= len || der[p++] != 0x30) return 0;
    if ((l = der_read_len(der, &p, len)) < 0) return 0;
    end = p + l;
    if (end > len) return 0;
    if (p < end && der[p] == 0xA0) {           /* version [0] */
        p++;
        if ((l = der_read_len(der, &p, len)) < 0 || p + l > end) return 0;
        p += l;
    }
    for (int i = 0; i < 6; i++) {             /* serial..spki */
        if (p >= end || der[p] != TBS_TAGS[i]) return 0;
        p++;
        if ((l = der_read_len(der, &p, len)) < 0 || p + l > end) return 0;
        p += l;
    }
    if (p < end && (der[p] == 0xA1 || der[p] == 0xA2)) {  /* unique IDs */
        p++;
        if ((l = der_read_len(der, &p, len)) < 0 || p + l > end) return 0;
        p += l;
    }
    if (p >= end || der[p] != 0xA3) return 0;  /* no extensions -> no SAN */
    p++;
    if ((l = der_read_len(der, &p, len)) < 0 || p + l > end) return 0;
    exts_end = p + l;
    if (p >= exts_end || der[p] != 0x30) return 0;
    p++;
    if ((l = der_read_len(der, &p, len)) < 0 || p + l > exts_end) return 0;
    exts_end = p + l;
    while (p < exts_end) {
        int e_end, ol, vl;
        if (der[p++] != 0x30) return 0;
        if ((l = der_read_len(der, &p, len)) < 0 || p + l > exts_end) return 0;
        e_end = p + l;
        if (p >= e_end || der[p] != 0x06) return 0;
        p++;
        if ((ol = der_read_len(der, &p, len)) < 0 || p + ol > e_end) return 0;
        {
            int is_san = (ol == 3 && memcmp(der + p, SAN_OID, 3) == 0);
            p += ol;
            if (p < e_end && der[p] == 0x01) {  /* critical flag */
                p++;
                if ((l = der_read_len(der, &p, len)) < 0 || p + l > e_end) return 0;
                p += l;
            }
            if (p >= e_end || der[p] != 0x04) return 0;
            p++;
            if ((vl = der_read_len(der, &p, len)) < 0 || p + vl > e_end) return 0;
            if (is_san) {
                int gp = p, gend = p + vl, gl;
                if (gp >= gend || der[gp] != 0x30) return 0;
                gp++;
                if ((gl = der_read_len(der, &gp, len)) < 0 || gp + gl > gend) return 0;
                gend = gp + gl;
                while (gp < gend) {
                    uint8_t t = der[gp++];
                    int nl;
                    if ((nl = der_read_len(der, &gp, len)) < 0 || gp + nl > gend) return 0;
                    if (t == 0x82) {
                        for (int d = 0; d < ndomains; d++)
                            if (dns_equal_nocase(domains[d], der + gp, nl)) found[d] = 1;
                    }
                    gp += nl;
                }
            }
        }
        p = e_end;
    }
    for (int d = 0; d < ndomains; d++)
        if (!found[d]) return 0;
    return 1;
}

/* --- PKCS#10 CSR (CertificationRequest) --- */

static const uint8_t OID_SHA256_RSA[9]  = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x0b };
static const uint8_t OID_RSA_ENCRYPT[9] = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01 };
static const uint8_t OID_CN[3]          = { 0x55, 0x04, 0x03 };
static const uint8_t OID_EXT_REQ[9]     = { 0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x0e };
static const uint8_t OID_SAN[3]         = { 0x55, 0x1d, 0x11 };

/* Build a CSR with CN=domains[0] and SAN=dNSName for every domain.
 * Multi-SAN is required for e.g. apex+www on a single certificate. */
static int build_csr(const RSAKey *key, const char *const *domains, int ndomains,
                     uint8_t *out, int out_max, int *out_len) {
    if (!key || !key->is_private) return -1;
    if (!domains || ndomains < 1 || ndomains > MAX_DOMAINS) return -1;
    const char *cn = domains[0];
    if (!cn || !*cn || strlen(cn) > 253) return -1;

    uint8_t oids[40];
    int ol = 0;
    ol = der_push(oids, ol, 0x06, OID_RSA_ENCRYPT, 9);
    oids[ol++] = 0x05; oids[ol++] = 0x00;
    uint8_t rsa_alg[48];
    int ra = der_push(rsa_alg, 0, 0x30, oids, ol);

    uint8_t sig_oids[40];
    int so = 0;
    so = der_push(sig_oids, so, 0x06, OID_SHA256_RSA, 9);
    sig_oids[so++] = 0x05; sig_oids[so++] = 0x00;
    uint8_t sig_alg[48];
    int sa = der_push(sig_alg, 0, 0x30, sig_oids, so);

    uint8_t rpk[700], rpk_seq[700];
    int rp = 0;
    rp += der_integer(rpk + rp, key->n, key->n_len);
    rp += der_integer(rpk + rp, key->e, key->e_len);
    int rs = der_push(rpk_seq, 0, 0x30, rpk, rp);

    uint8_t bit[700];
    bit[0] = 0x00;
    memcpy(bit + 1, rpk_seq, (size_t)rs);

    uint8_t spki_content[800];
    int sc = 0;
    memcpy(spki_content, rsa_alg, (size_t)ra);
    sc += ra;
    sc = der_push(spki_content, sc, 0x03, bit, rs + 1);
    uint8_t spki[800];
    int st = der_push(spki, 0, 0x30, spki_content, sc);

    uint8_t atv[512];
    int ap = 0;
    ap = der_push(atv, ap, 0x06, OID_CN, 3);
    ap = der_push(atv, ap, 0x13, (const uint8_t *)cn, (int)strlen(cn));
    uint8_t rdn[520];
    int rl = der_push(rdn, 0, 0x30, atv, ap);
    uint8_t rdnset[530];
    int sl = der_push(rdnset, 0, 0x31, rdn, rl);
    uint8_t subj[540];
    int sj = der_push(subj, 0, 0x30, rdnset, sl);

    /* attributes [0] IMPLICIT Attributes with extensionRequest
     * (SAN=dNSName for every requested domain).
     * Chrome (>=58) ignores CN and requires SAN, so a CSR without SAN
     * yields a certificate that Chrome rejects. */
    uint8_t gn[2200];
    int gp = 0;
    for (int d = 0; d < ndomains; d++) {
        size_t dl = strlen(domains[d]);
        if (!domains[d] || dl == 0 || dl > 253) return -1;
        gp = der_push(gn, gp, 0x82, (const uint8_t *)domains[d], (int)dl);
        if (gp <= 0) return -1;
    }
    uint8_t san_seq[2250];
    int san_len = der_push(san_seq, 0, 0x30, gn, gp);
    if (san_len <= 0) return -1;
    uint8_t ext_inner[2300];
    int ei = 0;
    ei = der_push(ext_inner, ei, 0x06, OID_SAN, 3);
    ei = der_push(ext_inner, ei, 0x04, san_seq, san_len);
    if (ei <= 0) return -1;
    uint8_t ext[2350];
    int ext_len = der_push(ext, 0, 0x30, ext_inner, ei);
    if (ext_len <= 0) return -1;
    uint8_t exts[2400];
    int exts_len = der_push(exts, 0, 0x30, ext, ext_len);
    if (exts_len <= 0) return -1;
    uint8_t attr_val[2450];
    int attr_val_len = der_push(attr_val, 0, 0x31, exts, exts_len);
    if (attr_val_len <= 0) return -1;
    uint8_t attr_inner[2600];
    int ai = 0;
    ai = der_push(attr_inner, ai, 0x06, OID_EXT_REQ, 9);
    if (ai <= 0) return -1;
    if (ai + attr_val_len > (int)sizeof(attr_inner)) return -1;
    memcpy(attr_inner + ai, attr_val, (size_t)attr_val_len);
    ai += attr_val_len;
    uint8_t attr[2650];
    int attr_len = der_push(attr, 0, 0x30, attr_inner, ai);
    if (attr_len <= 0) return -1;

    uint8_t tbs[4096];
    int p = 0;
    uint8_t ver[3] = { 0x02, 0x01, 0x00 };
    memcpy(tbs + p, ver, 3); p += 3;
    memcpy(tbs + p, subj, (size_t)sj); p += sj;
    memcpy(tbs + p, spki, (size_t)st); p += st;
    {
        uint8_t attr_hdr[8];
        int hl = der_header(attr_hdr, 0xA0, attr_len);
        if (hl <= 0) return -1;
        if (p + hl + attr_len > (int)sizeof(tbs)) return -1;
        memcpy(tbs + p, attr_hdr, (size_t)hl); p += hl;
        memcpy(tbs + p, attr, (size_t)attr_len); p += attr_len;
    }

    uint8_t tbs_seq[4400];
    int tbs_len = der_push(tbs_seq, 0, 0x30, tbs, p);
    if (tbs_len <= 0) return -1;

    uint8_t hash[32];
    SHA256State sha;
    sha256_init(&sha);
    sha256_process(&sha, tbs_seq, tbs_len);
    sha256_done(&sha, hash);
    uint8_t sig[256];
    int sig_len = 0;
    if (tls_rsa_sign(key, hash, sig, &sig_len) != 0) return -1;

    uint8_t sigbit[257];
    sigbit[0] = 0x00;
    memcpy(sigbit + 1, sig, (size_t)sig_len);

    uint8_t inner[5000];
    int ip = 0;
    memcpy(inner, tbs_seq, (size_t)tbs_len); ip = tbs_len;
    memcpy(inner + ip, sig_alg, (size_t)sa); ip += sa;
    ip = der_push(inner, ip, 0x03, sigbit, sig_len + 1);
    int hdr = der_header(out, 0x30, ip);
    if (hdr <= 0) return -1;
    if (hdr + ip > out_max) return -1;
    memcpy(out + hdr, inner, (size_t)ip);
    *out_len = hdr + ip;
    return 0;
}

/* --- ACME client (RFC 8555) --- */

typedef struct {
    char dir_url[256];
    char new_account[512];
    char new_nonce[512];
    char new_order[512];
    char revoke_cert[512];
    char terms[512];
    char email[256];
    char cache_dir[256];
    char kid[512];
    char nonce[256];
    int  have_nonce;
    char api_key[256];
    char dns_provider[64];
    int  have_dns_api;
    RSAKey account_key;
    int  have_account_key;
    UrlCtx *http;
} AcmeClient;

static AcmeClient g_acme;

static void acme_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    printf("[acme] ");
    vprintf(fmt, ap);
    va_end(ap);
}

static void acme_init(AcmeClient *ac, const char *dir_url, const char *cache_dir, const char *email) {
    memset(ac, 0, sizeof(*ac));
    strncpy(ac->dir_url, dir_url ? dir_url : DEFAULT_ACME_DIR, sizeof(ac->dir_url) - 1);
    strncpy(ac->cache_dir, cache_dir ? cache_dir : DEFAULT_CACHE_DIR, sizeof(ac->cache_dir) - 1);
    strncpy(ac->email, email ? email : DEFAULT_EMAIL, sizeof(ac->email) - 1);
}

/* JWK (RFC 7517) of the RSA account key */
static int acme_jwk(const AcmeClient *ac, char *out, int outsz) {
    char nb[384], eb[16];
    if (b64url_encode(ac->account_key.n, ac->account_key.n_len, nb, sizeof(nb)) < 0) return -1;
    if (b64url_encode(ac->account_key.e, ac->account_key.e_len, eb, sizeof(eb)) < 0) return -1;
    int l = snprintf(out, (size_t)outsz, "{\"e\":\"%s\",\"kty\":\"RSA\",\"n\":\"%s\"}", eb, nb);
    return (l > 0 && l < outsz) ? 0 : -1;
}

/* Key thumbprint (RFC 7638): base64url(sha256(canonical JWK)) */
static int acme_thumbprint(const AcmeClient *ac, char *out, int outsz) {
    char jwk[512];
    if (acme_jwk(ac, jwk, sizeof(jwk)) != 0) return -1;
    uint8_t hash[32];
    SHA256State sha;
    sha256_init(&sha);
    sha256_process(&sha, (const uint8_t *)jwk, (int)strlen(jwk));
    sha256_done(&sha, hash);
    return b64url_encode(hash, 32, out, outsz) >= 0 ? 0 : -1;
}

static int acme_fetch_nonce(AcmeClient *ac) {
    char *body = url_run(ac->http, ac->new_nonce, "HEAD", NULL);
    if (body) free(body);
    const char *rn = url_response_header(ac->http, "replay-nonce");
    if (!rn || !*rn) return -1;
    strncpy(ac->nonce, rn, sizeof(ac->nonce) - 1);
    ac->nonce[sizeof(ac->nonce) - 1] = '\0';
    ac->have_nonce = 1;
    return 0;
}

/* Build a JWS (RFC 7515) body. The "url" member is always present
 * (Boulder requires it even for newAccount). */
static int acme_jws(AcmeClient *ac, const char *url, const char *payload, char *out, int outsz) {
    if (!ac->have_nonce && acme_fetch_nonce(ac) != 0) {
        acme_log("failed to fetch nonce\n");
        return -1;
    }
    char protected[2048];
    if (ac->kid[0]) {
        snprintf(protected, sizeof(protected),
                 "{\"alg\":\"RS256\",\"kid\":\"%s\",\"nonce\":\"%s\",\"url\":\"%s\"}",
                 ac->kid, ac->nonce, url);
    } else {
        char jwk[512];
        if (acme_jwk(ac, jwk, sizeof(jwk)) != 0) return -1;
        snprintf(protected, sizeof(protected),
                 "{\"alg\":\"RS256\",\"jwk\":%s,\"nonce\":\"%s\",\"url\":\"%s\"}",
                 jwk, ac->nonce, url);
    }
    char pb[2048], pl[8192];
    if (b64url_encode((const uint8_t *)protected, (int)strlen(protected), pb, sizeof(pb)) < 0) return -1;
    if (b64url_encode((const uint8_t *)payload, (int)strlen(payload), pl, sizeof(pl)) < 0) return -1;
    char si[12288];
    int sl = snprintf(si, sizeof(si), "%s.%s", pb, pl);
    if (sl <= 0 || sl >= (int)sizeof(si)) return -1;
    uint8_t hash[32];
    SHA256State sha;
    sha256_init(&sha);
    sha256_process(&sha, (const uint8_t *)si, sl);
    sha256_done(&sha, hash);
    uint8_t sig[256];
    int sig_len = 0;
    if (tls_rsa_sign(&ac->account_key, hash, sig, &sig_len) != 0) return -1;
    char sb[384];
    if (b64url_encode(sig, sig_len, sb, sizeof(sb)) < 0) return -1;
    int l = snprintf(out, (size_t)outsz,
                     "{\"protected\":\"%s\",\"payload\":\"%s\",\"signature\":\"%s\"}", pb, pl, sb);
    return (l > 0 && l < outsz) ? 0 : -1;
}

/* One JWS POST. */
static int acme_request(AcmeClient *ac, const char *req_url, const char *jws_url,
                        const char *payload, char *resp, int respsz,
                         int *status, char *loc, int locsz) {
    char jws[16384];
    if (acme_jws(ac, jws_url, payload, jws, sizeof(jws)) != 0) return -1;
    url_set_data(ac->http, jws, strlen(jws));
    url_set_content_type(ac->http, "application/jose+json");
    char *body = url_run(ac->http, req_url, "POST", acme_log);
    *status = url_status(ac->http);
    if (!body)
        acme_log("POST %s: transport error %d\n", req_url, ac->http->last_error);
    const char *rn = url_response_header(ac->http, "replay-nonce");
    if (rn && *rn) {
        strncpy(ac->nonce, rn, sizeof(ac->nonce) - 1);
        ac->nonce[sizeof(ac->nonce) - 1] = '\0';
        ac->have_nonce = 1;
    }
    if (loc && locsz > 0) {
        const char *l = url_response_header(ac->http, "location");
        if (l) {
            strncpy(loc, l, (size_t)locsz - 1);
            loc[locsz - 1] = '\0';
        }
    }
    if (body) {
        strncpy(resp, body, (size_t)respsz - 1);
        resp[respsz - 1] = '\0';
        free(body);
    } else {
        resp[0] = '\0';
    }
    return 0;
}

/* JWS POST with retries on bad nonce / 5xx (analog of acme.Client.RetryBackoff).
 * HTTP 429 (rate limited) is fatal: retrying will not help, the app exits. */
static int acme_request_retry(AcmeClient *ac, const char *req_url, const char *jws_url,
                              const char *payload, char *resp, int respsz,
                              int *status, char *loc, int locsz) {
    for (int attempt = 0; attempt < 5; attempt++) {
        if (acme_request(ac, req_url, jws_url, payload, resp, respsz, status, loc, locsz) != 0)
            return -1;
        if (*status >= 200 && *status < 300) return 0;
        acme_log("POST %s -> HTTP %d: %.200s\n", req_url, *status, resp);
        if (*status == 400) {
            JsonValue *root = jparse(resp);
            const char *detail = jstr(root, "detail");
            int bad_nonce = detail && (strstr(detail, "bad nonce") || strstr(detail, "Bad nonce"));
            json_free_value(root);
            if (bad_nonce) {
                ac->have_nonce = 0;
                continue;
            }
            return -1;
        }
        if (*status == 429) {
            /* Rate limited (e.g. "too many certificates already issued for
             * this exact set of identifiers ... retry after <time>"):
             * retrying will not help, exit the application. */
            acme_log("HTTP 429 rateLimited, exiting.\n");
            g_stop = 1;
            return -1;
        }
        if (*status >= 500) {
            const char *ra = url_response_header(ac->http, "retry-after");
            int delay = ra ? atoi(ra) : (1 << attempt);
            if (delay < 1) delay = 1;
            if (delay > 30) delay = 30;
            acme_log("HTTP %d, retrying in %d s...\n", *status, delay);
            for (int i = 0; i < delay * 10 && !g_stop; i++) msleep(100);
            continue;
        }
        return -1;
    }
    return -1;
}

static int acme_post_as_get(AcmeClient *ac, const char *url, char *resp, int respsz, int *status) {
    return acme_request_retry(ac, url, url, "", resp, respsz, status, NULL, 0);
}

static int acme_discover(AcmeClient *ac) {
    acme_log("discovering directory %s\n", ac->dir_url);
    char *body = url_run(ac->http, ac->dir_url, "GET", acme_log);
    if (!body) return -1;
    int st = url_status(ac->http);
    if (st != 200) { free(body); return -1; }
    JsonValue *root = jparse(body);
    free(body);
    if (!root) return -1;
    const char *s;
    if ((s = jstr(root, "newAccount"))) strncpy(ac->new_account, s, sizeof(ac->new_account) - 1);
    if ((s = jstr(root, "newNonce")))   strncpy(ac->new_nonce, s, sizeof(ac->new_nonce) - 1);
    if ((s = jstr(root, "newOrder")))   strncpy(ac->new_order, s, sizeof(ac->new_order) - 1);
    if ((s = jstr(root, "revokeCert"))) strncpy(ac->revoke_cert, s, sizeof(ac->revoke_cert) - 1);
    if ((s = jstr(root, "termsOfService"))) strncpy(ac->terms, s, sizeof(ac->terms) - 1);
    json_free_value(root);
    if (!ac->new_account[0] || !ac->new_order[0]) return -1;
    if (!ac->new_nonce[0])
        strncpy(ac->new_nonce, ac->dir_url, sizeof(ac->new_nonce) - 1);
    return 0;
}

/* Load the account key from the cache or generate a new RSA 2048 key. */
static int acme_account_key(AcmeClient *ac) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/acme_account+key.pem", ac->cache_dir);
    uint8_t der[4096];
    int der_len = 0;
    if (tls_pem_to_der(path, der, &der_len, sizeof(der)) == 0 &&
        tls_rsa_parse_private_der(&ac->account_key, der, der_len) == 0) {
        ac->have_account_key = 1;
        acme_log("loaded account key from %s\n", path);
        return 0;
    }
    acme_log("generating new RSA 2048 account key...\n");
    if (tls_rsa_generate_key(&ac->account_key) != 0) return -1;
    ac->have_account_key = 1;
    uint8_t pkcs1[2048];
    int pkcs1_len = build_private_pkcs1(&ac->account_key, pkcs1);
    if (pkcs1_len > 0) {
        char *pem = pem_build("RSA PRIVATE KEY", pkcs1, pkcs1_len);
        if (pem) {
            if (write_file(path, pem, strlen(pem)) == 0)
                acme_log("saved account key to %s\n", path);
            free(pem);
        }
    }
    return 0;
}

/* Register the account (analog of acme.Client.Register with AcceptTOS). */
static int acme_register(AcmeClient *ac) {
    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"contact\":[\"mailto:%s\"],\"termsOfServiceAgreed\":true}", ac->email);
    char resp[8192], loc[512];
    int status = 0;
    if (acme_request_retry(ac, ac->new_account, ac->new_account, payload,
                           resp, sizeof(resp), &status, loc, sizeof(loc)) != 0) {
        acme_log("registration request failed\n");
        return -1;
    }
    if (status == 200 || status == 201) {
        acme_log("account registered: %s\n", loc);
    } else if (status == 409) {
        acme_log("account already exists: %s\n", loc);
    } else {
        JsonValue *root = jparse(resp);
        const char *detail = jstr(root, "detail");
        acme_log("registration failed (HTTP %d): %s\n", status, detail ? detail : resp);
        json_free_value(root);
        return -1;
    }
    if (loc[0]) {
        strncpy(ac->kid, loc, sizeof(ac->kid) - 1);
        ac->kid[sizeof(ac->kid) - 1] = '\0';
    }
    return 0;
}

/* Create a new order (analog of acme.Client.AuthorizeOrder). */
static int acme_new_order(AcmeClient *ac, const char *const *domains, int ndomains,
                          char *order_url, int order_url_sz,
                          char *finalize_url, int fin_sz,
                          char authz[][512], int max_authz) {
    if (!domains || ndomains < 1 || ndomains > MAX_DOMAINS) return -1;
    char payload[3072];
    int p = snprintf(payload, sizeof(payload), "{\"identifiers\":[");
    if (p <= 0) return -1;
    for (int i = 0; i < ndomains; i++) {
        if (!domains[i] || !*domains[i]) return -1;
        int n = snprintf(payload + p, sizeof(payload) - (size_t)p,
                         "%s{\"type\":\"dns\",\"value\":\"%s\"}",
                         i ? "," : "", domains[i]);
        if (n <= 0 || p + n >= (int)sizeof(payload) - 2) return -1;
        p += n;
    }
    if (p + 2 >= (int)sizeof(payload)) return -1;
    payload[p++] = ']';
    payload[p++] = '}';
    payload[p] = '\0';
    char resp[8192], loc[512];
    int status = 0;
    if (acme_request_retry(ac, ac->new_order, ac->new_order, payload,
                           resp, sizeof(resp), &status, loc, sizeof(loc)) != 0)
        return -1;
    if (status != 200 && status != 201) {
        JsonValue *root = jparse(resp);
        const char *detail = jstr(root, "detail");
        acme_log("newOrder failed (HTTP %d): %s\n", status, detail ? detail : resp);
        json_free_value(root);
        return -1;
    }
    if (loc[0]) {
        strncpy(order_url, loc, (size_t)order_url_sz - 1);
        order_url[order_url_sz - 1] = '\0';
    }
    JsonValue *root = jparse(resp);
    if (!root) return -1;
    const char *fin = jstr(root, "finalize");
    if (fin) strncpy(finalize_url, fin, (size_t)fin_sz - 1);
    JsonValue *authz_arr = json_get(root, "authorizations");
    int n = 0;
    if (json_is_array(authz_arr)) {
        int cnt = json_array_len(authz_arr);
        if (cnt > max_authz) cnt = max_authz;
        for (int i = 0; i < cnt; i++) {
            const char *u = json_string(json_array_item(authz_arr, i));
            if (!u) continue;
            strncpy(authz[n], u, 511);
            authz[n][511] = '\0';
            n++;
        }
    }
    json_free_value(root);
    if (n <= 0) {
        acme_log("no authorizations in order\n");
        return -1;
    }
    return n;
}

/* Extract a human-readable error from an invalid authorization: the top-level
 * "detail" if present, otherwise the error object of the failed challenge
 * (type + detail), which is where the ACME server puts the real reason. */
static int authz_error_detail(JsonValue *root, char *out, int outsz) {
    const char *d = jstr(root, "detail");
    if (d && *d) {
        snprintf(out, (size_t)outsz, "%s", d);
        return 1;
    }
    JsonValue *chals = json_get(root, "challenges");
    if (json_is_array(chals)) {
        int cnt = json_array_len(chals);
        for (int i = 0; i < cnt; i++) {
            JsonValue *c = (JsonValue *)json_array_item(chals, i);
            if (!json_is_object(c)) continue;
            const char *cs = jstr(c, "status");
            if (!cs || strcmp(cs, "invalid") != 0) continue;
            JsonValue *e = json_get(c, "error");
            const char *ct = e ? jstr(e, "type") : NULL;
            const char *cd = e ? jstr(e, "detail") : NULL;
            if (cd && *cd) {
                if (ct && *ct) snprintf(out, (size_t)outsz, "%s: %s", ct, cd);
                else snprintf(out, (size_t)outsz, "%s", cd);
                return 1;
            }
        }
    }
    return 0;
}

static int acme_wait_authz(AcmeClient *ac, const char *authz_url) {
    for (int i = 0; i < 60 && !g_stop; i++) {
        char resp[8192];
        int status = 0;
        if (acme_post_as_get(ac, authz_url, resp, sizeof(resp), &status) != 0) return -1;
        if (status != 200) return -1;
        JsonValue *root = jparse(resp);
        if (!root) return -1;
        const char *st = jstr(root, "status");
        if (!st) { json_free_value(root); return -1; }
        if (strcmp(st, "valid") == 0) { json_free_value(root); return 0; }
        if (strcmp(st, "invalid") == 0) {
            /* The validator may still retry (e.g. a second validation pass);
             * keep polling until it turns valid or the loop times out. */
            char det[1024];
            acme_log("authorization invalid: %s (rechecking...)\n",
                     authz_error_detail(root, det, sizeof(det)) ? det : "unknown");
        }
        json_free_value(root);
        msleep(5000);
    }
    acme_log("authorization timeout\n");
    return -1;
}

/* --- http-01 challenge table (served on port 80) --- */

#define CHAL_MAX 8
typedef struct {
    char token[256];
    char keyauth[512];
    int  active;
} ChalSlot;

static ChalSlot g_chal[CHAL_MAX];
static mtx_t g_chal_lock;

static void chal_set(const char *token, const char *keyauth) {
    mtx_lock(&g_chal_lock);
    for (int i = 0; i < CHAL_MAX; i++) {
        if (!g_chal[i].active) {
            strncpy(g_chal[i].token, token, sizeof(g_chal[i].token) - 1);
            strncpy(g_chal[i].keyauth, keyauth, sizeof(g_chal[i].keyauth) - 1);
            g_chal[i].active = 1;
            break;
        }
    }
    mtx_unlock(&g_chal_lock);
}

static void chal_clear(const char *token) {
    mtx_lock(&g_chal_lock);
    for (int i = 0; i < CHAL_MAX; i++)
        if (g_chal[i].active && strcmp(g_chal[i].token, token) == 0)
            g_chal[i].active = 0;
    mtx_unlock(&g_chal_lock);
}

static int chal_lookup(const char *token, char *keyauth, int keyauth_sz) {
    int found = 0;
    mtx_lock(&g_chal_lock);
    for (int i = 0; i < CHAL_MAX; i++) {
        if (g_chal[i].active && strcmp(g_chal[i].token, token) == 0) {
            strncpy(keyauth, g_chal[i].keyauth, (size_t)keyauth_sz - 1);
            keyauth[keyauth_sz - 1] = '\0';
            found = 1;
            break;
        }
    }
    mtx_unlock(&g_chal_lock);
    return found;
}

/* Satisfy one http-01 challenge (analog of Manager.fulfill + Accept + WaitAuthorization). */
static int acme_do_http01(AcmeClient *ac, JsonValue *chal, const char *domain,
                          const char *authz_url) {
    const char *token = jstr(chal, "token");
    const char *chal_url = jstr(chal, "url");
    if (!token || !chal_url) { acme_log("incomplete http-01 challenge\n"); return -1; }
    char token_b[256], chal_url_b[512];
    strncpy(token_b, token, sizeof(token_b) - 1);
    token_b[sizeof(token_b) - 1] = '\0';
    strncpy(chal_url_b, chal_url, sizeof(chal_url_b) - 1);
    chal_url_b[sizeof(chal_url_b) - 1] = '\0';

    char thumb[64];
    if (acme_thumbprint(ac, thumb, sizeof(thumb)) != 0) return -1;
    char keyauth[512];
    snprintf(keyauth, sizeof(keyauth), "%s.%s", token_b, thumb);
    acme_log("http-01: serving http://%s/.well-known/acme-challenge/%s\n", domain, token_b);
    chal_set(token_b, keyauth);
    char resp[8192];
    int status = 0;
    int rc = -1;
    if (acme_request_retry(ac, chal_url_b, chal_url_b, "{}",
                           resp, sizeof(resp), &status, NULL, 0) == 0 &&
        (status == 200 || status == 202)) {
        acme_log("challenge accepted, waiting for validation...\n");
        rc = acme_wait_authz(ac, authz_url);
    } else {
        JsonValue *r2 = jparse(resp);
        const char *detail = jstr(r2, "detail");
        acme_log("challenge accept failed (HTTP %d): %s\n", status, detail ? detail : resp);
        json_free_value(r2);
    }
    chal_clear(token_b);
    return rc;
}

/* --- dns-01 challenge support (required for wildcard domains) ---
 *
 * RFC 8555: a wildcard identifier (e.g. *.example.com) can only be validated
 * with the dns-01 challenge - Let's Encrypt does not offer http-01 for it.
 * The validator reads the TXT record _acme-challenge.<domain> (the "*" prefix
 * dropped). The operator publishes that record in the zone; this program
 * prints it and polls public resolvers (UDP/53 with a TCP/53 fallback)
 * until the record is visible. */

/* Walk a DNS response (RFC 1035) and invoke fn for every TXT RDATA
 * char-string; if fn returns non-zero the walk stops and 1 is returned,
 * otherwise 0 (including ID mismatch / no TXT answer). */
static int dns_resp_walk_txt(const uint8_t *resp, int n, uint16_t id,
                             int (*fn)(const char *txt, void *ctx), void *ctx) {
    if (n < 12 || resp[0] != (uint8_t)(id >> 8) || resp[1] != (uint8_t)(id & 0xFF)) return 0;
    uint16_t ancount = (uint16_t)((resp[6] << 8) | resp[7]);
    int rp = 12, ptr = 0;
    while (rp < n && resp[rp] != 0x00) {          /* skip question name */
        if ((resp[rp] & 0xC0) == 0xC0) { rp += 2; ptr = 1; break; }
        rp += 1 + resp[rp];
    }
    if (!ptr && rp < n && resp[rp] == 0x00) rp++;
    rp += 4;                                      /* QTYPE + QCLASS */
    for (int a = 0; a < ancount && rp + 12 <= n; a++) {
        ptr = 0;
        if ((resp[rp] & 0xC0) == 0xC0) {          /* name compression ptr */
            rp += 2;
            ptr = 1;
        } else {
            while (rp < n && resp[rp] != 0x00) {
                if ((resp[rp] & 0xC0) == 0xC0) { rp += 2; ptr = 1; break; }
                rp += 1 + resp[rp];
            }
            if (!ptr && rp < n) rp++;
        }
        if (rp + 10 > n) break;
        uint16_t atype = (uint16_t)((resp[rp] << 8) | resp[rp + 1]);
        uint16_t rdlen = (uint16_t)((resp[rp + 8] << 8) | resp[rp + 9]);
        rp += 10;
        if (rp + rdlen > n) break;
        if (atype == 0x0010) {                    /* TXT RDATA: char-strings */
            int sp = rp, se = rp + rdlen;
            while (sp < se) {
                int sl = resp[sp++];
                if (sp + sl > n) sl = n - sp;
                char txt[512];
                if (sl >= (int)sizeof(txt)) sl = (int)sizeof(txt) - 1;
                memcpy(txt, resp + sp, (size_t)sl);
                txt[sl] = '\0';
                if (fn(txt, ctx)) return 1;
                sp += sl;
            }
        }
        rp += rdlen;
    }
    return 0;
}

static int dns_txt_match_fn(const char *txt, void *ctx) {
    return strcmp(txt, (const char *)ctx) == 0;
}

typedef struct { char *out; int outsz; } TxtCopyCtx;
static int dns_txt_copy_fn(const char *txt, void *ctx) {
    TxtCopyCtx *tc = (TxtCopyCtx *)ctx;
    snprintf(tc->out, (size_t)tc->outsz, "%s", txt);
    return 1;
}

/* Build a DNS TXT query (RFC 1035) for "name"; returns its length or -1. */
static int dns_build_query(const char *name, uint16_t id, uint8_t *q, int qmax) {
    int p = 0;
    q[p++] = (uint8_t)(id >> 8); q[p++] = (uint8_t)(id & 0xFF);
    q[p++] = 0x01; q[p++] = 0x00;               /* RD set */
    q[p++] = 0x00; q[p++] = 0x01;               /* QDCOUNT = 1 */
    q[p++] = 0x00; q[p++] = 0x00;               /* ANCOUNT = 0 */
    q[p++] = 0x00; q[p++] = 0x00;               /* NSCOUNT = 0 */
    q[p++] = 0x00; q[p++] = 0x00;               /* ARCOUNT = 0 */
    const char *dot = name;
    while (*dot) {
        const char *next = strchr(dot, '.');
        int ll = next ? (int)(next - dot) : (int)strlen(dot);
        if (ll <= 0 || ll > 63 || p + 1 + ll + 5 > qmax) return -1;
        q[p++] = (uint8_t)ll;
        memcpy(q + p, dot, (size_t)ll);
        p += ll;
        dot = next ? next + 1 : dot + ll;
    }
    q[p++] = 0x00;
    q[p++] = 0x00; q[p++] = 0x10;               /* QTYPE = TXT */
    q[p++] = 0x00; q[p++] = 0x01;               /* QCLASS = IN */
    return p;
}

/* connect() with a timeout (portable: non-blocking connect + select). */
static int tcp_connect_timeout(SOCKET s, const struct sockaddr_in *sa, int timeout_ms) {
#ifdef _WIN32
    u_long nb = 1;
    if (ioctlsocket(s, FIONBIO, &nb) != 0) return -1;
#else
    int fl = fcntl(s, F_GETFL, 0);
    if (fl < 0) return -1;
    if (fcntl(s, F_SETFL, fl | O_NONBLOCK) != 0) return -1;
#endif
    if (connect(s, (const struct sockaddr *)sa, sizeof(*sa)) != 0) {
        int err;
#ifdef _WIN32
        err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) return -1;
#else
        err = errno;
        if (err != EINPROGRESS) return -1;
#endif
        fd_set wf;
        FD_ZERO(&wf);
        FD_SET(s, &wf);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        if (select((int)s + 1, NULL, &wf, NULL, &tv) <= 0) return -1;
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&soerr, &sl) != 0 || soerr != 0)
            return -1;
    }
#ifdef _WIN32
    u_long nb0 = 0;
    ioctlsocket(s, FIONBIO, &nb0);
#else
    fcntl(s, F_SETFL, fl);
#endif
    return 0;
}

/* recv exactly n bytes, waiting for data with select() (SO_RCVTIMEO is
 * unreliable on Windows after a non-blocking connect). Returns bytes read
 * or -1 on timeout / error. */
static int recv_all_timeout(SOCKET s, uint8_t *buf, int n, int timeout_ms) {
    int got = 0;
    while (got < n) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(s, &rf);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        if (select((int)s + 1, &rf, NULL, NULL, &tv) <= 0) break;
        int r = recv(s, (char *)buf + got, n - got, 0);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

/* Send a DNS query to one resolver (UDP first, then TCP per RFC 1035 4.2.2
 * because outbound UDP/53 is frequently blocked). Returns the response
 * length or -1 on transport error. */
static int dns_roundtrip(const uint8_t *q, int qlen, const unsigned char ip[4],
                         uint8_t *resp, int resp_sz) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(53);
    memcpy(&sa.sin_addr.s_addr, ip, 4);

    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s != INVALID_SOCKET) {
        struct timeval tv = { 3, 0 };
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof(tv));
        int n = -1;
        if (sendto(s, (const char *)q, qlen, 0, (struct sockaddr *)&sa, sizeof(sa)) > 0)
            n = recv(s, (char *)resp, (size_t)resp_sz, 0);
        closesocket(s);
        if (n > 0) return n;
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return -1;
    int rc = -1;
    if (tcp_connect_timeout(s, &sa, 5000) == 0) {
        uint8_t th[2] = { (uint8_t)(qlen >> 8), (uint8_t)(qlen & 0xFF) };
        if (send(s, (const char *)th, 2, 0) == 2 && send(s, (const char *)q, qlen, 0) == qlen) {
            if (recv_all_timeout(s, th, 2, 5000) == 2) {
                int tlen = (th[0] << 8) | th[1];
                if (tlen > 0 && tlen <= resp_sz &&
                    recv_all_timeout(s, resp, tlen, 5000) == tlen)
                    rc = tlen;
            }
        }
    }
    closesocket(s);
    return rc;
}

/* One TXT query against one resolver. Returns 1 if a TXT RR equals
 * "expected", 0 if the resolver answered but no TXT matched, -1 on
 * transport error. */
static int dns_query_resolver(const char *name, const char *expected,
                              const unsigned char ip[4]) {
    uint8_t q[512], resp[4096];
    uint16_t id = (uint16_t)(rand() & 0x7FFF) + 1;
    int p = dns_build_query(name, id, q, (int)sizeof(q));
    if (p <= 0) return -1;
    int n = dns_roundtrip(q, p, ip, resp, (int)sizeof(resp));
    if (n <= 0) return -1;
    return dns_resp_walk_txt(resp, n, id, dns_txt_match_fn, (void *)expected) ? 1 : 0;
}

/* TXT lookup with a list of public resolvers. Returns 1 if any TXT RR of
 * "name" equals "expected", 0 if the record was queried but did not match,
 * -1 if all resolvers were unreachable. */
static int dns_txt_lookup(const char *name, const char *expected) {
    static const unsigned char ips[3][4] = {
        { 8, 8, 8, 8 }, { 1, 1, 1, 1 }, { 9, 9, 9, 9 },
    };
    int answered = 0;
    for (int r = 0; r < 3; r++) {
        int rc = dns_query_resolver(name, expected, ips[r]);
        if (rc == 1) return 1;
        if (rc == 0) answered = 1;
    }
    return answered ? 0 : -1;
}

/* Fetch the first TXT value currently published at "name" (any resolver that
 * has an answer). Returns 1 if found (out filled), 0 if resolvers answered
 * but the record has no TXT, -1 if all resolvers were unreachable. */
static int dns_txt_first(const char *name, char *out, int outsz) {
    static const unsigned char ips[3][4] = {
        { 8, 8, 8, 8 }, { 1, 1, 1, 1 }, { 9, 9, 9, 9 },
    };
    uint8_t q[512], resp[4096];
    TxtCopyCtx tc = { out, outsz };
    uint16_t id = (uint16_t)(rand() & 0x7FFF) + 1;
    int p = dns_build_query(name, id, q, (int)sizeof(q));
    if (p <= 0) return -1;
    int answered = 0;
    for (int r = 0; r < 3; r++) {
        int n = dns_roundtrip(q, p, ips[r], resp, (int)sizeof(resp));
        if (n > 0) {
            answered = 1;
            if (dns_resp_walk_txt(resp, n, id, dns_txt_copy_fn, &tc)) return 1;
        }
    }
    return answered ? 0 : -1;
}

/* --- DNS provider API (automated dns-01 TXT record management) ---
 *
 * With --dns <provider> --apikey <key> the TXT record is published and
 * removed via the provider API instead of asking the operator to edit the
 * zone by hand. Currently the only supported provider is "dynadot"
 * (API3 set_dns2 command, GET with a query string). */

/* Percent-encode a string for use in a URL query. */
static void dns_url_encode(const char *s, char *out, int outsz) {
    static const char hexd[] = "0123456789ABCDEF";
    int o = 0;
    for (const char *p = s; *p && o + 3 < outsz; p++) {
        unsigned char c = (unsigned char)*p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
            out[o++] = (char)c;
        } else {
            out[o++] = '%';
            out[o++] = hexd[c >> 4];
            out[o++] = hexd[c & 0x0F];
        }
    }
    out[o] = '\0';
}

/* One set_dns2 call: publish (record != NULL) or remove (record == NULL)
 * the TXT record of subdomain "_acme-challenge" of "domain" without
 * touching the rest of the zone (add_dns_to_current_setting=1).
 * Returns 0 on ResponseCode "0" / Status "success", -1 otherwise. */
static int dynadot_set_acme_txt(const AcmeClient *ac, const char *domain, const char *record) {
    char key_e[768], dom_e[768], rec_e[1536], url[4096];
    dns_url_encode(ac->api_key, key_e, sizeof(key_e));
    dns_url_encode(domain, dom_e, sizeof(dom_e));
    int ul;
    if (record) {
        dns_url_encode(record, rec_e, sizeof(rec_e));
        ul = snprintf(url, sizeof(url),
                 "https://api.dynadot.com/api3.json"
                 "?key=%s&command=set_dns2&domain=%s"
                 "&subdomain0=_acme-challenge&sub_record_type0=txt"
                 "&sub_record0=%s&add_dns_to_current_setting=1&ttl=300",
                 key_e, dom_e, rec_e);
    } else {
        ul = snprintf(url, sizeof(url),
                 "https://api.dynadot.com/api3.json"
                 "?key=%s&command=set_dns2&domain=%s"
                 "&subdomain0=_acme-challenge&sub_record_type0=none"
                 "&sub_record0=&add_dns_to_current_setting=1",
                 key_e, dom_e);
    }
    if (ul < 0 || ul >= (int)sizeof(url)) return -1;
    /* Plain GET: make sure no stale POST body/content-type is reused. */
    url_set_data(ac->http, NULL, 0);
    url_set_content_type(ac->http, NULL);
    char *body = url_run(ac->http, url, "GET", NULL);
    int st = url_status(ac->http);
    int ok = 0;
    if (body && st == 200) {
        JsonValue *root = jparse(body);
        JsonValue *r = root ? json_get(root, "SetDnsResponse") : NULL;
        JsonValue *codev = r ? json_get(r, "ResponseCode") : NULL;
        const char *status = r ? jstr(r, "Status") : NULL;
        /* Dynadot reports ResponseCode as a JSON number (0) on success and as
         * a string ("-1") on some errors; accept either representation. */
        int code_zero = 0;
        if (codev) {
            if (json_is_string(codev)) code_zero = (strcmp(json_string(codev), "0") == 0);
            else if (json_is_number(codev)) code_zero = (json_number(codev) == 0.0);
        }
        ok = (code_zero && status && strcmp(status, "success") == 0);
        /* Removing a record that does not exist is a benign no-op: Dynadot
         * answers "no record for subdomain0"; do not treat that as a failure. */
        if (!ok && !record) {
            const char *err = r ? jstr(r, "Error") : NULL;
            if (err && strstr(err, "no record")) ok = 1;
        }
        json_free_value(root);
    }
    if (!ok) {
        acme_log("dynadot: %s failed (HTTP %d, transport error %d): %.300s\n",
                 record ? "set TXT" : "remove TXT", st, ac->http->last_error,
                 body ? body : "no response");
    }
    free(body);
    return ok ? 0 : -1;
}

/* Satisfy one dns-01 challenge: publish the required TXT record (via the
 * provider API when --dns/--apikey are given, otherwise printed for the
 * operator), wait until it is publicly resolvable, accept the challenge,
 * then remove the record again. */
static int acme_do_dns01(AcmeClient *ac, JsonValue *chal, const char *domain,
                         const char *authz_url) {
    const char *token = jstr(chal, "token");
    const char *chal_url = jstr(chal, "url");
    if (!token || !chal_url) { acme_log("incomplete dns-01 challenge\n"); return -1; }
    char token_b[256], chal_url_b[512];
    strncpy(token_b, token, sizeof(token_b) - 1);
    token_b[sizeof(token_b) - 1] = '\0';
    strncpy(chal_url_b, chal_url, sizeof(chal_url_b) - 1);
    chal_url_b[sizeof(chal_url_b) - 1] = '\0';

    char thumb[64];
    if (acme_thumbprint(ac, thumb, sizeof(thumb)) != 0) return -1;
    char keyauth[512];
    snprintf(keyauth, sizeof(keyauth), "%s.%s", token_b, thumb);
    uint8_t hash[32];
    SHA256State sha;
    sha256_init(&sha);
    sha256_process(&sha, (const uint8_t *)keyauth, (int)strlen(keyauth));
    sha256_done(&sha, hash);
    char digest[64];
    if (b64url_encode(hash, 32, digest, sizeof(digest)) < 0) return -1;

    const char *base = domain;
    if (strncmp(base, "*.", 2) == 0) base += 2;
    char recname[300];
    snprintf(recname, sizeof(recname), "_acme-challenge.%s", base);

    int record_added = 0, ok = 0, rc = -1;
    if (ac->have_dns_api) {
        /* Automated mode: first clear any stale record left by a previous
         * run (leftovers break validation), then publish the new one. */
        acme_log("dynadot: removing stale TXT record %s (if any)...\n", recname);
        if (dynadot_set_acme_txt(ac, base, NULL) != 0)
            acme_log("dynadot: warning: stale record may not have been removed\n");
        acme_log("dynadot: adding TXT record %s via API...\n", recname);
        if (dynadot_set_acme_txt(ac, base, digest) != 0) {
            acme_log("dns-01: aborting: failed to publish TXT record via dynadot API\n");
            return -1;
        }
        record_added = 1;
        acme_log("dns-01: TXT record published, waiting for it to become visible (polling every 10 s, up to 15 min)...\n");
    } else {
        /* Leftover records from previous (failed) runs break validation: the
         * validator rejects the challenge if ANY of the TXT values differs. */
        char cur[512] = { 0 };
        if (dns_txt_first(recname, cur, sizeof(cur)) == 1 && strcmp(cur, digest) != 0) {
            acme_log("dns-01: WARNING: %s already has TXT value \"%s\"\n", recname, cur);
            acme_log("dns-01: remove ALL old TXT records for %s first, then add the new one\n", recname);
        }
        acme_log("dns-01: add this TXT record to the zone of %s:\n", base);
        printf("[acme]   name:  %s\n", recname);
        printf("[acme]   value: %s\n", digest);
        acme_log("dns-01: waiting for the TXT record (polling every 10 s, up to 15 min)...\n");
    }
    for (int i = 0; i < 90 && !g_stop; i++) {
        if (dns_txt_lookup(recname, digest) == 1) {
            /* confirm once more (10 s later) so the record is stable on the
             * authoritative nameservers before the validator runs */
            msleep(10000);
            if (!g_stop && dns_txt_lookup(recname, digest) == 1) { ok = 1; break; }
        }
        msleep(10000);
    }
    if (!ok) {
        acme_log("dns-01: TXT record %s not visible, aborting\n", recname);
    } else {
        acme_log("dns-01: TXT record confirmed, waiting %d s for propagation to other resolvers...\n",
                 DNS_PROPAGATION_WAIT_SEC);
        for (int w = 0; w < DNS_PROPAGATION_WAIT_SEC * 10 && !g_stop; w++) msleep(100);
        acme_log("dns-01: accepting challenge...\n");
        char resp[8192];
        int status = 0;
        if (acme_request_retry(ac, chal_url_b, chal_url_b, "{}",
                               resp, sizeof(resp), &status, NULL, 0) == 0 &&
            (status == 200 || status == 202)) {
            acme_log("challenge accepted, waiting for validation...\n");
            rc = acme_wait_authz(ac, authz_url);
        } else {
            JsonValue *r2 = jparse(resp);
            const char *detail = jstr(r2, "detail");
            acme_log("challenge accept failed (HTTP %d): %s\n", status, detail ? detail : resp);
            json_free_value(r2);
        }
    }
    if (record_added) {
        /* Always clean up the record we published (success or failure),
         * otherwise it becomes a stale record for the next run. */
        acme_log("dynadot: removing TXT record %s...\n", recname);
        if (dynadot_set_acme_txt(ac, base, NULL) == 0)
            acme_log("dynadot: TXT record removed\n");
        else
            acme_log("dynadot: WARNING: failed to remove the TXT record, remove it manually at the DNS provider\n");
    } else if (rc == 0) {
        acme_log("dns-01: challenge validated, you can remove the TXT record %s now\n", recname);
    }
    return rc;
}

/* Satisfy one authorization: http-01 when offered, otherwise dns-01
 * (wildcard identifiers only get dns-01). Uses the identifier from the
 * authorization response, not the request order. */
static int acme_satisfy_authz(AcmeClient *ac, const char *authz_url, const char *fallback_domain) {
    char resp[8192];
    int status = 0;
    if (acme_post_as_get(ac, authz_url, resp, sizeof(resp), &status) != 0) return -1;
    if (status != 200) return -1;
    JsonValue *root = jparse(resp);
    if (!root) return -1;
    const char *st = jstr(root, "status");
    if (!st) { json_free_value(root); return -1; }
    const char *domain = jstr(json_get(root, "identifier"), "value");
    if (!domain || !*domain) domain = fallback_domain;
    char domain_b[256];
    strncpy(domain_b, domain, sizeof(domain_b) - 1);
    domain_b[sizeof(domain_b) - 1] = '\0';
    if (strcmp(st, "valid") == 0) {
        acme_log("authorization for %s already valid\n", domain_b);
        json_free_value(root);
        return 0;
    }
    if (strcmp(st, "invalid") == 0) {
        char det[1024];
        acme_log("authorization invalid: %s\n",
                 authz_error_detail(root, det, sizeof(det)) ? det : "unknown");
        json_free_value(root);
        return -1;
    }
    JsonValue *chals = json_get(root, "challenges");
    JsonValue *http_c = NULL, *dns_c = NULL;
    if (json_is_array(chals)) {
        int cnt = json_array_len(chals);
        for (int i = 0; i < cnt; i++) {
            JsonValue *c = (JsonValue *)json_array_item(chals, i);
            if (!json_is_object(c)) continue;
            const char *t = jstr(c, "type");
            if (!t) continue;
            if (strcmp(t, "http-01") == 0 && !http_c) http_c = c;
            else if (strcmp(t, "dns-01") == 0 && !dns_c) dns_c = c;
        }
    }
    if (!http_c && !dns_c) {
        acme_log("no http-01 or dns-01 challenge found for %s\n", domain_b);
        json_free_value(root);
        return -1;
    }
    int rc = http_c ? acme_do_http01(ac, http_c, domain_b, authz_url)
                    : acme_do_dns01(ac, dns_c, domain_b, authz_url);
    json_free_value(root);
    return rc;
}

static int acme_wait_order(AcmeClient *ac, const char *order_url) {
    for (int i = 0; i < 60 && !g_stop; i++) {
        char resp[8192];
        int status = 0;
        if (acme_post_as_get(ac, order_url, resp, sizeof(resp), &status) != 0) return -1;
        if (status != 200) return -1;
        JsonValue *root = jparse(resp);
        if (!root) return -1;
        const char *st = jstr(root, "status");
        if (!st) { json_free_value(root); return -1; }
        if (strcmp(st, "ready") == 0 || strcmp(st, "valid") == 0) {
            json_free_value(root);
            return 0;
        }
        if (strcmp(st, "invalid") == 0) {
            const char *detail = jstr(root, "detail");
            acme_log("order invalid: %s\n", detail ? detail : "unknown");
            json_free_value(root);
            return -1;
        }
        json_free_value(root);
        msleep(2000);
    }
    acme_log("order timeout\n");
    return -1;
}

static int acme_finalize(AcmeClient *ac, const char *finalize_url,
                         const RSAKey *key, const char *const *domains, int ndomains,
                         char *order_url, int order_url_sz) {
    uint8_t csr[4096];
    int csr_len = 0;
    if (build_csr(key, domains, ndomains, csr, (int)sizeof(csr), &csr_len) != 0) {
        acme_log("CSR build failed\n");
        return -1;
    }
    char cb[5632];
    if (b64url_encode(csr, csr_len, cb, sizeof(cb)) < 0) return -1;
    char payload[6144];
    int pl = snprintf(payload, sizeof(payload), "{\"csr\":\"%s\"}", cb);
    if (pl <= 0 || pl >= (int)sizeof(payload)) return -1;
    char resp[8192], loc[512];
    int status = 0;
    if (acme_request_retry(ac, finalize_url, finalize_url, payload,
                           resp, sizeof(resp), &status, loc, sizeof(loc)) != 0)
        return -1;
    if (status != 200 && status != 202) {
        JsonValue *root = jparse(resp);
        const char *detail = jstr(root, "detail");
        acme_log("finalize failed (HTTP %d): %s\n", status, detail ? detail : resp);
        json_free_value(root);
        return -1;
    }
    if (loc[0]) {
        strncpy(order_url, loc, (size_t)order_url_sz - 1);
        order_url[order_url_sz - 1] = '\0';
    }
    return 0;
}

static int acme_fetch_cert(AcmeClient *ac, const char *order_url, char *cert_pem, int cert_sz) {
    for (int i = 0; i < 60 && !g_stop; i++) {
        char resp[8192];
        int status = 0;
        if (acme_post_as_get(ac, order_url, resp, sizeof(resp), &status) != 0) return -1;
        if (status != 200) return -1;
        JsonValue *root = jparse(resp);
        if (!root) return -1;
        const char *st = jstr(root, "status");
        if (!st) { json_free_value(root); return -1; }
        if (strcmp(st, "valid") == 0) {
            const char *cert_url_s = jstr(root, "certificate");
            if (!cert_url_s) {
                acme_log("no certificate URL in order\n");
                json_free_value(root);
                return -1;
            }
            char cert_url[512];
            strncpy(cert_url, cert_url_s, sizeof(cert_url) - 1);
            json_free_value(root);
            char cresp[16384];
            if (acme_post_as_get(ac, cert_url, cresp, sizeof(cresp), &status) != 0) return -1;
            if (status != 200) return -1;
            if (strstr(cresp, "-----BEGIN CERTIFICATE-----") == NULL) {
                acme_log("certificate response is not PEM\n");
                return -1;
            }
            strncpy(cert_pem, cresp, (size_t)cert_sz - 1);
            cert_pem[cert_sz - 1] = '\0';
            return 0;
        }
        if (strcmp(st, "invalid") == 0) {
            const char *detail = jstr(root, "detail");
            acme_log("order invalid: %s\n", detail ? detail : "unknown");
            json_free_value(root);
            return -1;
        }
        json_free_value(root);
        msleep(2000);
    }
    acme_log("certificate fetch timeout\n");
    return -1;
}

/* Full issuance flow (analog of Manager.createCert + authorizedCert + verifyRFC).
 * domains[0] is the primary (CN + cache file name), all entries land in SAN. */
static int acme_create_cert(AcmeClient *ac, const char *const *domains, int ndomains,
                            RSAKey *cert_key, char *cert_pem, int cert_sz) {
    if (!domains || ndomains < 1 || ndomains > MAX_DOMAINS) return -1;
    if (acme_discover(ac) != 0) {
        acme_log("directory discovery failed\n");
        return -1;
    }
    if (acme_account_key(ac) != 0) return -1;
    if (acme_register(ac) != 0) return -1;

    char order_url[512], finalize_url[512];
    char authz[ACME_MAX_AUTHZ][512];
    int nauthz = acme_new_order(ac, domains, ndomains, order_url, sizeof(order_url),
                                finalize_url, sizeof(finalize_url), authz, ACME_MAX_AUTHZ);
    if (nauthz <= 0) return -1;
    if (nauthz != ndomains)
        acme_log("warning: order has %d authorizations for %d domains\n", nauthz, ndomains);

    for (int i = 0; i < nauthz && !g_stop; i++) {
        if (acme_satisfy_authz(ac, authz[i], domains[i < ndomains ? i : 0]) != 0) return -1;
    }

    if (acme_wait_order(ac, order_url) != 0) return -1;

    acme_log("generating RSA 2048 certificate key...\n");
    if (tls_rsa_generate_key(cert_key) != 0) return -1;

    if (acme_finalize(ac, finalize_url, cert_key, domains, ndomains, order_url, sizeof(order_url)) != 0)
        return -1;
    if (acme_fetch_cert(ac, order_url, cert_pem, cert_sz) != 0) return -1;
    acme_log("certificate obtained for %s (%d SAN entries)\n", domains[0], ndomains);
    return 0;
}

/* --- certificate cache (analog of autocert.DirCache) --- */

static int cert_cache_load(AcmeClient *ac, const char *domain,
                           RSAKey *key, uint8_t *leaf, int *leaf_len, time_t *not_after) {
    char path[1024];
    snprintf(path, sizeof(path), "%s/%s.pem", ac->cache_dir, domain);
    char buf[32768];
    long n = read_file(path, buf, sizeof(buf) - 1);
    if (n <= 0) return -1;
    buf[n] = '\0';

    char *kb = strstr(buf, "-----BEGIN RSA PRIVATE KEY-----");
    if (!kb) return -1;
    char *ke = strstr(kb, "-----END RSA PRIVATE KEY-----");
    if (!ke) return -1;
    uint8_t der[4096];
    int der_len = b64_decode(kb + 31, (int)(ke - (kb + 31)), der, sizeof(der));
    if (der_len <= 0) return -1;
    if (tls_rsa_parse_private_der(key, der, der_len) != 0) return -1;

    char *cb = strstr(buf, "-----BEGIN CERTIFICATE-----");
    if (!cb) return -1;
    char *ce = strstr(cb, "-----END CERTIFICATE-----");
    if (!ce) return -1;
    int clen = b64_decode(cb + 27, (int)(ce - (cb + 27)), leaf, TLS_RSA_MAX_CERT_SIZE);
    if (clen <= 0) return -1;
    *leaf_len = clen;
    return cert_not_after(leaf, clen, not_after);
}

static int cert_cache_save(AcmeClient *ac, const char *domain,
                           const RSAKey *key, const char *cert_pem) {
    uint8_t pkcs1[2048];
    int pkcs1_len = build_private_pkcs1(key, pkcs1);
    if (pkcs1_len <= 0) return -1;
    char *keypem = pem_build("RSA PRIVATE KEY", pkcs1, pkcs1_len);
    if (!keypem) return -1;

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s.pem", ac->cache_dir, domain);
    char *combined = (char *)malloc(strlen(keypem) + strlen(cert_pem) + 16);
    if (!combined) { free(keypem); return -1; }
    strcpy(combined, keypem);
    strcat(combined, cert_pem);
    int rc = write_file(path, combined, strlen(combined));
    free(combined);

    char crt[1024], keyf[1024];
    snprintf(crt, sizeof(crt), "%s/%s.crt", ac->cache_dir, domain);
    snprintf(keyf, sizeof(keyf), "%s/%s.key", ac->cache_dir, domain);
    if (write_file(crt, cert_pem, strlen(cert_pem)) != 0) rc = -1;
    if (write_file(keyf, keypem, strlen(keypem)) != 0) rc = -1;
    free(keypem);
    if (rc == 0) acme_log("certificate saved to %s\n", path);
    return rc;
}

/* Return a valid certificate for the domains: from cache or freshly issued.
 * The cache file is keyed by the primary domain (domains[0]). */
static int acme_ensure_cert(AcmeClient *ac, const char *const *domains, int ndomains,
                            RSAKey *cert_key, char *cert_pem, int cert_sz, time_t *not_after) {
    const char *domain = domains[0];
    uint8_t leaf[TLS_RSA_MAX_CERT_SIZE];
    int leaf_len = 0;
    time_t na = 0;
    if (cert_cache_load(ac, domain, cert_key, leaf, &leaf_len, &na) == 0) {
        time_t now = time(NULL);
        char ts[64];
        struct tm *t = gmtime(&na);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S UTC", t);
        if (!cert_san_covers(leaf, leaf_len, domains, ndomains)) {
            acme_log("cached certificate SAN does not cover all requested domains, renewing...\n");
        } else if (na - now > RENEW_BEFORE_SEC) {
            char crt_path[1024];
            snprintf(crt_path, sizeof(crt_path), "%s/%s.crt", ac->cache_dir, domain);
            long n = read_file(crt_path, cert_pem, (size_t)cert_sz - 1);
            if (n > 0) {
                cert_pem[n] = '\0';
                *not_after = na;
                acme_log("using cached certificate for %s (expires %s)\n", domain, ts);
                return 0;
            }
        } else {
            acme_log("cached certificate for %s expires %s, renewing...\n", domain, ts);
        }
    }
    if (acme_create_cert(ac, domains, ndomains, cert_key, cert_pem, cert_sz) != 0) return -1;
    if (cert_cache_save(ac, domain, cert_key, cert_pem) != 0)
        acme_log("warning: failed to save certificate to cache\n");
    uint8_t cder[TLS_RSA_MAX_CERT_SIZE];
    int clen = 0;
    if (cert_first_der(cert_pem, cder, &clen) == 0)
        cert_not_after(cder, clen, not_after);
    return 0;
}

/* --- http-01 challenge server on port 80 (analog of Manager.HTTPHandler) --- */

static void *chal_thread_fn(void *arg) {
    int port = (int)(intptr_t)arg;
    SOCKET lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd == INVALID_SOCKET) return NULL;
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        printf("[chal] bind port %d failed (run as administrator?)\n", port);
        closesocket(lfd);
        return NULL;
    }
    if (listen(lfd, 16) != 0) {
        closesocket(lfd);
        return NULL;
    }
    printf("[chal] http-01 challenge server listening on port %d\n", port);
    while (!g_stop) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(lfd, &rf);
        struct timeval tv = { 0, 500000 };
        int sel = select((int)lfd + 1, &rf, NULL, NULL, &tv);
        if (sel <= 0 || !FD_ISSET(lfd, &rf)) continue;
        SOCKET sock = accept(lfd, NULL, NULL);
        if (sock == INVALID_SOCKET) continue;
        char req[8192];
        int n = recv(sock, req, (int)sizeof(req) - 1, 0);
        if (n > 0) {
            req[n] = '\0';
            char method[8] = { 0 }, path[2048] = { 0 }, host[256] = { 0 };
            sscanf(req, "%7s %2047s", method, path);
            const char *hh = strstr(req, "\r\nHost: ");
            if (!hh) hh = strstr(req, "\nHost: ");
            if (hh) {
                hh += 8;
                const char *he = strchr(hh, '\r');
                if (!he) he = strchr(hh, '\n');
                if (he) {
                    size_t hl = (size_t)(he - hh);
                    if (hl >= sizeof(host)) hl = sizeof(host) - 1;
                    memcpy(host, hh, hl);
                    host[hl] = '\0';
                }
            }
            const char *prefix = "/.well-known/acme-challenge/";
            if (strcmp(method, "GET") == 0 && strncmp(path, prefix, strlen(prefix)) == 0) {
                const char *token = path + strlen(prefix);
                char keyauth[512];
                if (chal_lookup(token, keyauth, sizeof(keyauth))) {
                    char resp[1024];
                    int rl = snprintf(resp, sizeof(resp),
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                        "Content-Length: %d\r\nConnection: close\r\n\r\n%s",
                        (int)strlen(keyauth), keyauth);
                    send(sock, resp, rl, 0);
                } else {
                    const char *resp =
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    send(sock, resp, (int)strlen(resp), 0);
                }
            } else {
                char resp[2300];
                const char *h = host[0] ? host : g_domain;
                int rl = snprintf(resp, sizeof(resp),
                    "HTTP/1.1 302 Found\r\nLocation: https://%s%s\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n",
                    h, path);
                send(sock, resp, rl, 0);
            }
        }
        shutdown(sock, SD_BOTH);
        closesocket(sock);
    }
    closesocket(lfd);
    return NULL;
}

/* --- shutdown handling --- */

#ifdef _WIN32
static BOOL WINAPI console_ctrl_handler(DWORD ctrl) {
    (void)ctrl;
    g_stop = 1;
    return TRUE;
}
#else
static void sigint_handler(int sig) {
    (void)sig;
    g_stop = 1;
}
#endif

/* --- entry point --- */

static void print_help(FILE *out, const char *prog) {
    fprintf(out,
        "mini-acme - automatic ACME (Let's Encrypt) certificate management in pure C.\n"
        "\n"
         "Usage:\n"
         "  %s [-domain <name>]... [-dir <acme-directory-url>] [-cache <dir>] [-email <addr>]\n"
         "      [--apikey <key> --dns <provider>] [-h]\n"
         "\n"
         "Arguments:\n"
         "  -domain <name>   Domain to include in the certificate (repeatable, up to %d).\n"
         "                   The first -domain is the primary (CN + cache file name),\n"
         "                   all are listed in SAN. Every domain must be publicly\n"
         "                   resolvable for http-01 validation. Wildcard domains\n"
         "                   (*.example.com) are validated via dns-01 instead: the\n"
         "                   required TXT record (_acme-challenge.*) is published and\n"
         "                   removed automatically when --dns/--apikey are given,\n"
         "                   otherwise it is printed and you add it at the DNS provider.\n"
         "  --apikey <key>   API key of the DNS provider (--dns). The two options\n"
         "                   must be given together.\n"
          "  --dns <provider> DNS provider for the automatic TXT record management.\n"
          "                   Supported: dynadot.\n"
         "  -dir <url>       ACME directory URL (default: Let's Encrypt production:\n"
         "                   https://acme-v02.api.letsencrypt.org/directory).\n"
         "                   Staging: https://acme-staging-v02.api.letsencrypt.org/directory\n"
        "  -cache <dir>     Certificate cache directory (default: certs).\n"
        "  -email <addr>    Contact email for the ACME account (default: admin@example.com).\n"
        "  -h, -help        Show this help.\n"
        "\n"
        "The program serves the http-01 challenge on port 80, obtains an RSA\n"
        "certificate and saves it to the cache directory, then exits.\n"
        "A cached certificate is reused if it is valid for more than 30 days.\n"
         "\n"
         "Example:\n"
         "  %s -domain example.com -domain www.example.com\n"
         "  %s -domain example.com -domain '*.example.com'   (wildcard: dns-01)\n"
         "  %s -domain example.com -domain '*.example.com' --dns dynadot --apikey <key>\n",
         prog, MAX_DOMAINS, prog, prog, prog);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    const char *dir_url = NULL, *cache = NULL, *email = NULL;
    const char *api_key = NULL, *dns_provider = NULL;
    const char *domains[MAX_DOMAINS];
    int ndomains = 0;
    char hostbuf[256];

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "-h") == 0 || strcmp(a, "-help") == 0 || strcmp(a, "--help") == 0) {
            print_help(stdout, argv[0]);
            return 0;
        } else if (strcmp(a, "-domain") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no domain specified for -domain\n"); return 1; }
            const char *d = argv[++i];
            if (!*d || strlen(d) > 253) { fprintf(stderr, "Error: bad domain \"%s\"\n", d); return 1; }
            int dup = 0;
            for (int k = 0; k < ndomains; k++)
                if (strcmp(domains[k], d) == 0) { dup = 1; break; }
            if (dup) continue;
            if (ndomains >= MAX_DOMAINS) {
                fprintf(stderr, "Error: too many -domain flags (max %d)\n", MAX_DOMAINS);
                return 1;
            }
            domains[ndomains++] = d;
        } else if (strcmp(a, "-dir") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no URL specified for -dir\n"); return 1; }
            dir_url = argv[++i];
        } else if (strcmp(a, "-cache") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no directory specified for -cache\n"); return 1; }
            cache = argv[++i];
        } else if (strcmp(a, "-email") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no email specified for -email\n"); return 1; }
            email = argv[++i];
        } else if (strcmp(a, "--apikey") == 0 || strcmp(a, "-apikey") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no API key specified for --apikey\n"); return 1; }
            api_key = argv[++i];
        } else if (strcmp(a, "--dns") == 0 || strcmp(a, "-dns") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "Error: no provider specified for --dns\n"); return 1; }
            dns_provider = argv[++i];
        } else {
            fprintf(stderr, "Error: unknown argument \"%s\"\n", a);
            print_help(stderr, argv[0]);
            return 1;
        }
    }

    if ((api_key != NULL) != (dns_provider != NULL)) {
        fprintf(stderr, "Error: --apikey and --dns must be given together\n");
        return 1;
    }
    if (api_key && !*api_key) {
        fprintf(stderr, "Error: empty --apikey\n");
        return 1;
    }
    if (api_key && strcmp(dns_provider, "dynadot") != 0) {
        fprintf(stderr, "Error: unsupported DNS provider \"%s\" (supported: dynadot)\n", dns_provider);
        return 1;
    }

    if (ndomains == 0) {
        if (get_hostname(hostbuf, sizeof(hostbuf)) != 0) {
            fprintf(stderr, "Error: cannot get hostname, use -domain <name>\n");
            return 1;
        }
        domains[ndomains++] = hostbuf;
    }
    strncpy(g_domain, domains[0], sizeof(g_domain) - 1);
    g_domain[sizeof(g_domain) - 1] = '\0';
    printf("Domains (%d):", ndomains);
    for (int i = 0; i < ndomains; i++) printf(" %s", domains[i]);
    printf("\n");

    if (sock_init() != 0) {
        fprintf(stderr, "Error: socket init failed\n");
        return 1;
    }

    acme_init(&g_acme, dir_url, cache, email);
    if (api_key) {
        snprintf(g_acme.api_key, sizeof(g_acme.api_key), "%s", api_key);
        snprintf(g_acme.dns_provider, sizeof(g_acme.dns_provider), "%s", dns_provider);
        g_acme.have_dns_api = 1;
        printf("DNS provider: %s (automatic TXT record management)\n", dns_provider);
    }
    ensure_dir(g_acme.cache_dir);
    mtx_init(&g_chal_lock);

    g_acme.http = url_init();
    if (!g_acme.http) {
        fprintf(stderr, "Error: url_init failed\n");
        return 1;
    }
    url_set_user_agent(g_acme.http, "mini-acme/1.0");
    g_acme.http->connect_timeout_ms = 15000;
    g_acme.http->connect_timeout_set = 1;

#ifdef _WIN32
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#else
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
#endif

    thr_t chal_thr;
    if (thr_create(&chal_thr, chal_thread_fn, (void *)(intptr_t)CHAL_PORT) != 0) {
        fprintf(stderr, "Error: cannot start challenge server thread\n");
        return 1;
    }

    printf("Obtaining certificate for %s ...\n", domains[0]);
    RSAKey cert_key;
    char cert_pem[16384];
    time_t not_after = 0;
    if (acme_ensure_cert(&g_acme, domains, ndomains, &cert_key, cert_pem, sizeof(cert_pem), &not_after) != 0) {
        fprintf(stderr, "Error: failed to obtain certificate for %s\n", domains[0]);
        g_stop = 1;
        thr_join(&chal_thr);
        url_free(g_acme.http);
        mtx_destroy(&g_chal_lock);
        sock_cleanup();
        return 1;
    }
    if (not_after) {
        char ts[64];
        struct tm *t = gmtime(&not_after);
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S UTC", t);
        printf("Certificate valid until: %s\n", ts);
    }
    printf("Certificate saved to %s/%s.pem\n", g_acme.cache_dir, g_domain);

    g_stop = 1;
    thr_join(&chal_thr);
    url_free(g_acme.http);
    mtx_destroy(&g_chal_lock);
    sock_cleanup();
    printf("Done.\n");
    return 0;
}
