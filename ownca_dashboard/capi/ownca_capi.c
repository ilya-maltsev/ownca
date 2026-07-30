/* ownca_capi — OwnCA <-> CryptoPro CSP (CAPILite) bridge.
 *
 * A thin C-shim invoked by dashboard/own_ca.py via subprocess (mirroring the
 * existing _run([openssl,...]) model), so the GOST leg of the CA runs entirely
 * on the certified CryptoPro CSP — NO openssl touches the GOST material. The CA
 * key never leaves its CryptoPro container; only DER cert/CRL/PFX bytes cross
 * the process boundary.
 *
 * Subcommands:
 *   info
 *   paramsets --alg gost2012_256|gost2012_512
 *             (JSON list of the key-paramset OIDs the provider supports, read
 *             via PP_ENUM_SIGNATUREOID — what the issue form may offer)
 *   genkey    --container NAME --alg gost2012_256|gost2012_512
 *             [--paramset A|B|C|XA|XB]  (256: CryptoPro sets incl. XchA/XchB;
 *             512: TC26 sets A/B/C. Omitted => the provider default. An
 *             unknown name is refused, never silently defaulted.)
 *   gencsr    --container NAME --subject DN --alg ALG --out FILE(DER PKCS#10)
 *             (self-signed request for a key already in the container; the
 *             issue path does not need it — it exists so a server-generated
 *             cert leaves the same csr.pem the openssl backend writes)
 *   selfsign  --container NAME --subject "CN=..,O=..,C=RU" --days N --serial HEX
 *             --alg ... [--extspec FILE] --out FILE
 *   issue     --container CA_NAME --subject-container SUBJ_NAME --subject DN
 *             --issuer DN --days N --serial HEX --alg CA_ALG
 *             [--subject-alg SUBJ_ALG] [--extspec FILE] --out FILE
 *   issuecsr  --container CA_NAME --csr FILE(DER PKCS#10) --issuer DN --days N
 *             --serial HEX --alg CA_ALG [--subject DN] [--extspec FILE] --out FILE
 *             (subject public key comes from the CSR; its self-signature is
 *             verified first; subject DN defaults to the CSR's own)
 *   gencrl    --container CA_NAME --issuer DN [--revoked FILE] [--crlnumber HEX] --out FILE
 *             (--revoked lines: "serialhex[,unixtime[,reasoncode]]"; an absent
 *             reasoncode omits the RFC 5280 reasonCode entry extension)
 *   exportpfx --container NAME --cert FILE(DER) [--password PW]
 *             [--chain FILE(DER)]... --out FILE
 *             (each --chain cert is added to the store WITHOUT a key — the
 *             parent chain of a CA/leaf export)
 *   importpfx --pfx FILE [--password PW] --out FILE(DER)
 *             (PFXIsPFXBlob -> PFXVerifyPassword -> PFXImportCertStore: the
 *             private key lands in a CryptoPro container, never on disk; the
 *             cert that owns the key is written DER to --out and its container
 *             name / prov type / X.500 subject are reported as JSON)
 *   delcontainer --container NAME [--alg ALG]
 *             (CryptAcquireContext CRYPT_DELETEKEYSET — drops the key
 *             container when a CA/cert is deleted or its creation is rolled
 *             back. --alg is a hint only; both GOST provider types are tried.
 *             An absent container is deleted:false with exit 0, so cleanup is
 *             idempotent)
 *
 * X.509 extensions are built structurally via CryptEncodeObject from a simple
 * line-based --extspec file (Python writes it from the CertProfile model). SKI
 * is hashed by CryptoPro (CryptHashPublicKeyInfo); AKI = the issuer key's SKI.
 * Supported extspec keys: bc*, ku*, eku*, ski, aki, san_{dns,email,uri,ip},
 * cdp, aia_{ca,ocsp}, sia_repo, freshest_crl, ian_{dns,email,uri,ip},
 * aki_issuer_{dn,serial}. ski/aki are opt-in: a profile that omits the line
 * gets no extension, matching the openssl backend.
 *
 * Exit 0 on success; non-zero + stderr on error. Build flags/link libs are in
 * dev_env/dashboard/Dockerfile.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

#include "CSP_WinDef.h"
#include "CSP_WinCrypt.h"
#include "WinCryptEx.h"

#ifndef PROV_GOST_2012_256
#define PROV_GOST_2012_256 80
#endif
#ifndef PROV_GOST_2012_512
#define PROV_GOST_2012_512 81
#endif

/* "no such container" from CryptAcquireContext, i.e. nothing to delete.
 * Standard wincrypt values, redefined defensively like the OIDs below. */
#ifndef NTE_BAD_KEYSET
#define NTE_BAD_KEYSET 0x80090016L
#endif
#ifndef NTE_KEYSET_NOT_DEF
#define NTE_KEYSET_NOT_DEF 0x80090019L
#endif

/* CRL entry reasonCode (RFC 5280 §5.3.1). Standard wincrypt names, redefined
 * defensively in case a CryptoPro SDK header revision omits them. */
#ifndef szOID_CRL_REASON_CODE
#define szOID_CRL_REASON_CODE "2.5.29.21"
#endif
#ifndef X509_CRL_REASON_CODE
#define X509_CRL_REASON_CODE ((LPCSTR) 22)
#endif

/* CA-cert distribution pointers. szOID_PKIX_CA_REPOSITORY in particular is not
 * part of the Microsoft wincrypt set the CryptoPro headers mirror, so it must
 * be spelled out here. */
#ifndef szOID_SUBJECT_INFO_ACCESS
#define szOID_SUBJECT_INFO_ACCESS "1.3.6.1.5.5.7.1.11"
#endif
#ifndef szOID_PKIX_CA_REPOSITORY
#define szOID_PKIX_CA_REPOSITORY "1.3.6.1.5.5.7.48.5"
#endif
#ifndef szOID_FRESHEST_CRL
#define szOID_FRESHEST_CRL "2.5.29.46"
#endif
#ifndef szOID_ISSUER_ALT_NAME2
#define szOID_ISSUER_ALT_NAME2 "2.5.29.18"
#endif

#define MAX_LIST 32
#define MAX_EXT  16

/* ---- diagnostics -------------------------------------------------------- */

static void err(const char *what) {
    fprintf(stderr, "ownca_capi: %s failed: 0x%08X\n", what, (unsigned)GetLastError());
}
static int fail(const char *what) { err(what); return 1; }

static FILETIME unix_to_ft(time_t t) {
    unsigned long long ticks = ((unsigned long long)t + 11644473600ULL) * 10000000ULL;
    FILETIME ft;
    ft.dwLowDateTime  = (DWORD)(ticks & 0xFFFFFFFF);
    ft.dwHighDateTime = (DWORD)(ticks >> 32);
    return ft;
}

static DWORD prov_type_for(const char *alg) {
    if (alg && strcmp(alg, "gost2012_512") == 0) return PROV_GOST_2012_512;
    return PROV_GOST_2012_256;
}
static const char *sign_oid_for(const char *alg) {
    if (alg && strcmp(alg, "gost2012_512") == 0)
        return szOID_CP_GOST_R3411_12_512_R3410;
    return szOID_CP_GOST_R3411_12_256_R3410;
}
/* GOST R 34.10-2012 key paramset OIDs, keyed by the short names the dashboard
 * offers (own_ca.GOST_PARAMSET_CHOICES_256 / _512). 256-bit keys reuse the
 * CryptoPro 2001 sets, including the XchA/XchB exchange sets; 512-bit keys use
 * the TC26 sets. Returns NULL for an unknown name so the caller can refuse
 * rather than silently generate with the provider default. */
static const char *paramset_oid_for(const char *alg, const char *ps) {
    if (!ps || !*ps) return NULL;
    if (alg && strcmp(alg, "gost2012_512") == 0) {
        if (!strcmp(ps, "A")) return "1.2.643.7.1.2.1.2.1";
        if (!strcmp(ps, "B")) return "1.2.643.7.1.2.1.2.2";
        if (!strcmp(ps, "C")) return "1.2.643.7.1.2.1.2.3";
        return NULL;
    }
    if (!strcmp(ps, "A"))  return "1.2.643.2.2.35.1";
    if (!strcmp(ps, "B"))  return "1.2.643.2.2.35.2";
    if (!strcmp(ps, "C"))  return "1.2.643.2.2.35.3";
    if (!strcmp(ps, "XA")) return "1.2.643.2.2.36.0";
    if (!strcmp(ps, "XB")) return "1.2.643.2.2.36.1";
    return NULL;
}

static ALG_ID hash_alg_for(const char *alg) {
    if (alg && strcmp(alg, "gost2012_512") == 0) return CALG_GR3411_2012_512;
    return CALG_GR3411_2012_256;
}

/* ---- small helpers ------------------------------------------------------ */

static const char *opt(int argc, char **argv, const char *key) {
    for (int i = 0; i + 1 < argc; i++)
        if (strcmp(argv[i], key) == 0) return argv[i + 1];
    return NULL;
}

static int hex2bin(const char *hex, BYTE **out, DWORD *outlen) {
    size_t n = strlen(hex);
    if (n % 2 != 0) return 1;
    size_t bytes = n / 2;
    BYTE *b = (BYTE *)malloc(bytes ? bytes : 1);
    if (!b) return 1;
    for (size_t i = 0; i < bytes; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) { free(b); return 1; }
        b[i] = (BYTE)v;
    }
    *out = b; *outlen = (DWORD)bytes;
    return 0;
}

/* hex serial -> little-endian CRYPT_INTEGER_BLOB (MS stores serials LE). */
static int parse_serial_le(const char *hex, BYTE **out, DWORD *outlen) {
    if (!hex || !*hex) {
        BYTE *b = (BYTE *)malloc(1); if (!b) return 1;
        b[0] = 0x01; *out = b; *outlen = 1; return 0;
    }
    BYTE *be = NULL; DWORD n = 0;
    if (hex2bin(hex, &be, &n) != 0) return 1;
    BYTE *le = (BYTE *)malloc(n ? n : 1);
    if (!le) { free(be); return 1; }
    for (DWORD i = 0; i < n; i++) le[i] = be[n - 1 - i];
    free(be);
    *out = le; *outlen = n;
    return 0;
}

static wchar_t *to_wide(const char *s) {
    size_t n = strlen(s);
    wchar_t *w = (wchar_t *)malloc((n + 1) * sizeof(wchar_t));
    if (!w) return NULL;
    for (size_t i = 0; i < n; i++) w[i] = (wchar_t)(unsigned char)s[i];
    w[n] = 0;
    return w;
}

static int write_file(const char *path, const BYTE *buf, DWORD len) {
    FILE *f = fopen(path, "wb");
    if (!f) { fprintf(stderr, "ownca_capi: cannot open %s for write\n", path); return 1; }
    size_t w = fwrite(buf, 1, len, f);
    fclose(f);
    if (w != len) { fprintf(stderr, "ownca_capi: short write to %s\n", path); return 1; }
    return 0;
}

static BYTE *read_file(const char *path, DWORD *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return NULL; }
    BYTE *b = (BYTE *)malloc(sz ? sz : 1);
    if (!b) { fclose(f); return NULL; }
    size_t r = fread(b, 1, sz, f);
    fclose(f);
    if (r != (size_t)sz) { free(b); return NULL; }
    *len = (DWORD)sz;
    return b;
}

/* ---- extspec ------------------------------------------------------------ */
/* A simple key=value line file. Repeated san/eku/cdp/aia keys accumulate. */

typedef struct {
    int  has_bc, bc_ca, bc_critical, bc_pathlen;   /* bc_pathlen<0 => none */
    int  has_ku, ku_critical; char ku_hex[16]; int ku_unused;
    int  eku_critical; char *eku[MAX_LIST]; int eku_n;
    int  want_ski, want_aki;
    char *san_dns[MAX_LIST];   int san_dns_n;
    char *san_email[MAX_LIST]; int san_email_n;
    char *san_uri[MAX_LIST];   int san_uri_n;
    char *san_ip[MAX_LIST];    int san_ip_n;   /* hex */
    char *cdp[MAX_LIST];       int cdp_n;
    char *aia_ca[MAX_LIST];    int aia_ca_n;
    char *aia_ocsp[MAX_LIST];  int aia_ocsp_n;
    /* CA-cert distribution pointers: subjectInfoAccess caRepository,
     * freshestCRL (delta-CRL) and issuerAltName. */
    char *sia_repo[MAX_LIST];     int sia_repo_n;
    char *freshest_crl[MAX_LIST]; int freshest_crl_n;
    char *ian_dns[MAX_LIST];      int ian_dns_n;
    char *ian_email[MAX_LIST];    int ian_email_n;
    char *ian_uri[MAX_LIST];      int ian_uri_n;
    char *ian_ip[MAX_LIST];       int ian_ip_n;   /* hex */
    /* authorityKeyIdentifier "issuer:always": the CA certificate's OWN issuer
     * DN + serial, identifying the CA cert itself (RFC 5280 §4.2.1.1). Empty =
     * keyid-only AKI, which is what a profile without `issuer:always` asks for. */
    char aki_issuer_dn[512];
    char aki_issuer_serial[128];
} ExtSpec;

static void spec_init(ExtSpec *s) { memset(s, 0, sizeof(*s)); s->bc_pathlen = -1; }

static void push(char **arr, int *n, const char *v) {
    if (*n < MAX_LIST) arr[(*n)++] = strdup(v);
}

static int parse_extspec(const char *path, ExtSpec *s) {
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "ownca_capi: cannot open extspec %s\n", path); return 1; }
    char line[2048];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
        if (!line[0] || line[0] == '#') continue;
        char *eq = strchr(line, '='); if (!eq) continue;
        *eq = 0; const char *k = line, *v = eq + 1;
        if      (!strcmp(k, "bc"))           s->has_bc = atoi(v);
        else if (!strcmp(k, "bc_ca"))        s->bc_ca = atoi(v);
        else if (!strcmp(k, "bc_critical"))  s->bc_critical = atoi(v);
        else if (!strcmp(k, "bc_pathlen"))   s->bc_pathlen = atoi(v);
        else if (!strcmp(k, "ku"))           { s->has_ku = 1; }
        else if (!strcmp(k, "ku_hex"))       { s->has_ku = 1; strncpy(s->ku_hex, v, sizeof(s->ku_hex)-1); }
        else if (!strcmp(k, "ku_unused"))    s->ku_unused = atoi(v);
        else if (!strcmp(k, "ku_critical"))  s->ku_critical = atoi(v);
        else if (!strcmp(k, "eku"))          push(s->eku, &s->eku_n, v);
        else if (!strcmp(k, "eku_critical")) s->eku_critical = atoi(v);
        else if (!strcmp(k, "ski"))          s->want_ski = atoi(v);
        else if (!strcmp(k, "aki"))          s->want_aki = atoi(v);
        else if (!strcmp(k, "san_dns"))      push(s->san_dns, &s->san_dns_n, v);
        else if (!strcmp(k, "san_email"))    push(s->san_email, &s->san_email_n, v);
        else if (!strcmp(k, "san_uri"))      push(s->san_uri, &s->san_uri_n, v);
        else if (!strcmp(k, "san_ip"))       push(s->san_ip, &s->san_ip_n, v);
        else if (!strcmp(k, "cdp"))          push(s->cdp, &s->cdp_n, v);
        else if (!strcmp(k, "aia_ca"))       push(s->aia_ca, &s->aia_ca_n, v);
        else if (!strcmp(k, "aia_ocsp"))     push(s->aia_ocsp, &s->aia_ocsp_n, v);
        else if (!strcmp(k, "sia_repo"))     push(s->sia_repo, &s->sia_repo_n, v);
        else if (!strcmp(k, "freshest_crl")) push(s->freshest_crl, &s->freshest_crl_n, v);
        else if (!strcmp(k, "ian_dns"))      push(s->ian_dns, &s->ian_dns_n, v);
        else if (!strcmp(k, "ian_email"))    push(s->ian_email, &s->ian_email_n, v);
        else if (!strcmp(k, "ian_uri"))      push(s->ian_uri, &s->ian_uri_n, v);
        else if (!strcmp(k, "ian_ip"))       push(s->ian_ip, &s->ian_ip_n, v);
        else if (!strcmp(k, "aki_issuer_dn"))
            strncpy(s->aki_issuer_dn, v, sizeof(s->aki_issuer_dn) - 1);
        else if (!strcmp(k, "aki_issuer_serial"))
            strncpy(s->aki_issuer_serial, v, sizeof(s->aki_issuer_serial) - 1);
    }
    fclose(f);
    return 0;
}

/* CryptEncodeObject wrapper: allocates *out (caller frees). */
static int encode(LPCSTR structType, const void *data, BYTE **out, DWORD *outlen) {
    DWORD cb = 0;
    if (!CryptEncodeObject(X509_ASN_ENCODING, structType, data, NULL, &cb)) return 1;
    BYTE *b = (BYTE *)malloc(cb ? cb : 1);
    if (!b) return 1;
    if (!CryptEncodeObject(X509_ASN_ENCODING, structType, data, b, &cb)) { free(b); return 1; }
    *out = b; *outlen = cb;
    return 0;
}

/* CryptDecodeObject wrapper: allocates *out (caller frees). */
static int decode_alloc(LPCSTR structType, const BYTE *data, DWORD len, void **out) {
    DWORD cb = 0;
    if (!CryptDecodeObject(X509_ASN_ENCODING, structType, data, len, 0, NULL, &cb)) return 1;
    void *b = malloc(cb ? cb : 1);
    if (!b) return 1;
    if (!CryptDecodeObject(X509_ASN_ENCODING, structType, data, len, 0, b, &cb)) { free(b); return 1; }
    *out = b;
    return 0;
}

/* Map a subject-public-key OID to our alg name (for provider selection). */
static const char *alg_for_pubkey_oid(const char *oid) {
    if (oid && strcmp(oid, szOID_CP_GOST_R3410_12_512) == 0) return "gost2012_512";
    return "gost2012_256";
}

/* Compute a key identifier (SKI) = CryptoPro hash of the public key info. */
/* Key identifier (SKI) = CryptoPro GOST hash of the raw public-key bytes. We
 * hash the subjectPublicKey BIT STRING contents with CryptCreateHash/HashData
 * (CryptHashPublicKeyInfo rejects the GOST algids here with 0x57). SKI and AKI
 * use the SAME routine, so a child's AKI keyid always equals its issuer's SKI.
 * Truncated to 20 bytes for a conventional-length identifier. */
static int compute_keyid(HCRYPTPROV hProv, ALG_ID hashAlg,
                         PCERT_PUBLIC_KEY_INFO pPub, BYTE **out, DWORD *outlen) {
    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, hashAlg, 0, 0, &hHash)) return 1;
    if (!CryptHashData(hHash, pPub->PublicKey.pbData, pPub->PublicKey.cbData, 0)) {
        CryptDestroyHash(hHash); return 1;
    }
    DWORD cb = 0;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, NULL, &cb, 0)) {
        CryptDestroyHash(hHash); return 1;
    }
    BYTE *b = (BYTE *)malloc(cb ? cb : 1);
    if (!b) { CryptDestroyHash(hHash); return 1; }
    if (!CryptGetHashParam(hHash, HP_HASHVAL, b, &cb, 0)) {
        free(b); CryptDestroyHash(hHash); return 1;
    }
    CryptDestroyHash(hHash);
    DWORD keep = cb < 20 ? cb : 20;   /* conventional 20-byte SKI */
    *out = b; *outlen = keep;
    return 0;
}

/* Encode an X.500 DN string ("CN=x, O=y") into a CERT_NAME_BLOB. */
static int encode_name(const char *dn, CERT_NAME_BLOB *out) {
    DWORD cb = 0;
    if (!CertStrToNameA(X509_ASN_ENCODING, dn, CERT_X500_NAME_STR, NULL, NULL, &cb, NULL))
        return 1;
    BYTE *buf = (BYTE *)malloc(cb);
    if (!buf) return 1;
    if (!CertStrToNameA(X509_ASN_ENCODING, dn, CERT_X500_NAME_STR, NULL, buf, &cb, NULL)) {
        free(buf); return 1;
    }
    out->cbData = cb; out->pbData = buf;
    return 0;
}

/* Build a GeneralNames entry array from typed lists. Shared by subjectAltName
 * and issuerAltName — both are the same ASN.1 structure, only the extension OID
 * differs. Returns a malloc'd array via *entries (caller frees) and its count. */
static int build_altname_entries(char **dns, int dns_n, char **email, int email_n,
                                 char **uri, int uri_n, char **ip, int ip_n,
                                 CERT_ALT_NAME_ENTRY **entries, DWORD *count) {
    int total = dns_n + email_n + uri_n + ip_n;
    if (total == 0) { *entries = NULL; *count = 0; return 0; }
    CERT_ALT_NAME_ENTRY *e = (CERT_ALT_NAME_ENTRY *)calloc(total, sizeof(*e));
    if (!e) return 1;
    int i = 0;
    for (int k = 0; k < dns_n; k++) {
        e[i].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
        e[i]._empty_union_.pwszDNSName = to_wide(dns[k]); i++;
    }
    for (int k = 0; k < email_n; k++) {
        e[i].dwAltNameChoice = CERT_ALT_NAME_RFC822_NAME;
        e[i]._empty_union_.pwszRfc822Name = to_wide(email[k]); i++;
    }
    for (int k = 0; k < uri_n; k++) {
        e[i].dwAltNameChoice = CERT_ALT_NAME_URL;
        e[i]._empty_union_.pwszURL = to_wide(uri[k]); i++;
    }
    for (int k = 0; k < ip_n; k++) {
        BYTE *ipb = NULL; DWORD iplen = 0;
        if (hex2bin(ip[k], &ipb, &iplen) == 0) {
            e[i].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
            e[i]._empty_union_.IPAddress.cbData = iplen;
            e[i]._empty_union_.IPAddress.pbData = ipb;
            i++;
        }
    }
    *entries = e; *count = i;
    return 0;
}

/* Fill an alt-name-info from spec SAN lists. Returns malloc'd entry array via
 * *entries (caller frees) and count. */
static int build_altnames(ExtSpec *s, CERT_ALT_NAME_ENTRY **entries, DWORD *count) {
    return build_altname_entries(s->san_dns, s->san_dns_n,
                                 s->san_email, s->san_email_n,
                                 s->san_uri, s->san_uri_n,
                                 s->san_ip, s->san_ip_n, entries, count);
}

/* Build the CERT_EXTENSION array from spec. pSubjectPub is hashed for SKI;
 * pIssuerPub for AKI. Returns count; caller frees rgExt[i].Value.pbData. */
static int build_extensions(ExtSpec *s, HCRYPTPROV hProv, ALG_ID hashAlg,
                            PCERT_PUBLIC_KEY_INFO pSubjectPub,
                            PCERT_PUBLIC_KEY_INFO pIssuerPub,
                            CERT_EXTENSION *rgExt) {
    int n = 0;

    if (s->has_bc) {
        CERT_BASIC_CONSTRAINTS2_INFO bc;
        memset(&bc, 0, sizeof(bc));
        bc.fCA = s->bc_ca ? TRUE : FALSE;
        if (s->bc_pathlen >= 0) { bc.fPathLenConstraint = TRUE; bc.dwPathLenConstraint = s->bc_pathlen; }
        BYTE *v = NULL; DWORD vl = 0;
        if (encode(X509_BASIC_CONSTRAINTS2, &bc, &v, &vl) == 0) {
            rgExt[n].pszObjId = (LPSTR)szOID_BASIC_CONSTRAINTS2;
            rgExt[n].fCritical = s->bc_critical ? TRUE : FALSE;
            rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
        }
    }

    if (s->has_ku && s->ku_hex[0]) {
        BYTE *bits = NULL; DWORD bl = 0;
        if (hex2bin(s->ku_hex, &bits, &bl) == 0) {
            CRYPT_BIT_BLOB blob; memset(&blob, 0, sizeof(blob));
            blob.cbData = bl; blob.pbData = bits; blob.cUnusedBits = s->ku_unused;
            BYTE *v = NULL; DWORD vl = 0;
            if (encode(X509_KEY_USAGE, &blob, &v, &vl) == 0) {
                rgExt[n].pszObjId = (LPSTR)szOID_KEY_USAGE;
                rgExt[n].fCritical = s->ku_critical ? TRUE : FALSE;
                rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
            }
        }
    }

    if (s->eku_n > 0) {
        CTL_USAGE eku; memset(&eku, 0, sizeof(eku));
        eku.cUsageIdentifier = s->eku_n;
        eku.rgpszUsageIdentifier = (LPSTR *)malloc(sizeof(LPSTR) * s->eku_n);
        for (int i = 0; i < s->eku_n; i++) eku.rgpszUsageIdentifier[i] = s->eku[i];
        BYTE *v = NULL; DWORD vl = 0;
        if (encode(X509_ENHANCED_KEY_USAGE, &eku, &v, &vl) == 0) {
            rgExt[n].pszObjId = (LPSTR)szOID_ENHANCED_KEY_USAGE;
            rgExt[n].fCritical = s->eku_critical ? TRUE : FALSE;
            rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
        }
        free(eku.rgpszUsageIdentifier);
    }

    if (s->want_ski && pSubjectPub) {
        BYTE *kid = NULL; DWORD kl = 0;
        compute_keyid(hProv, hashAlg, pSubjectPub, &kid, &kl);
        if (kid) {
            CRYPT_DATA_BLOB blob; blob.cbData = kl; blob.pbData = kid;
            BYTE *v = NULL; DWORD vl = 0;
            /* SKI value is a bare OCTET STRING of the key id */
            if (encode(X509_OCTET_STRING, &blob, &v, &vl) == 0) {
                rgExt[n].pszObjId = (LPSTR)szOID_SUBJECT_KEY_IDENTIFIER;
                rgExt[n].fCritical = FALSE;
                rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
            }
            free(kid);
        }
    }

    if (s->want_aki && pIssuerPub) {
        BYTE *kid = NULL; DWORD kl = 0;
        if (compute_keyid(hProv, hashAlg, pIssuerPub, &kid, &kl) == 0) {
            CERT_AUTHORITY_KEY_ID2_INFO aki; memset(&aki, 0, sizeof(aki));
            aki.KeyId.cbData = kl; aki.KeyId.pbData = kid;
            /* "issuer:always" adds the CA certificate's own issuer + serial */
            CERT_NAME_BLOB isuName; memset(&isuName, 0, sizeof(isuName));
            CERT_ALT_NAME_ENTRY isuEntry; memset(&isuEntry, 0, sizeof(isuEntry));
            BYTE *snLE = NULL; DWORD snLen = 0;
            int haveName = 0;
            if (s->aki_issuer_dn[0] && encode_name(s->aki_issuer_dn, &isuName) == 0) {
                isuEntry.dwAltNameChoice = CERT_ALT_NAME_DIRECTORY_NAME;
                isuEntry._empty_union_.DirectoryName = isuName;
                aki.AuthorityCertIssuer.cAltEntry = 1;
                aki.AuthorityCertIssuer.rgAltEntry = &isuEntry;
                haveName = 1;
            }
            if (s->aki_issuer_serial[0] &&
                parse_serial_le(s->aki_issuer_serial, &snLE, &snLen) == 0) {
                aki.AuthorityCertSerialNumber.cbData = snLen;
                aki.AuthorityCertSerialNumber.pbData = snLE;
            }
            BYTE *v = NULL; DWORD vl = 0;
            if (encode(X509_AUTHORITY_KEY_ID2, &aki, &v, &vl) == 0) {
                rgExt[n].pszObjId = (LPSTR)szOID_AUTHORITY_KEY_IDENTIFIER2;
                rgExt[n].fCritical = FALSE;
                rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
            }
            if (haveName) free(isuName.pbData);
            free(snLE);
            free(kid);
        }
    }

    /* subjectAltName */
    {
        CERT_ALT_NAME_ENTRY *entries = NULL; DWORD cnt = 0;
        build_altnames(s, &entries, &cnt);
        if (cnt > 0) {
            CERT_ALT_NAME_INFO ai; ai.cAltEntry = cnt; ai.rgAltEntry = entries;
            BYTE *v = NULL; DWORD vl = 0;
            if (encode(X509_ALTERNATE_NAME, &ai, &v, &vl) == 0) {
                rgExt[n].pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
                rgExt[n].fCritical = FALSE;
                rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
            }
        }
    }

    /* crlDistributionPoints (one dist point, full-name = the URIs) */
    if (s->cdp_n > 0) {
        CERT_ALT_NAME_ENTRY *e = (CERT_ALT_NAME_ENTRY *)calloc(s->cdp_n, sizeof(*e));
        for (int i = 0; i < s->cdp_n; i++) {
            e[i].dwAltNameChoice = CERT_ALT_NAME_URL;
            e[i]._empty_union_.pwszURL = to_wide(s->cdp[i]);
        }
        CRL_DIST_POINT dp; memset(&dp, 0, sizeof(dp));
        dp.DistPointName.dwDistPointNameChoice = CRL_DIST_POINT_FULL_NAME;
        dp.DistPointName._empty_union_.FullName.cAltEntry = s->cdp_n;
        dp.DistPointName._empty_union_.FullName.rgAltEntry = e;
        CRL_DIST_POINTS_INFO info; info.cDistPoint = 1; info.rgDistPoint = &dp;
        BYTE *v = NULL; DWORD vl = 0;
        if (encode(X509_CRL_DIST_POINTS, &info, &v, &vl) == 0) {
            rgExt[n].pszObjId = (LPSTR)szOID_CRL_DIST_POINTS;
            rgExt[n].fCritical = FALSE;
            rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
        }
    }

    /* authorityInfoAccess (caIssuers + OCSP) */
    if (s->aia_ca_n > 0 || s->aia_ocsp_n > 0) {
        int total = s->aia_ca_n + s->aia_ocsp_n;
        CERT_ACCESS_DESCRIPTION *ad = (CERT_ACCESS_DESCRIPTION *)calloc(total, sizeof(*ad));
        int i = 0;
        for (int k = 0; k < s->aia_ca_n; k++) {
            ad[i].pszAccessMethod = (LPSTR)szOID_PKIX_CA_ISSUERS;
            ad[i].AccessLocation.dwAltNameChoice = CERT_ALT_NAME_URL;
            ad[i].AccessLocation._empty_union_.pwszURL = to_wide(s->aia_ca[k]); i++;
        }
        for (int k = 0; k < s->aia_ocsp_n; k++) {
            ad[i].pszAccessMethod = (LPSTR)szOID_PKIX_OCSP;
            ad[i].AccessLocation.dwAltNameChoice = CERT_ALT_NAME_URL;
            ad[i].AccessLocation._empty_union_.pwszURL = to_wide(s->aia_ocsp[k]); i++;
        }
        CERT_AUTHORITY_INFO_ACCESS aia; aia.cAccDescr = i; aia.rgAccDescr = ad;
        BYTE *v = NULL; DWORD vl = 0;
        if (encode(X509_AUTHORITY_INFO_ACCESS, &aia, &v, &vl) == 0) {
            rgExt[n].pszObjId = (LPSTR)szOID_AUTHORITY_INFO_ACCESS;
            rgExt[n].fCritical = FALSE;
            rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
        }
    }

    /* subjectInfoAccess (caRepository) — RFC 5280 §4.2.2.2. Same ASN.1 shape as
     * AIA, only the extension and access-method OIDs differ. */
    if (s->sia_repo_n > 0) {
        CERT_ACCESS_DESCRIPTION *ad =
            (CERT_ACCESS_DESCRIPTION *)calloc(s->sia_repo_n, sizeof(*ad));
        for (int k = 0; k < s->sia_repo_n; k++) {
            ad[k].pszAccessMethod = (LPSTR)szOID_PKIX_CA_REPOSITORY;
            ad[k].AccessLocation.dwAltNameChoice = CERT_ALT_NAME_URL;
            ad[k].AccessLocation._empty_union_.pwszURL = to_wide(s->sia_repo[k]);
        }
        CERT_AUTHORITY_INFO_ACCESS sia; sia.cAccDescr = s->sia_repo_n; sia.rgAccDescr = ad;
        BYTE *v = NULL; DWORD vl = 0;
        if (encode(X509_AUTHORITY_INFO_ACCESS, &sia, &v, &vl) == 0) {
            rgExt[n].pszObjId = (LPSTR)szOID_SUBJECT_INFO_ACCESS;
            rgExt[n].fCritical = FALSE;
            rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
        }
    }

    /* freshestCRL (delta-CRL pointer) — RFC 5280 §4.2.1.15. Encoded exactly
     * like a CDP; only the extension OID differs. */
    if (s->freshest_crl_n > 0) {
        CERT_ALT_NAME_ENTRY *e =
            (CERT_ALT_NAME_ENTRY *)calloc(s->freshest_crl_n, sizeof(*e));
        for (int i = 0; i < s->freshest_crl_n; i++) {
            e[i].dwAltNameChoice = CERT_ALT_NAME_URL;
            e[i]._empty_union_.pwszURL = to_wide(s->freshest_crl[i]);
        }
        CRL_DIST_POINT dp; memset(&dp, 0, sizeof(dp));
        dp.DistPointName.dwDistPointNameChoice = CRL_DIST_POINT_FULL_NAME;
        dp.DistPointName._empty_union_.FullName.cAltEntry = s->freshest_crl_n;
        dp.DistPointName._empty_union_.FullName.rgAltEntry = e;
        CRL_DIST_POINTS_INFO info; info.cDistPoint = 1; info.rgDistPoint = &dp;
        BYTE *v = NULL; DWORD vl = 0;
        if (encode(X509_CRL_DIST_POINTS, &info, &v, &vl) == 0) {
            rgExt[n].pszObjId = (LPSTR)szOID_FRESHEST_CRL;
            rgExt[n].fCritical = FALSE;
            rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
        }
    }

    /* issuerAltName — RFC 5280 §4.2.1.7 */
    {
        CERT_ALT_NAME_ENTRY *entries = NULL; DWORD cnt = 0;
        build_altname_entries(s->ian_dns, s->ian_dns_n,
                              s->ian_email, s->ian_email_n,
                              s->ian_uri, s->ian_uri_n,
                              s->ian_ip, s->ian_ip_n, &entries, &cnt);
        if (cnt > 0) {
            CERT_ALT_NAME_INFO ai; ai.cAltEntry = cnt; ai.rgAltEntry = entries;
            BYTE *v = NULL; DWORD vl = 0;
            if (encode(X509_ALTERNATE_NAME, &ai, &v, &vl) == 0) {
                rgExt[n].pszObjId = (LPSTR)szOID_ISSUER_ALT_NAME2;
                rgExt[n].fCritical = FALSE;
                rgExt[n].Value.cbData = vl; rgExt[n].Value.pbData = v; n++;
            }
        }
    }

    return n;
}

/* ---- subcommands -------------------------------------------------------- */

static int cmd_info(void) {
    printf("{\"shim\":\"ownca_capi\",\"ok\":true}\n");
    return 0;
}

/* paramsets: the key paramsets this provider actually supports, as raw OIDs.
 * own_ca.py's GOST_PARAMSET_CHOICES_* describe what gost-engine offers; the
 * certified provider's list is its own, so the issue form must ask rather than
 * assume — offering a set the provider will refuse is a dead option. */
static int cmd_paramsets(int argc, char **argv) {
    const char *alg = opt(argc, argv, "--alg");
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, NULL, NULL, prov_type_for(alg),
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        return fail("CryptAcquireContext");
    printf("{\"alg\":\"%s\",\"oids\":[", alg ? alg : "gost2012_256");
    BYTE buf[512];
    DWORD flags = CRYPT_FIRST;
    int n = 0;
    for (;;) {
        DWORD cb = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        if (!CryptGetProvParam(hProv, PP_ENUM_SIGNATUREOID, buf, &cb, flags))
            break;
        printf("%s\"%s\"", n ? "," : "", (char *)buf);
        n++;
        flags = CRYPT_NEXT;
    }
    printf("],\"ok\":true}\n");
    CryptReleaseContext(hProv, 0);
    return 0;
}

/* Delete a key container (CryptAcquireContext CRYPT_DELETEKEYSET).
 *
 * The provider type is part of a container's identity, and an imported
 * container ('pfx-<guid>') carries whichever one PFXImportCertStore chose, so
 * --alg is only a hint: both GOST provider types are tried before giving up.
 * A container that is already gone is reported as deleted:false with exit 0 —
 * cleanup runs on paths where the container may never have been created, and
 * has to stay idempotent. Any other provider error is a real failure. */
static int cmd_delcontainer(int argc, char **argv) {
    const char *cont = opt(argc, argv, "--container");
    const char *alg  = opt(argc, argv, "--alg");
    if (!cont) { fprintf(stderr, "ownca_capi: delcontainer needs --container\n"); return 2; }

    DWORD first = prov_type_for(alg);
    DWORD provs[2] = { first,
                       first == PROV_GOST_2012_512 ? PROV_GOST_2012_256
                                                   : PROV_GOST_2012_512 };
    DWORD last_err = 0;
    for (int i = 0; i < 2; i++) {
        HCRYPTPROV hProv = 0;
        /* On success the handle is undefined and must NOT be released. */
        if (CryptAcquireContextA(&hProv, cont, NULL, provs[i],
                                 CRYPT_DELETEKEYSET | CRYPT_SILENT)) {
            printf("{\"container\":\"%s\",\"provtype\":%u,\"deleted\":true,\"ok\":true}\n",
                   cont, (unsigned)provs[i]);
            return 0;
        }
        last_err = GetLastError();
        if (last_err != (DWORD)NTE_BAD_KEYSET && last_err != (DWORD)NTE_KEYSET_NOT_DEF)
            return fail("CryptAcquireContext(CRYPT_DELETEKEYSET)");
    }
    fprintf(stderr, "ownca_capi: container '%s' not found (0x%08X)\n",
            cont, (unsigned)last_err);
    printf("{\"container\":\"%s\",\"deleted\":false,\"ok\":true}\n", cont);
    return 0;
}

static int cmd_genkey(int argc, char **argv) {
    const char *cont = opt(argc, argv, "--container");
    const char *alg  = opt(argc, argv, "--alg");
    const char *ps   = opt(argc, argv, "--paramset");
    if (!cont) { fprintf(stderr, "ownca_capi: genkey needs --container\n"); return 2; }

    /* An explicit paramset is selected on the PROVIDER, before the key is
     * generated: CryptSetProvParam(PP_SIGNATUREOID) then CryptGenKey, which is
     * what this CSP accepts (the deferred CRYPT_PREGEN + KP_SIGNATUREOID idiom
     * returns NTE_BAD_FLAGS for AT_SIGNATURE here). Without --paramset the call
     * is exactly what it always was, so the provider default still applies. An
     * unknown name is refused outright — generating with the default while the
     * operator asked for something else is the silent misissue this prevents.
     * The provider's own supported list is readable via PP_ENUM_SIGNATUREOID. */
    const char *psOid = NULL;
    if (ps && *ps) {
        psOid = paramset_oid_for(alg, ps);
        if (!psOid) {
            fprintf(stderr, "ownca_capi: unsupported paramset '%s' for %s\n",
                    ps, alg ? alg : "gost2012_256");
            return 2;
        }
    }

    DWORD prov = prov_type_for(alg);
    HCRYPTPROV hProv = 0; HCRYPTKEY hKey = 0;
    if (!CryptAcquireContextA(&hProv, cont, NULL, prov, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
        if (!CryptAcquireContextA(&hProv, cont, NULL, prov, CRYPT_SILENT))
            return fail("CryptAcquireContext");
    }
    if (psOid && !CryptSetProvParam(hProv, PP_SIGNATUREOID, (const BYTE *)psOid, 0)) {
        fprintf(stderr, "ownca_capi: paramset %s (%s) rejected by the provider: "
                "0x%08X\n", ps, psOid, (unsigned)GetLastError());
        CryptReleaseContext(hProv, 0); return 1;
    }
    /* CRYPT_EXPORTABLE: the dashboard promises PKCS#12 export for both CAs
     * and end-entity certs (parity with the openssl backend, whose keys live
     * as PEM files). A non-exportable key would make PFXExportCertStoreEx
     * silently emit a cert-only PFX. */
    if (!CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKey)) {
        if (GetLastError() != (DWORD)NTE_EXISTS) {
            err("CryptGenKey"); CryptReleaseContext(hProv, 0); return 1;
        }
        /* container already holds a key: leave it (and its paramset) alone */
        hKey = 0;
    }
    if (hKey) CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    printf("{\"container\":\"%s\",\"paramset\":\"%s\",\"ok\":true}\n",
           cont, ps ? ps : "");
    return 0;
}

/* Export the AT_SIGNATURE public key info from an open provider (malloc'd). */
static PCERT_PUBLIC_KEY_INFO export_pub(HCRYPTPROV hProv) {
    DWORD cb = 0;
    if (!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, NULL, &cb))
        return NULL;
    PCERT_PUBLIC_KEY_INFO p = (PCERT_PUBLIC_KEY_INFO)malloc(cb);
    if (!p) return NULL;
    if (!CryptExportPublicKeyInfo(hProv, AT_SIGNATURE, X509_ASN_ENCODING, p, &cb)) {
        free(p); return NULL;
    }
    return p;
}

/* Shared cert builder: signs CERT_INFO with hProvCA's key. subjectPub is placed
 * in the cert; issuerName/subjectName are pre-encoded blobs. */
static int sign_cert(HCRYPTPROV hProvCA, const char *alg, ExtSpec *spec,
                     PCERT_PUBLIC_KEY_INFO pSubjectPub, PCERT_PUBLIC_KEY_INFO pIssuerPub,
                     CERT_NAME_BLOB issuer, CERT_NAME_BLOB subject,
                     const char *serial, long days, const char *out) {
    const char *oid = sign_oid_for(alg);
    ALG_ID hashAlg = hash_alg_for(alg);
    BYTE *serialLE = NULL; DWORD serialLen = 0;
    if (parse_serial_le(serial, &serialLE, &serialLen) != 0) {
        fprintf(stderr, "ownca_capi: bad --serial\n"); return 1;
    }
    CERT_EXTENSION rgExt[MAX_EXT]; memset(rgExt, 0, sizeof(rgExt));
    int nExt = 0;
    if (spec) nExt = build_extensions(spec, hProvCA, hashAlg, pSubjectPub, pIssuerPub, rgExt);

    CERT_INFO ci; memset(&ci, 0, sizeof(ci));
    ci.dwVersion = CERT_V3;
    ci.SerialNumber.cbData = serialLen; ci.SerialNumber.pbData = serialLE;
    ci.SignatureAlgorithm.pszObjId = (LPSTR)oid;
    ci.Issuer = issuer; ci.Subject = subject;
    ci.NotBefore = unix_to_ft(time(NULL) - 300);
    ci.NotAfter  = unix_to_ft(time(NULL) + (time_t)days * 24 * 3600);
    ci.SubjectPublicKeyInfo = *pSubjectPub;
    ci.cExtension = nExt; ci.rgExtension = nExt ? rgExt : NULL;

    CRYPT_ALGORITHM_IDENTIFIER sigAlg; memset(&sigAlg, 0, sizeof(sigAlg));
    sigAlg.pszObjId = (LPSTR)oid;

    DWORD cbCert = 0; int rc = 1; BYTE *cert = NULL;
    if (!CryptSignAndEncodeCertificate(hProvCA, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED, &ci, &sigAlg, NULL, NULL, &cbCert)) {
        err("CryptSignAndEncodeCertificate(size)"); goto done;
    }
    cert = (BYTE *)malloc(cbCert);
    if (!cert) goto done;
    if (!CryptSignAndEncodeCertificate(hProvCA, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_TO_BE_SIGNED, &ci, &sigAlg, NULL, cert, &cbCert)) {
        err("CryptSignAndEncodeCertificate"); goto done;
    }
    if (write_file(out, cert, cbCert) != 0) goto done;
    printf("{\"out\":\"%s\",\"bytes\":%u,\"ext\":%d,\"ok\":true}\n",
           out, (unsigned)cbCert, nExt);
    rc = 0;
done:
    free(cert); free(serialLE);
    for (int i = 0; i < nExt; i++) free(rgExt[i].Value.pbData);
    return rc;
}

/* gencsr: build a PKCS#10 for a key already sitting in a container, signed by
 * that key. The CryptoPro issue path takes the subject key straight from its
 * container, so this request is never needed to *make* the certificate — it
 * exists so a server-generated cert leaves the same `csr.pem` on disk that the
 * openssl backend writes (downloads, renew, storage contract). */
static int cmd_gencsr(int argc, char **argv) {
    const char *cont    = opt(argc, argv, "--container");
    const char *subject = opt(argc, argv, "--subject");
    const char *alg     = opt(argc, argv, "--alg");
    const char *out     = opt(argc, argv, "--out");
    if (!cont || !subject || !out) {
        fprintf(stderr, "ownca_capi: gencsr needs --container --subject --out\n");
        return 2;
    }
    const char *oid = sign_oid_for(alg);
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, cont, NULL, prov_type_for(alg), CRYPT_SILENT))
        return fail("CryptAcquireContext");

    int rc = 1; BYTE *csr = NULL;
    PCERT_PUBLIC_KEY_INFO pPub = export_pub(hProv);
    if (!pPub) { err("export_pub"); goto done; }

    CERT_NAME_BLOB subjName;
    if (encode_name(subject, &subjName) != 0) { err("CertStrToName(subject)"); goto done; }

    CERT_REQUEST_INFO req; memset(&req, 0, sizeof(req));
    req.dwVersion = CERT_REQUEST_V1;
    req.Subject = subjName;
    req.SubjectPublicKeyInfo = *pPub;
    req.cAttribute = 0; req.rgAttribute = NULL;

    CRYPT_ALGORITHM_IDENTIFIER sigAlg; memset(&sigAlg, 0, sizeof(sigAlg));
    sigAlg.pszObjId = (LPSTR)oid;

    DWORD cb = 0;
    if (!CryptSignAndEncodeCertificate(hProv, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED, &req, &sigAlg, NULL, NULL, &cb)) {
        err("CryptSignAndEncodeCertificate(CSR size)"); goto done;
    }
    csr = (BYTE *)malloc(cb);
    if (!csr) goto done;
    if (!CryptSignAndEncodeCertificate(hProv, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED, &req, &sigAlg, NULL, csr, &cb)) {
        err("CryptSignAndEncodeCertificate(CSR)"); goto done;
    }
    if (write_file(out, csr, cb) != 0) goto done;
    printf("{\"out\":\"%s\",\"bytes\":%u,\"ok\":true}\n", out, (unsigned)cb);
    rc = 0;
done:
    free(csr); free(pPub);
    CryptReleaseContext(hProv, 0);
    return rc;
}

static int cmd_selfsign(int argc, char **argv) {
    const char *cont = opt(argc, argv, "--container");
    const char *subject = opt(argc, argv, "--subject");
    const char *alg = opt(argc, argv, "--alg");
    const char *out = opt(argc, argv, "--out");
    const char *serial = opt(argc, argv, "--serial");
    const char *days_s = opt(argc, argv, "--days");
    const char *extspec = opt(argc, argv, "--extspec");
    if (!cont || !subject || !out) {
        fprintf(stderr, "ownca_capi: selfsign needs --container --subject --out\n");
        return 2;
    }
    long days = days_s ? strtol(days_s, NULL, 10) : 3650;
    if (days <= 0) days = 3650;

    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextA(&hProv, cont, NULL, prov_type_for(alg), CRYPT_SILENT))
        return fail("CryptAcquireContext(open)");
    PCERT_PUBLIC_KEY_INFO pPub = export_pub(hProv);
    if (!pPub) { err("CryptExportPublicKeyInfo"); CryptReleaseContext(hProv, 0); return 1; }

    CERT_NAME_BLOB name;
    if (encode_name(subject, &name) != 0) { err("CertStrToName"); return 1; }

    ExtSpec spec; ExtSpec *ps = NULL;
    if (extspec) { spec_init(&spec); if (parse_extspec(extspec, &spec) == 0) ps = &spec; }

    /* self-signed: issuer == subject; SKI + AKI both from this key */
    int rc = sign_cert(hProv, alg, ps, pPub, pPub, name, name, serial, days, out);
    CryptReleaseContext(hProv, 0);
    return rc;
}

static int cmd_issue(int argc, char **argv) {
    const char *ca_cont   = opt(argc, argv, "--container");
    const char *subj_cont = opt(argc, argv, "--subject-container");
    const char *subject   = opt(argc, argv, "--subject");
    const char *issuer    = opt(argc, argv, "--issuer");
    const char *alg       = opt(argc, argv, "--alg");
    const char *out       = opt(argc, argv, "--out");
    const char *serial    = opt(argc, argv, "--serial");
    const char *days_s    = opt(argc, argv, "--days");
    const char *extspec   = opt(argc, argv, "--extspec");
    if (!ca_cont || !subj_cont || !subject || !issuer || !out) {
        fprintf(stderr, "ownca_capi: issue needs --container --subject-container "
                        "--subject --issuer --out\n");
        return 2;
    }
    long days = days_s ? strtol(days_s, NULL, 10) : 365;
    if (days <= 0) days = 365;
    /* --alg is the CA's algorithm (signature OID + CA provider type);
     * --subject-alg the subject container's (defaults to the CA's). */
    const char *salg = opt(argc, argv, "--subject-alg");
    if (!salg) salg = alg;

    HCRYPTPROV hCA = 0, hSubj = 0;
    if (!CryptAcquireContextA(&hCA, ca_cont, NULL, prov_type_for(alg), CRYPT_SILENT))
        return fail("CryptAcquireContext(CA)");
    if (!CryptAcquireContextA(&hSubj, subj_cont, NULL, prov_type_for(salg), CRYPT_SILENT)) {
        err("CryptAcquireContext(subject)"); CryptReleaseContext(hCA, 0); return 1;
    }
    PCERT_PUBLIC_KEY_INFO pSubjPub = export_pub(hSubj);
    PCERT_PUBLIC_KEY_INFO pCaPub   = export_pub(hCA);
    int rc = 1;
    if (!pSubjPub || !pCaPub) { err("export_pub"); goto done; }

    CERT_NAME_BLOB subjName, issName;
    if (encode_name(subject, &subjName) != 0) { err("CertStrToName(subject)"); goto done; }
    if (encode_name(issuer, &issName) != 0) { err("CertStrToName(issuer)"); goto done; }

    ExtSpec spec; ExtSpec *ps = NULL;
    if (extspec) { spec_init(&spec); if (parse_extspec(extspec, &spec) == 0) ps = &spec; }

    /* signed by the CA key; SKI from subject key, AKI from CA key */
    rc = sign_cert(hCA, alg, ps, pSubjPub, pCaPub, issName, subjName, serial, days, out);
done:
    if (hSubj) CryptReleaseContext(hSubj, 0);
    if (hCA) CryptReleaseContext(hCA, 0);
    return rc;
}

/* issuecsr: issue a certificate for an EXTERNAL PKCS#10 request. The subject
 * public key is taken from the CSR (no subject container involved); the CSR's
 * self-signature is verified first so we never certify a key the requester
 * does not control. Subject DN defaults to the CSR's own; --subject overrides. */
static int cmd_issuecsr(int argc, char **argv) {
    const char *ca_cont = opt(argc, argv, "--container");
    const char *csrf    = opt(argc, argv, "--csr");
    const char *subject = opt(argc, argv, "--subject");   /* optional override */
    const char *issuer  = opt(argc, argv, "--issuer");
    const char *alg     = opt(argc, argv, "--alg");
    const char *out     = opt(argc, argv, "--out");
    const char *serial  = opt(argc, argv, "--serial");
    const char *days_s  = opt(argc, argv, "--days");
    const char *extspec = opt(argc, argv, "--extspec");
    if (!ca_cont || !csrf || !issuer || !out) {
        fprintf(stderr, "ownca_capi: issuecsr needs --container --csr --issuer --out\n");
        return 2;
    }
    long days = days_s ? strtol(days_s, NULL, 10) : 365;
    if (days <= 0) days = 365;

    DWORD csrLen = 0;
    BYTE *csr = read_file(csrf, &csrLen);
    if (!csr) { fprintf(stderr, "ownca_capi: cannot read --csr\n"); return 1; }

    int rc = 1;
    CERT_SIGNED_CONTENT_INFO *sci = NULL;
    CERT_REQUEST_INFO *req = NULL;
    HCRYPTPROV hCA = 0, hVerify = 0;
    PCERT_PUBLIC_KEY_INFO pCaPub = NULL;

    /* outer SEQUENCE { tbs, sigAlg, sig } then the inner CertificationRequestInfo */
    if (decode_alloc(X509_CERT, csr, csrLen, (void **)&sci) != 0) {
        err("CryptDecodeObject(CSR outer)"); goto done;
    }
    if (decode_alloc(X509_CERT_REQUEST_TO_BE_SIGNED,
                     sci->ToBeSigned.pbData, sci->ToBeSigned.cbData,
                     (void **)&req) != 0) {
        err("CryptDecodeObject(CSR request)"); goto done;
    }

    /* Verify the CSR self-signature with a provider matching the CSR key's
     * own algorithm (which may differ from the CA's, e.g. 256 vs 512). */
    const char *csr_alg = alg_for_pubkey_oid(req->SubjectPublicKeyInfo.Algorithm.pszObjId);
    if (!CryptAcquireContextA(&hVerify, NULL, NULL, prov_type_for(csr_alg),
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        err("CryptAcquireContext(verify)"); goto done;
    }
    if (!CryptVerifyCertificateSignature(hVerify, X509_ASN_ENCODING, csr, csrLen,
                                         &req->SubjectPublicKeyInfo)) {
        fprintf(stderr, "ownca_capi: CSR signature verification failed: 0x%08X\n",
                (unsigned)GetLastError());
        goto done;
    }

    if (!CryptAcquireContextA(&hCA, ca_cont, NULL, prov_type_for(alg), CRYPT_SILENT)) {
        err("CryptAcquireContext(CA)"); goto done;
    }
    pCaPub = export_pub(hCA);
    if (!pCaPub) { err("export_pub(CA)"); goto done; }

    CERT_NAME_BLOB issName, subjName;
    if (encode_name(issuer, &issName) != 0) { err("CertStrToName(issuer)"); goto done; }
    if (subject) {
        if (encode_name(subject, &subjName) != 0) { err("CertStrToName(subject)"); goto done; }
    } else {
        subjName = req->Subject;   /* byte-exact DN from the CSR */
    }

    ExtSpec spec; ExtSpec *ps = NULL;
    if (extspec) { spec_init(&spec); if (parse_extspec(extspec, &spec) == 0) ps = &spec; }

    /* signed by the CA key; SKI from the CSR public key, AKI from the CA key */
    rc = sign_cert(hCA, alg, ps, &req->SubjectPublicKeyInfo, pCaPub,
                   issName, subjName, serial, days, out);
done:
    if (hVerify) CryptReleaseContext(hVerify, 0);
    if (hCA) CryptReleaseContext(hCA, 0);
    free(pCaPub); free(req); free(sci); free(csr);
    return rc;
}

/* gencrl: sign a CRL with the CA container key. Revoked entries come from a
 * --revoked file, one per line: "serialhex[,unixtime[,reasoncode]]". */
static int cmd_gencrl(int argc, char **argv) {
    const char *ca_cont = opt(argc, argv, "--container");
    const char *issuer  = opt(argc, argv, "--issuer");
    const char *alg     = opt(argc, argv, "--alg");
    const char *out     = opt(argc, argv, "--out");
    const char *days_s  = opt(argc, argv, "--days");
    const char *revoked = opt(argc, argv, "--revoked");
    const char *crlnum  = opt(argc, argv, "--crlnumber");
    if (!ca_cont || !issuer || !out) {
        fprintf(stderr, "ownca_capi: gencrl needs --container --issuer --out\n");
        return 2;
    }
    long days = days_s ? strtol(days_s, NULL, 10) : 7;
    if (days <= 0) days = 7;
    const char *oid = sign_oid_for(alg);

    HCRYPTPROV hCA = 0;
    if (!CryptAcquireContextA(&hCA, ca_cont, NULL, prov_type_for(alg), CRYPT_SILENT))
        return fail("CryptAcquireContext(CA)");

    CERT_NAME_BLOB issName;
    if (encode_name(issuer, &issName) != 0) { err("CertStrToName(issuer)"); CryptReleaseContext(hCA,0); return 1; }

    /* revoked entries */
    CRL_ENTRY *entries = NULL; int nEntry = 0;
    BYTE **entrySerials = NULL;
    CERT_EXTENSION **entryExts = NULL;   /* per-entry reasonCode, or NULL */
    if (revoked) {
        FILE *f = fopen(revoked, "r");
        if (f) {
            char line[512];
            entries = (CRL_ENTRY *)calloc(4096, sizeof(*entries));
            entrySerials = (BYTE **)calloc(4096, sizeof(BYTE *));
            entryExts = (CERT_EXTENSION **)calloc(4096, sizeof(CERT_EXTENSION *));
            while (fgets(line, sizeof(line), f) && nEntry < 4096) {
                char *nl = strpbrk(line, "\r\n"); if (nl) *nl = 0;
                if (!line[0] || line[0] == '#') continue;
                char *c1 = strchr(line, ',');
                char *c2 = NULL;
                if (c1) { *c1 = 0; c2 = strchr(c1 + 1, ','); if (c2) *c2 = 0; }
                time_t rt = c1 ? (time_t)strtoll(c1 + 1, NULL, 10) : time(NULL);
                BYTE *sn = NULL; DWORD snl = 0;
                if (parse_serial_le(line, &sn, &snl) != 0) continue;
                entrySerials[nEntry] = sn;
                entries[nEntry].SerialNumber.cbData = snl;
                entries[nEntry].SerialNumber.pbData = sn;
                entries[nEntry].RevocationDate = unix_to_ft(rt);
                /* Optional third field: the RFC 5280 reasonCode. An ABSENT
                 * field means "no reason recorded" and yields no extension at
                 * all — mirroring an openssl revocation without -crl_reason,
                 * so we never assert `unspecified` on the operator's behalf. */
                if (c2 && c2[1]) {
                    int reason = (int)strtol(c2 + 1, NULL, 10);
                    BYTE *v = NULL; DWORD vl = 0;
                    if (encode(X509_CRL_REASON_CODE, &reason, &v, &vl) == 0) {
                        CERT_EXTENSION *ex = (CERT_EXTENSION *)calloc(1, sizeof(*ex));
                        if (ex) {
                            ex->pszObjId = (LPSTR)szOID_CRL_REASON_CODE;
                            ex->fCritical = FALSE;
                            ex->Value.cbData = vl; ex->Value.pbData = v;
                            entryExts[nEntry] = ex;
                            entries[nEntry].cExtension = 1;
                            entries[nEntry].rgExtension = ex;
                        } else {
                            free(v);
                        }
                    }
                }
                nEntry++;
            }
            fclose(f);
        }
    }

    /* optional crlNumber extension */
    CERT_EXTENSION rgExt[2]; memset(rgExt, 0, sizeof(rgExt)); int nExt = 0;
    if (crlnum) {
        BYTE *num = NULL; DWORD numl = 0;
        if (hex2bin(crlnum, &num, &numl) == 0) {
            /* store big-endian bytes as a multi-byte integer blob */
            CRYPT_INTEGER_BLOB ib; ib.cbData = numl; ib.pbData = num;
            BYTE *v = NULL; DWORD vl = 0;
            if (encode(X509_MULTI_BYTE_INTEGER, &ib, &v, &vl) == 0) {
                rgExt[nExt].pszObjId = (LPSTR)szOID_CRL_NUMBER;
                rgExt[nExt].fCritical = FALSE;
                rgExt[nExt].Value.cbData = vl; rgExt[nExt].Value.pbData = v; nExt++;
            }
        }
    }

    CRL_INFO ci; memset(&ci, 0, sizeof(ci));
    ci.dwVersion = CRL_V2;
    ci.SignatureAlgorithm.pszObjId = (LPSTR)oid;
    ci.Issuer = issName;
    ci.ThisUpdate = unix_to_ft(time(NULL) - 300);
    ci.NextUpdate = unix_to_ft(time(NULL) + (time_t)days * 24 * 3600);
    ci.cCRLEntry = nEntry; ci.rgCRLEntry = nEntry ? entries : NULL;
    ci.cExtension = nExt; ci.rgExtension = nExt ? rgExt : NULL;

    CRYPT_ALGORITHM_IDENTIFIER sigAlg; memset(&sigAlg, 0, sizeof(sigAlg));
    sigAlg.pszObjId = (LPSTR)oid;

    DWORD cb = 0; int rc = 1; BYTE *crl = NULL;
    if (!CryptSignAndEncodeCertificate(hCA, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_CRL_TO_BE_SIGNED, &ci, &sigAlg, NULL, NULL, &cb)) {
        err("CryptSignAndEncodeCertificate(CRL size)"); goto done;
    }
    crl = (BYTE *)malloc(cb);
    if (!crl) goto done;
    if (!CryptSignAndEncodeCertificate(hCA, AT_SIGNATURE, X509_ASN_ENCODING,
            X509_CERT_CRL_TO_BE_SIGNED, &ci, &sigAlg, NULL, crl, &cb)) {
        err("CryptSignAndEncodeCertificate(CRL)"); goto done;
    }
    if (write_file(out, crl, cb) != 0) goto done;
    printf("{\"out\":\"%s\",\"bytes\":%u,\"revoked\":%d,\"ok\":true}\n",
           out, (unsigned)cb, nEntry);
    rc = 0;
done:
    free(crl);
    for (int i = 0; i < nExt; i++) free(rgExt[i].Value.pbData);
    for (int i = 0; i < nEntry; i++) {
        free(entrySerials ? entrySerials[i] : NULL);
        if (entryExts && entryExts[i]) {
            free(entryExts[i]->Value.pbData);
            free(entryExts[i]);
        }
    }
    free(entries); free(entrySerials); free(entryExts);
    CryptReleaseContext(hCA, 0);
    return rc;
}

/* exportpfx: bundle a cert + its container private key into a PKCS#12/PFX. */
static int cmd_exportpfx(int argc, char **argv) {
    const char *cont = opt(argc, argv, "--container");
    const char *certf = opt(argc, argv, "--cert");
    const char *pw = opt(argc, argv, "--password");
    const char *alg = opt(argc, argv, "--alg");
    const char *out = opt(argc, argv, "--out");
    if (!cont || !certf || !out) {
        fprintf(stderr, "ownca_capi: exportpfx needs --container --cert --out\n");
        return 2;
    }
    DWORD certLen = 0;
    BYTE *certDer = read_file(certf, &certLen);
    if (!certDer) { fprintf(stderr, "ownca_capi: cannot read --cert\n"); return 1; }

    int rc = 1;
    HCRYPTPROV hProv = 0;   /* not opened here — prop info names the container */
    (void)hProv;
    HCERTSTORE store = 0;
    PCCERT_CONTEXT ctx = CertCreateCertificateContext(X509_ASN_ENCODING, certDer, certLen);
    if (!ctx) { err("CertCreateCertificateContext"); goto done; }

    CRYPT_KEY_PROV_INFO kpi; memset(&kpi, 0, sizeof(kpi));
    wchar_t *wcont = to_wide(cont);
    kpi.pwszContainerName = wcont;
    kpi.pwszProvName = NULL;               /* default GOST provider */
    kpi.dwProvType = prov_type_for(alg);
    kpi.dwFlags = CRYPT_SILENT;
    kpi.dwKeySpec = AT_SIGNATURE;
    if (!CertSetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi)) {
        err("CertSetCertificateContextProperty"); goto done;
    }

    store = CertOpenStore((LPCSTR)CERT_STORE_PROV_MEMORY, 0, 0,
                          CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!store) { err("CertOpenStore"); goto done; }
    if (!CertAddCertificateContextToStore(store, ctx, CERT_STORE_ADD_ALWAYS, NULL)) {
        err("CertAddCertificateContextToStore"); goto done;
    }

    /* Optional parent-chain certs: added WITHOUT key-prov-info, so only the
     * primary cert carries a private key in the PFX. Repeatable option. */
    for (int i = 2; i + 1 < argc; i++) {
        if (strcmp(argv[i], "--chain") != 0) continue;
        DWORD clen = 0;
        BYTE *cder = read_file(argv[i + 1], &clen);
        if (!cder) {
            fprintf(stderr, "ownca_capi: cannot read --chain %s\n", argv[i + 1]);
            goto done;
        }
        PCCERT_CONTEXT cctx = CertCreateCertificateContext(X509_ASN_ENCODING, cder, clen);
        free(cder);
        if (!cctx) { err("CertCreateCertificateContext(chain)"); goto done; }
        BOOL added = CertAddCertificateContextToStore(store, cctx, CERT_STORE_ADD_ALWAYS, NULL);
        CertFreeCertificateContext(cctx);
        if (!added) { err("CertAddCertificateContextToStore(chain)"); goto done; }
    }

    /* REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY: fail loudly if the container key
     * cannot be exported (e.g. a pre-fix non-exportable key) instead of
     * silently producing a cert-only PFX. REPORT_NO_PRIVATE_KEY is NOT set —
     * the --chain certs legitimately carry no key. */
    const DWORD pfxFlags = EXPORT_PRIVATE_KEYS | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY;
    wchar_t *wpw = to_wide(pw ? pw : "");
    CRYPT_DATA_BLOB pfx; memset(&pfx, 0, sizeof(pfx));
    if (!PFXExportCertStoreEx(store, &pfx, wpw, NULL, pfxFlags)) {
        err("PFXExportCertStoreEx(size)"); goto done;
    }
    pfx.pbData = (BYTE *)malloc(pfx.cbData);
    if (!pfx.pbData) goto done;
    if (!PFXExportCertStoreEx(store, &pfx, wpw, NULL, pfxFlags)) {
        err("PFXExportCertStoreEx"); free(pfx.pbData); goto done;
    }
    if (write_file(out, pfx.pbData, pfx.cbData) == 0) {
        printf("{\"out\":\"%s\",\"bytes\":%u,\"ok\":true}\n", out, (unsigned)pfx.cbData);
        rc = 0;
    }
    free(pfx.pbData);
done:
    if (store) CertCloseStore(store, 0);
    if (ctx) CertFreeCertificateContext(ctx);
    free(certDer);
    return rc;
}

/* importpfx: import a PFX blob — keys land in CryptoPro containers (never on
 * disk). Reports the key-owning cert (DER to --out) + its container/prov/subject. */
static int cmd_importpfx(int argc, char **argv) {
    const char *pfxf = opt(argc, argv, "--pfx");
    const char *pw   = opt(argc, argv, "--password");
    const char *out  = opt(argc, argv, "--out");
    if (!pfxf || !out) {
        fprintf(stderr, "ownca_capi: importpfx needs --pfx --out\n");
        return 2;
    }
    CRYPT_DATA_BLOB blob;
    blob.pbData = read_file(pfxf, &blob.cbData);
    if (!blob.pbData) { fprintf(stderr, "ownca_capi: cannot read --pfx\n"); return 1; }

    int rc = 1;
    HCERTSTORE store = 0;
    PCCERT_CONTEXT ctx = NULL;
    CRYPT_KEY_PROV_INFO *kpi = NULL;
    wchar_t *wpw = to_wide(pw ? pw : "");

    if (!PFXIsPFXBlob(&blob)) {
        fprintf(stderr, "ownca_capi: not a PFX/PKCS#12 blob\n");
        goto done;
    }
    if (!PFXVerifyPassword(&blob, wpw, 0)) {
        fprintf(stderr, "ownca_capi: PFX password is wrong\n");
        goto done;
    }
    /* CRYPT_EXPORTABLE keeps the imported key exportable (so a later PKCS#12
     * export of this CA works); PKCS12_IMPORT_SILENT (CryptoPro) suppresses
     * the interactive container-password prompt on headless boxes. */
    store = PFXImportCertStore(&blob, wpw, CRYPT_EXPORTABLE | PKCS12_IMPORT_SILENT);
    if (!store) { err("PFXImportCertStore"); goto done; }

    /* Find the cert that owns a private key (CERT_KEY_PROV_INFO set by import). */
    while ((ctx = CertEnumCertificatesInStore(store, ctx)) != NULL) {
        DWORD cb = 0;
        if (!CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, NULL, &cb))
            continue;
        kpi = (CRYPT_KEY_PROV_INFO *)malloc(cb);
        if (!kpi) goto done;
        if (!CertGetCertificateContextProperty(ctx, CERT_KEY_PROV_INFO_PROP_ID, kpi, &cb)) {
            free(kpi); kpi = NULL; continue;
        }
        break;   /* ctx is the key-owning cert */
    }
    if (!ctx || !kpi) {
        fprintf(stderr, "ownca_capi: the PFX contains no cert with a private key\n");
        goto done;
    }

    if (write_file(out, ctx->pbCertEncoded, ctx->cbCertEncoded) != 0) {
        CertFreeCertificateContext(ctx); goto done;
    }

    /* Canonical container name: the KPI property stores a FILE-style path
     * ("HDIMAGE\\pfx-xxxx.000\XXXX") that CryptAcquireContextA does not
     * reliably accept. Open the key through the cert context instead and ask
     * the provider for its real container name (PP_CONTAINER). */
    char cont_raw[1024] = "";
    {
        HCRYPTPROV hKeyProv = 0; DWORD keySpec = 0; BOOL callerFree = FALSE;
        if (!CryptAcquireCertificatePrivateKey(ctx, CRYPT_ACQUIRE_SILENT_FLAG,
                                               NULL, &hKeyProv, &keySpec,
                                               &callerFree)) {
            err("CryptAcquireCertificatePrivateKey");
            CertFreeCertificateContext(ctx); goto done;
        }
        DWORD cb = sizeof(cont_raw);
        if (!CryptGetProvParam(hKeyProv, PP_CONTAINER, (BYTE *)cont_raw, &cb, 0)) {
            err("CryptGetProvParam(PP_CONTAINER)");
            if (callerFree) CryptReleaseContext(hKeyProv, 0);
            CertFreeCertificateContext(ctx); goto done;
        }
        if (callerFree) CryptReleaseContext(hKeyProv, 0);
    }
    /* JSON-escape backslashes and quotes */
    char cont[2048]; size_t ci = 0;
    for (const char *p = cont_raw; *p && ci + 2 < sizeof(cont); p++) {
        if (*p == '\\' || *p == '"') cont[ci++] = '\\';
        cont[ci++] = *p;
    }
    cont[ci] = 0;

    char subj_raw[1024];
    if (!CertNameToStrA(X509_ASN_ENCODING, &ctx->pCertInfo->Subject,
                        CERT_X500_NAME_STR, subj_raw, sizeof(subj_raw)))
        subj_raw[0] = 0;
    char subj[2048]; size_t si = 0;
    for (const char *p = subj_raw; *p && si + 2 < sizeof(subj); p++) {
        if (*p == '\\' || *p == '"') subj[si++] = '\\';
        subj[si++] = *p;
    }
    subj[si] = 0;

    printf("{\"out\":\"%s\",\"container\":\"%s\",\"provtype\":%u,"
           "\"subject\":\"%s\",\"ok\":true}\n",
           out, cont, (unsigned)kpi->dwProvType, subj);
    CertFreeCertificateContext(ctx);
    rc = 0;
done:
    free(kpi);
    if (store) CertCloseStore(store, 0);
    free(wpw); free(blob.pbData);
    return rc;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: ownca_capi <info|paramsets|genkey|gencsr|selfsign"
                        "|issue|issuecsr|gencrl|exportpfx|importpfx"
                        "|delcontainer> [opts]\n");
        return 2;
    }
    const char *cmd = argv[1];
    if (!strcmp(cmd, "info"))      return cmd_info();
    if (!strcmp(cmd, "genkey"))    return cmd_genkey(argc, argv);
    if (!strcmp(cmd, "gencsr"))    return cmd_gencsr(argc, argv);
    if (!strcmp(cmd, "paramsets")) return cmd_paramsets(argc, argv);
    if (!strcmp(cmd, "selfsign"))  return cmd_selfsign(argc, argv);
    if (!strcmp(cmd, "issue"))     return cmd_issue(argc, argv);
    if (!strcmp(cmd, "issuecsr"))  return cmd_issuecsr(argc, argv);
    if (!strcmp(cmd, "gencrl"))    return cmd_gencrl(argc, argv);
    if (!strcmp(cmd, "exportpfx")) return cmd_exportpfx(argc, argv);
    if (!strcmp(cmd, "importpfx")) return cmd_importpfx(argc, argv);
    if (!strcmp(cmd, "delcontainer")) return cmd_delcontainer(argc, argv);
    fprintf(stderr, "ownca_capi: unknown command '%s'\n", cmd);
    return 2;
}
