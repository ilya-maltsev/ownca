# PKCS#12 export

PKCS#12 (`.p12` / `.pfx`) bundles the end-entity certificate, its
private key, and the full CA chain into a single password-protected
file. This format is accepted by Windows certificate stores,
browsers, and most VPN/email clients.

## When to use PKCS#12

* Importing into a Windows certificate store (`certmgr`, `certlm`).
* Configuring a mail client (Thunderbird, Outlook) for S/MIME.
* Provisioning a VPN client that requires a combined credential file.
* Any tool that does not accept separate PEM cert + key + chain files.

## Exporting

On the certificate detail page (`/certificates/<uuid>/`), click
**Export PKCS#12**. An inline panel slides open under the toolbar
asking for a passphrase; click **Download .p12** to get the file.

The button is shown only when the certificate has a server-side
private key. If the certificate was issued from an externally
supplied CSR, no key is stored and the button is hidden — there is
nothing to bundle.

**Passphrase rules:**

* Must not be empty — OwnCA rejects blank passphrases.
* At most 32 characters and no line breaks — the server refuses a
  longer passphrase. The 4-character minimum is checked by the browser
  only. Follow your organisation's password policy.
* The same passphrase is required to import the file later.

## Bundle contents

The exported `.p12` contains:

| Bag | Content |
|---|---|
| `certBag` | End-entity certificate (friendly name set to the Common Name). |
| `keyBag` | Private key. |
| `certBag` × N | Full CA chain — intermediate(s) + root, walked via the issuer relationship. |

## TK-26 compatible variant (GOST keys only)

When the certificate's key is **GOST** (GOST R 34.10-2012 256 / 512
bit), the passphrase row gains a checkbox and a cipher selectbox:

> [x] **TK-26 compatible format (GOST PFX)**
> Cipher: [`kuznyechik-ctr-acpkm` ▾]

What the checkbox does: produce a PFX conformant to RFC 9337 +
RFC 9548 (TK-26). The key and the certificates are encrypted with
PBES2 / PBKDF2-HMAC-Streebog and the selected CTR-ACPKM cipher
(Kuznyechik or Magma); the outer MAC is HMAC-Streebog-512 with the
RFC 9548 §3 KDF (PBKDF2 with `dkLen=96`, last 32 octets → HMAC key).
That is the wire format CryptoPro CSP and other TK-26-conformant
cryptoproviders accept on import.

The selected cipher is passed to `openssl pkcs12` as both `-keypbe`
and `-certpbe`, so the key and the certificates are encrypted the
same way. Choices: `kuznyechik-ctr-acpkm` (default) and
`magma-ctr-acpkm`.

A GOST certificate has **two** valid PFX variants — pick by where the
file will be imported:

* Software without TK-26 support → leave the box unchecked. You get
  a stock `.p12` (PBES2 / AES-256-CBC / PBKDF2-HMAC-SHA-256).
* Cryptoproviders with TK-26 support → keep the box ticked and pick
  another cipher if needed. The `.gost.p12` imports without
  conversion.

If the box is ticked but the certificate's key is RSA, the dashboard
rejects the request — the format is meaningless without a GOST key.

Under the hood: the server runs stock `openssl pkcs12 -export` with
a gost-engine that supports RFC 9337/9548
([`gost-engine/engine`](https://github.com/gost-engine/engine): support
was merged into the main branch in PR #527).

## Exporting a CA

The same container format is available for a **CA's own** certificate +
private key, not just end-entity certificates. On the CA detail page
(`/cas/<uuid>/`) click **Export PKCS#12** and choose the bag-encryption /
MAC **suite**:

| Suite | Bag PBE / MAC |
|---|---|
| Standard (AES-256) | AES-256-CBC bags, SHA-256 MAC — the interoperable default. |
| GOST Kuznyechik | `kuznyechik-ctr-acpkm` / `md_gost12_512` (TK-26, as above). |
| GOST Magma | `magma-ctr-acpkm-omac` / `md_gost12_256` (TK-26). |
| GOST 28147-89 (legacy) | `gost89` / `md_gost94` — for pre-TK-26 tools. |

For an imported/intermediate CA you can also tick **Include chain** to add
the parent CA certificates to the bundle. Besides the TK-26 suites, the CA
export offers the legacy `gost89` suite for older software that does not
support TK-26. See [CA management](cas.md).

## Importing (examples)

**Windows:**
```
certutil -importpfx -p "passphrase" cert.p12
```

**macOS:**
```
security import cert.p12 -P passphrase -k login.keychain
```

**Linux (p11-kit / NSS):**
```
pk12util -i cert.p12 -d sql:$HOME/.pki/nssdb -W passphrase
```

**TK-26 compatible cryptoprovider on Windows (`.gost.p12`):**

```
csptest -keyset -container "\\.\HDIMAGE\<container-name>" \
        -keytype exchange -import cert.gost.p12 -pwd "passphrase"
```

…or use the GUI: *Crypto-Pro → Tools → Install personal certificate*
and point it at the `.gost.p12` file.

> **CryptoPro CSP-backed CA.** For such a CA the provider builds the container
> itself, so the TK-26 format (`.gost.p12`) and the GOST encryption suites are
> unavailable, and the private key cannot be written out as PEM. See
> [CryptoPro CSP backend](cryptopro.md).

## Related topics

* [CryptoPro CSP backend](cryptopro.md)
* [CA management](cas.md)
* [Certificate registry](certificates.md)
* [Certificate renewal](cert_renew.md)
