# CryptoPro CSP backend

Provider status, licence and the DRBG gamma pool are shown on the
**Maintenance** page (`/system/maintenance/`). CryptoPro has no page or menu
entry of its own.

The CryptoPro panels are shown whenever CryptoPro is installed in the image,
even with `OWNCA_CRYPTOPRO_ENABLED` off. The openssl / gost-engine panel is
shown only while CryptoPro is off: once it is on, GOST signing is done by
CryptoPro.

The CA's GOST operations can run on the certified **CryptoPro CSP** instead of
the free `openssl + gost-engine`. Non-GOST algorithms (RSA, ECDSA, Ed25519)
always stay on openssl.

## When the backend is active

Two independent conditions:

1. **CryptoPro is installed in the image.** This happens only if its `.deb`
   distribution was supplied when the image was built (`dev_env/build.sh`).
   The build also compiles `ownca_capi`, the bridge to CAPILite.
2. **The runtime flag is on** — `OWNCA_CRYPTOPRO_ENABLED=True`. On an image
   without CryptoPro the flag does nothing.

The **Provider status** panel reports both conditions separately, so "flag on,
but CryptoPro not installed" is visible at a glance.

## What runs on CryptoPro

The backend is chosen **when a CA is created** and recorded on disk
(`cas/<uuid>/backend`). It never changes afterwards:

* a new GOST CA created while CryptoPro is enabled lands on CryptoPro;
* an intermediate inherits its **parent's** backend rather than the current
  flag — otherwise there would be nothing to sign it with;
* pre-existing CAs stay where they were: switching the flag off does not move an
  existing CryptoPro CA back to openssl, because its key physically lives in a
  container.

Each CA's backend is shown as a badge in the authorities list and on the CA
page.

For a CryptoPro-backed CA the whole lifecycle goes through the bridge: key
generation into containers, root self-signing, intermediate signing, end-entity
issuance (server-side key generation **or** an external CSR — the PKCS#10
signature is verified first), renewal, CRL generation, PKCS#12 export and import
of an existing GOST CA from PKCS#12/PFX. openssl is used only to read metadata.

## DRBG gamma

On a headless server CryptoPro cannot collect entropy on its own — key
generation fails with `NTE_SILENT_CONTEXT (0x80090022)` when the gamma pool is
empty.

The page shows a **remaining key generations** counter: each new key consumes
one 36-byte segment (32 bytes of entropy + CRC32). Gamma can be:

* **uploaded** — either a ready CPSD pool or raw entropy (which is segmented and
  CRC-stamped automatically);
* **generated** — from `os.urandom`. **Test rigs only:** this is not a certified
  entropy source. Production use needs a hardware source or real CPSD gamma.

## Licence

Set through `OWNCA_CRYPTOPRO_LICENSE` or in the panel; the panel value wins.
Left unset, CryptoPro runs on its built-in 90-day demo licence.

## Backend limitations

The panel warns about each limitation in advance: unsupported actions are
hidden or flagged in the UI, and a forbidden operation is refused with a clear
error before it starts.

### The private key cannot be extracted

This is the purpose of a certified backend, not a shortcoming: the key is
generated and kept inside a container. So for certificates of a CryptoPro CA
there is no:

* private key download in PEM;
* "certificate + key + chain" PEM bundle;
* PEM-pair import of a GOST CA — use PKCS#12/PFX instead, and the key goes
  straight into a container without ever touching disk.

Those buttons are hidden, and a direct link to them shows an explanation of
why the action is unavailable. **PKCS#12 export still works** — CryptoPro's
`PFXExportCertStoreEx` builds the container.

### PKCS#12 only in CryptoPro's format

The resulting PFX imports correctly into CryptoPro itself (`certmgr`,
`PFXImportCertStore`), but the **TK-26** format (`.gost.p12`) and the GOST
encryption suites (`kuznyechik`, `magma`, `gost89`) cannot be selected:
CAPILite does not let the caller choose the export encryption. The panel does
not offer those options for a CryptoPro CA and never substitutes one format for
another — the recipient would get a different format from the one chosen.

### X.509 extensions

The bridge builds each extension itself, so only the ones listed below are
supported.

**Supported:** `basicConstraints` (including `pathlen`), `keyUsage`,
`extendedKeyUsage` (names and raw OIDs), `subjectKeyIdentifier`,
`authorityKeyIdentifier` (including `issuer:always` — with DirName and serial),
`subjectAltName` (DNS, IP, email, URI), `crlDistributionPoints`,
`authorityInfoAccess` (caIssuers and OCSP), `subjectInfoAccess` (caRepository),
`freshestCRL`, `issuerAltName` (DNS, IP, email, URI). Critical flags are
honoured.

**Not supported** — issuance will refuse:

* `nameConstraints`;
* `policyConstraints`, `inhibitAnyPolicy`, `certificatePolicies`;
* `otherName` SAN entries;
* free-form lines from the "Extra extensions" field and any `[...]` sections;
* OID-registry fields placed as "Extension";
* `issuerAltName` of type `dirName`, `otherName`, `RID`.

A profile carrying any of these is flagged in the profile editor and in the
issue form: the incompatibility is visible **before** the form is filled in,
not after submitting it.

### On par with openssl

* **GOST paramset** — applied to the key and validated against the list the
  provider itself reports. The issue form offers only supported sets.
* **CSR** — written even for server-side key generation, downloadable, and
  carried forward on renewal.
* **Revocation reason** — reaches the CRL as `reasonCode`.
* **CRL validity** — shared by both backends (30 days by default).
* **subjectKeyIdentifier / authorityKeyIdentifier** — included or left out
  as the profile says. Both extensions are on by default.
