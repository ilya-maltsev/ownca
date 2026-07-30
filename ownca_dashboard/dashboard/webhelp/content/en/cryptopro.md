# CryptoPro CSP backend

Provider status, licence and the DRBG gamma pool live on the **Maintenance**
page (`/system/maintenance/`). CryptoPro has no page of its own: when the
backend is on it **is** the system's crypto backend, so its panels sit next to
the rest of the backend diagnostics.

With the integration off those panels are not shown; the openssl / gost-engine
panel takes their place — the one actually doing the work in that case.

The CA's GOST operations can run on the certified **CryptoPro CSP** instead of
the free `openssl + gost-engine`. Non-GOST algorithms (RSA, ECDSA, Ed25519)
always stay on openssl.

## When the backend is active

Two independent conditions:

1. **The distribution is baked into the image.** CryptoPro is included only if
   its `.deb` distribution was staged into the build (`dev_env/build.sh`). The
   build also compiles `ownca_capi`, the bridge to CAPILite.
2. **The runtime flag is on** — `OWNCA_CRYPTOPRO_ENABLED=True`. On an image
   built without the distribution the flag does nothing.

The page reports both states separately, so "flag on, but not installed" is
visible at a glance. When the distribution is absent the **CryptoPro CSP** menu
entry is hidden; when it is installed but switched off the entry carries an
"off" badge.

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

No limitation is silent: anything unsupported is either hidden in the UI,
flagged up front, or refused with a clear error before the operation starts.

### The private key is non-exportable

This is the point of the certified backend, not a gap: the key is born and stays
inside a container. So for certificates of a CryptoPro CA there is no:

* private key download in PEM;
* "certificate + key + chain" PEM bundle;
* PEM-pair import of a GOST CA — use PKCS#12/PFX instead, and the key goes
  straight into a container without ever touching disk.

Those buttons are hidden, and following a direct link answers with an
explanation. **PKCS#12 export still works** — `PFXExportCertStoreEx` builds the
container.

### PKCS#12 format — CryptoPro's own only

The resulting PFX imports correctly into CryptoPro itself (`certmgr`,
`PFXImportCertStore`), but **TK-26** (`.gost.p12`) and the GOST encryption
suites (`kuznyechik`, `magma`, `gost89`) cannot be selected: CAPILite exposes no
control over the export PBE. The panel does not offer those options for a
CryptoPro CA — no format is substituted behind your back, because the importing
side would receive something other than what was asked for.

### X.509 extensions

The bridge encodes extensions structurally, so the set is closed.

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
* **subjectKeyIdentifier / authorityKeyIdentifier toggles** from the profile are
  honoured. Both extensions are on by default.
