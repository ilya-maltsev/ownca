# Maintenance

`/system/maintenance/` — counts, crypto-backend status, and
operational actions.

## Counts

A row of cards shows raw counts straight from the database:

* **Authorities** — total CAs.
* **Active certs** — certificates with status `active`.
* **Revoked certs** — certificates with status `revoked`.
* **Expired certs** — certificates with status `expired`.
* **CRL exports** — total CRL generations recorded across all CAs.

## Crypto backend

A panel showing whether OwnCA's crypto stack is healthy:

* **GOST engine loaded** — green badge when `openssl engine gost`
  responds, red otherwise. When red, only RSA / ECDSA / Ed25519
  algorithms are usable until the engine is reachable.
* **Storage directory** — the path resolved from `OWNCA_STORAGE_DIR`.
* **openssl version** — full output of `openssl version -a` (build
  flags, platform, engine search path).

## Operations

The **Operations** panel groups the maintenance actions; each button
reports its result inline.

### Refresh metadata

Re-parses every certificate file from disk and writes back the
database fields (subject, dates, fingerprint, serial). It also flips
any active certificate whose `notAfter` is in the past to `expired`
status.

Use it after manually editing files in the storage directory.
Nothing happens to disk except metadata reads.

### Rebuild all CRLs

Regenerates the certificate revocation list for every enabled CA and
records a fresh CRL export. Each CA's CRL is rewritten with an
incremented CRL number and the current set of revoked serials.

Every regenerated CRL is also published to the shared export directory
`OWNCA_STORAGE_DIR/crls/` under the name `<ca_name>.crl` (for example
`rsa_root.crl`), giving a single predictable folder to serve all CAs'
CRLs from. The per-CA master copy still lives at
`cas/<uuid>/crl.pem`.

Use it after bulk revocations or to refresh the `nextUpdate` window
before the scheduled CRL refresh job runs.

## Related topics

* [Configuration](configuration.md)
* [CA management](cas.md)
