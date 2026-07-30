# Revocation and CRL

## Revoking a certificate

The **Revoke** button on the certificate detail page marks the
certificate as revoked and immediately regenerates the CRL for the
issuing CA.

### Reason codes

| Reason | When to use |
|---|---|
| `unspecified` | No specific reason. |
| `keyCompromise` | The private key was compromised. |
| `CACompromise` | The issuing CA key was compromised. (Stored as `CACompromise` in the model — keep the capitalisation.) |
| `affiliationChanged` | The owner's organisation changed. |
| `superseded` | Replaced by a new certificate. |
| `cessationOfOperation` | The service has been decommissioned. |
| `certificateHold` | Temporary suspension — may be lifted later. |

The reason is embedded in the CRL entry. Relying parties that process
CRL reason codes can present a more informative error to end users.

### What happens on revocation

1. The certificate is marked revoked in the CA's index with the
   chosen reason code.
2. A new CRL is signed and replaces the previous one for that CA.
3. The export history records the CRL number and revoked-count.
4. The certificate's status flips to `revoked` and the timestamp is
   recorded.

## CRL lifecycle

### Generating a CRL on demand

Use **Regenerate CRL** on the CA detail page to produce a new CRL
without revoking anything. This is useful when the current CRL is
about to expire.

### Downloading the CRL

**Download CRL** on the CA detail page serves the latest CRL as a
PEM file. If no CRL has been produced yet, the first download
generates one on the fly.

## Related topics

* [Certificate registry](certificates.md)
* [CA management](cas.md)
* [Certificate renewal](cert_renew.md)
