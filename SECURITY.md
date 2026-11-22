# Security Architecture

## Cryptographic Controls

- RSA 4096-bit keys for certificate authorities.
- ECC NIST P-256 keys for server certificates.
- SHA-256 for certificate signatures with RSA.
- AES-256 encryption for private key storage.

## Private Key Protection

- Private keys are protected by passphrases.
- Private directory permissions are set to 700.
- Private key file permissions are set to 600.
- Private keys are excluded from Git version control.

## Certificate Security

- Two-tier certificate authority hierarchy.
- X.509 certificate chain validation.
- Certificate Signing Request verification.
- Certificate expiry monitoring.
- Certificate Revocation List validation.
- Certificate replacement following simulated compromise.

## Application Security

- Restricted certificate filename characters.
- Path traversal input rejection.
- Duplicate certificate overwrite prevention.
- Explicit confirmation before revocation.
- Interrupted operation handling.
- Certificate and private key matching.
- Subprocess execution without shell interpretation.

## Known Limitations

- Intended for educational and laboratory use.
- No hardware security module (HSM) integration.
- No Online Certificate Status Protocol (OCSP).
- No multi-user access control.
- No automated certificate renewal.
- No concurrent CA database access protection.
- Certificate hostname verification is not implemented.
- Revocation checking covers end-entity certificates.

## Production Considerations

Production deployment would require offline Root CA
storage, hardware-backed key protection, access controls,
centralised auditing, secure backups and independent
security assessment.
