# PKI Certificate Manager

A Python-based Public Key Infrastructure (PKI) laboratory
demonstrating digital certificate lifecycle management,
cryptographic key generation, trust validation and revocation.

## Project Overview

This project simulates a two-tier private certificate
authority infrastructure using Python and LibreSSL.

It demonstrates how organisations establish digital trust,
issue certificates, monitor expiry and revoke compromised
certificates.

## PKI Architecture

Root CA (RSA 4096)
    |
Intermediate CA (RSA 4096)
    |
Server Certificates (ECC P-256)

## Features

- Two-tier certificate authority architecture
- RSA 4096 and ECC P-256 key generation
- AES-256 encrypted private keys
- X.509 certificate issuance
- Certificate Signing Request (CSR) verification
- Certificate chain validation
- Certificate expiry monitoring
- Certificate Revocation Lists (CRL)
- Automated certificate revocation
- Certificate replacement
- Automated security report generation
- Filename validation and overwrite protection
- Interrupted issuance handling

## Technologies

- Python 3.9.6
- LibreSSL 3.3.6
- X.509
- RSA
- Elliptic Curve Cryptography (ECC)
- SHA-256
- AES-256
- Git

## Usage

After initialising the local PKI infrastructure, run:

```bash
python3 scripts/pki_manager.py
```

Available options:

1. Inspect certificate
2. Check certificate expiry
3. Verify certificate and revocation
4. Issue new certificate
5. Revoke certificate
6. Generate updated CRL
7. Generate security report
8. Exit

## Security Testing

13 functional and security checks were demonstrated,
including rejection of revoked certificates, missing
certificate chains, duplicate filenames and path
traversal input.

## Security Considerations

Private keys are encrypted and excluded from version control.

The certificate authority is restricted to an educational
laboratory environment.

This project is not intended for production deployment
or public certificate issuance.

## Author

Siddhesh Yadav Tambe

MSc Cyber Security
City St George's, University of London

## License

MIT License
