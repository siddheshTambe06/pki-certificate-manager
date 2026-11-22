# Security Testing Results

## Test Environment

- Date: 22 November 2026
- Operating system: macOS
- Python: 3.9.6
- LibreSSL: 3.3.6
- Application version: 1.0
- Environment: Isolated local PKI laboratory

## Test Results

| ID | Test | Expected Result | Result |
|---|---|---|---|
| T01 | RSA private key generation | Valid RSA 4096-bit key | PASS |
| T02 | ECC key generation | Valid P-256 key | PASS |
| T03 | CSR verification | Valid CSR signature | PASS |
| T04 | Certificate issuance | Signed X.509 certificate | PASS |
| T05 | Certificate inspection | Certificate metadata displayed | PASS |
| T06 | Expiry monitoring | Remaining validity calculated | PASS |
| T07 | Certificate chain validation | Trusted chain accepted | PASS |
| T08 | Missing intermediate CA | Certificate rejected | PASS |
| T09 | Duplicate filename | Overwriting prevented | PASS |
| T10 | Path traversal input | Invalid filename rejected | PASS |
| T11 | Certificate revocation | Database updated | PASS |
| T12 | CRL regeneration | Updated CRL generated | PASS |
| T13 | Revoked certificate verification | Certificate rejected | PASS |
| T14 | Security report generation | Report created | PASS |

## Certificate Lifecycle Results

| Certificate | Serial (Hex) | Final Status |
|---|---|---|
| server.cert.pem | 1000 | Revoked |
| server-v2.cert.pem | 1001 | Valid |
| server-v3.cert.pem | 1002 | Revoked |

## Negative Test Evidence

### Missing Intermediate CA

Error 20: Unable to get local issuer certificate.

### Revoked Certificate

Error 23: Certificate revoked.

### Duplicate Certificate

Certificate already exists. No overwrite allowed.

### Path Traversal Input

Input: ../test

Result: Invalid certificate filename.

## Conclusion

All 14 documented functional checks passed during
manual testing.

The application successfully demonstrated certificate
issuance, trust validation, expiry monitoring, revocation,
replacement and security reporting.

These results demonstrate laboratory functionality and
do not constitute a production security certification.
