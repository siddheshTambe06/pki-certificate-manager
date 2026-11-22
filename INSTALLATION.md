# Installation and Setup

## Prerequisites

- Python 3.9 or later
- OpenSSL or LibreSSL
- Git
- Terminal

Tested on macOS using Python 3.9.6 and LibreSSL 3.3.6.

## 1. Clone Repository

```bash
git clone https://github.com/siddheshTambe06/pki-certificate-manager.git
cd pki-certificate-manager
```

## 2. Initialise Directories

```bash
mkdir -p private csr certificates root-ca
mkdir -p intermediate-ca/newcerts intermediate-ca/crl
chmod 700 private
umask 077
```

## 3. Generate Root CA

```bash
openssl genrsa -aes256 -out private/root-ca.key.pem 4096

openssl req -new -x509 \
-key private/root-ca.key.pem \
-sha256 -days 3650 \
-out root-ca/root-ca.cert.pem \
-config root-ca/root-ca.cnf
```

## 4. Generate Intermediate CA

```bash
openssl genrsa -aes256 \
-out private/intermediate-ca.key.pem 4096

openssl req -new \
-key private/intermediate-ca.key.pem \
-sha256 \
-out csr/intermediate-ca.csr.pem \
-config intermediate-ca/intermediate-ca.cnf
```

## 5. Sign Intermediate CA

```bash
openssl x509 -req \
-in csr/intermediate-ca.csr.pem \
-CA root-ca/root-ca.cert.pem \
-CAkey private/root-ca.key.pem \
-CAcreateserial \
-out intermediate-ca/intermediate-ca.cert.pem \
-days 1825 -sha256 \
-extfile intermediate-ca/intermediate-ca.cnf \
-extensions v3_intermediate_ca
```

## 6. Initialise CA Database

Run these commands only for a new CA:

```bash
touch intermediate-ca/index.txt
echo 1000 > intermediate-ca/serial
echo 1000 > intermediate-ca/crlnumber
chmod 600 private/*.key.pem
```

Do not reset serial numbers or database files
after issuing certificates.

## 7. Generate Initial CRL

```bash
openssl ca -config intermediate-ca/ca.cnf \
-gencrl \
-out intermediate-ca/crl/intermediate-ca.crl.pem
```

## 8. Run Application

```bash
python3 scripts/pki_manager.py
```

Select option 4 to issue your first server certificate.

## Security Notice

Generate unique passphrases for all private keys.

Never publish private keys or passphrases.

Do not install the laboratory Root CA into your
operating system's trusted certificate store.

This project is intended for educational use only.
