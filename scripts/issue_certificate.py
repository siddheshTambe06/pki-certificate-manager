import os
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def run_openssl(arguments):
    subprocess.run(
        ["openssl"] + arguments,
        cwd=BASE_DIR,
        check=True
    )


def issue_certificate():
    os.umask(0o077)

    key = "private/server-v2.key.pem"
    csr = "csr/server-v2.csr.pem"
    certificate = "certificates/server-v2.cert.pem"

    for filename in (key, csr, certificate):
        if (BASE_DIR / filename).exists():
            print("File already exists:", filename)
            print("Issuance cancelled to prevent overwriting.")
            return

    try:
        print("\n[1/3] Generating encrypted ECC private key")

        run_openssl([
            "genpkey",
            "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-aes256",
            "-out", key
        ])

        os.chmod(BASE_DIR / key, 0o600)

        print("\n[2/3] Generating certificate signing request")

        run_openssl([
            "req", "-new",
            "-key", key,
            "-sha256",
            "-out", csr,
            "-config", "certificates/server.cnf"
        ])

        print("\n[3/3] Issuing certificate")

        run_openssl([
            "ca",
            "-config", "intermediate-ca/ca.cnf",
            "-in", csr,
            "-out", certificate,
            "-extfile", "certificates/server.cnf",
            "-extensions", "server_cert",
            "-notext"
        ])

        print("\nCertificate issued successfully.")
        print("Certificate:", certificate)

    except subprocess.CalledProcessError:
        print("\nCertificate issuance failed.")
        print("Review the error before retrying.")


if __name__ == "__main__":
    issue_certificate()
