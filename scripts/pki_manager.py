import os
import re
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from ssl import cert_time_to_seconds

os.umask(0o077)

BASE = Path(__file__).resolve().parent.parent
CERTS = BASE / "certificates"
CA = BASE / "intermediate-ca"
ROOT = BASE / "root-ca/root-ca.cert.pem"
INTERMEDIATE = CA / "intermediate-ca.cert.pem"
CRL = CA / "crl/intermediate-ca.crl.pem"
CONFIG = CA / "ca.cnf"


def openssl(args, interactive=False):
    return subprocess.run(
        ["openssl"] + [str(arg) for arg in args],
        cwd=BASE,
        capture_output=not interactive,
        text=True,
        check=True
    )


def select_certificate():
    certificates = sorted(CERTS.glob("*.cert.pem"))

    if not certificates:
        print("No certificates found.")
        return None

    for i, cert in enumerate(certificates, 1):
        print(f"{i}. {cert.name}")

    choice = input("Select certificate number: ").strip()

    if choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(certificates):
            return certificates[index]

    print("Invalid selection.")
    return None


def inspect_certificate(cert):
    result = openssl([
        "x509", "-in", cert, "-noout",
        "-subject", "-issuer", "-dates",
        "-serial", "-fingerprint", "-sha256"
    ])

    print("\n===== CERTIFICATE DETAILS =====")
    print(result.stdout)


def expiry_report(cert):
    result = openssl([
        "x509", "-in", cert, "-noout", "-enddate"
    ])

    date = result.stdout.strip().split("=", 1)[1]

    expiry = datetime.fromtimestamp(
        cert_time_to_seconds(date), timezone.utc
    )

    remaining = expiry - datetime.now(timezone.utc)

    if remaining.total_seconds() <= 0:
        status = "EXPIRED"
    elif remaining.days <= 30:
        status = "EXPIRING SOON"
    else:
        status = "NOT EXPIRED"

    return (
        f"Certificate: {cert.name}\n"
        f"Expiry: {expiry}\n"
        f"Days remaining: {remaining.days}\n"
        f"Status: {status}"
    )


def serial_number(cert):
    result = openssl([
        "x509", "-in", cert, "-noout", "-serial"
    ])

    return int(result.stdout.strip().split("=", 1)[1], 16)


def database_status(cert):
    serial = serial_number(cert)

    for line in (CA / "index.txt").read_text().splitlines():
        fields = line.split("\t")

        if len(fields) >= 6:
            if int(fields[3], 16) == serial:
                return fields[0]

    return "UNKNOWN"


def verify_certificate(cert):
    try:
        result = openssl([
            "verify",
            "-CAfile", ROOT,
            "-untrusted", INTERMEDIATE,
            "-CRLfile", CRL,
            "-crl_check",
            "-purpose", "sslserver",
            cert
        ])

        if database_status(cert) != "V":
            return "VERIFICATION FAILED: CA database status"

        return "VERIFIED\n" + result.stdout.strip()

    except subprocess.CalledProcessError as error:
        return (
            "VERIFICATION FAILED\n"
            + (error.stdout or "")
            + (error.stderr or "")
        )


def public_key(file, file_type):
    return openssl([
        file_type, "-in", file, "-pubkey", "-noout"
    ]).stdout.strip()


def issue_certificate():
    name = input("Certificate filename (e.g. server-v3): ").strip()

    if not re.fullmatch(r"[A-Za-z0-9_-]{1,50}", name):
        print("Invalid certificate filename.")
        return

    key = BASE / "private" / f"{name}.key.pem"
    csr = BASE / "csr" / f"{name}.csr.pem"
    cert = CERTS / f"{name}.cert.pem"

    if cert.exists():
        print("Certificate already exists. No overwrite allowed.")
        return

    if csr.exists() and not key.exists():
        print("CSR exists but private key is missing.")
        return

    if key.exists():
        print("Existing private key found. Resuming issuance.")
    else:
        openssl([
            "genpkey", "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-aes256", "-out", key
        ], interactive=True)

        key.chmod(0o600)

    if not csr.exists():
        openssl([
            "req", "-new", "-key", key,
            "-sha256", "-out", csr,
            "-config", CERTS / "server.cnf"
        ], interactive=True)

    openssl(["req", "-in", csr, "-noout", "-verify"])

    # Confirm that the CSR belongs to the existing private key.
    with tempfile.TemporaryDirectory() as directory:
        pub_file = Path(directory) / "public.pem"

        openssl([
            "pkey", "-in", key,
            "-pubout", "-out", pub_file
        ], interactive=True)

        if pub_file.read_text().strip() != public_key(csr, "req"):
            print("Private key and CSR do not match.")
            return

    # Avoid issuing twice after an interrupted database commit.
    csr_pub = public_key(csr, "req")

    for archived in (CA / "newcerts").glob("*.pem"):
        if public_key(archived, "x509") == csr_pub:
            print("An issued certificate already uses this key.")
            print("Check CA archive:", archived.name)
            return

    openssl([
        "ca", "-config", CONFIG,
        "-in", csr, "-out", cert,
        "-extfile", CERTS / "server.cnf",
        "-extensions", "server_cert",
        "-notext"
    ], interactive=True)

    if cert.exists() and database_status(cert) == "V":
        print("Certificate issued successfully:", cert.name)
    else:
        print("Certificate issuance was not confirmed.")


def generate_crl():
    with tempfile.TemporaryDirectory(dir=CRL.parent) as directory:
        temporary = Path(directory) / "updated.crl.pem"

        openssl([
            "ca", "-config", CONFIG,
            "-gencrl", "-out", temporary
        ], interactive=True)

        os.replace(temporary, CRL)

    print("Certificate Revocation List updated.")


def revoke_certificate(cert):
    if database_status(cert) != "V":
        print("Certificate is not marked valid in the CA database.")
        return

    serial = serial_number(cert)
    archive = CA / "newcerts" / f"{serial:X}.pem"

    if not archive.exists():
        print("Certificate missing from CA archive.")
        return

    if cert.read_bytes() != archive.read_bytes():
        # Compare canonical DER if PEM formatting differs.
        first = openssl([
            "x509", "-in", cert,
            "-noout", "-fingerprint", "-sha256"
        ]).stdout

        second = openssl([
            "x509", "-in", archive,
            "-noout", "-fingerprint", "-sha256"
        ]).stdout

        if first != second:
            print("Certificate does not match the CA archive.")
            return

    print("Selected certificate:", cert.name)

    confirm = input("Type REVOKE to confirm: ")

    if confirm != "REVOKE":
        print("Revocation cancelled.")
        return

    openssl([
        "ca", "-config", CONFIG,
        "-revoke", cert,
        "-crl_reason", "keyCompromise"
    ], interactive=True)

    print("Certificate revoked in CA database.")
    print("Updating CRL. Enter CA passphrase again.")

    generate_crl()


def generate_report():
    reports = BASE / "reports"
    reports.mkdir(exist_ok=True)

    now = datetime.now(timezone.utc)

    filename = reports / (
        "security-report-"
        + now.strftime("%Y%m%d-%H%M%S-%f")
        + ".txt"
    )

    with filename.open("x") as report:
        report.write("PKI SECURITY REPORT\n")
        report.write(f"Generated: {now}\n")

        for cert in sorted(CERTS.glob("*.cert.pem")):
            report.write("\n" + "=" * 40 + "\n")

            try:
                report.write(expiry_report(cert) + "\n")
                report.write(
                    verify_certificate(cert) + "\n"
                )
            except subprocess.CalledProcessError:
                report.write(
                    f"Unable to inspect {cert.name}\n"
                )

    print("Security report saved:", filename)


def main():
    while True:
        print("\n================================")
        print("     PKI CERTIFICATE MANAGER")
        print("          Version 1.0")
        print("================================")
        print("1. Inspect certificate")
        print("2. Check certificate expiry")
        print("3. Verify certificate and revocation")
        print("4. Issue new certificate")
        print("5. Revoke certificate")
        print("6. Generate updated CRL")
        print("7. Generate security report")
        print("8. Exit")

        try:
            choice = input("\nSelect an option: ").strip()

            if choice == "8":
                print("Exiting PKI Certificate Manager.")
                break

            elif choice == "4":
                issue_certificate()

            elif choice == "6":
                generate_crl()

            elif choice == "7":
                generate_report()

            elif choice in ("1", "2", "3", "5"):
                cert = select_certificate()

                if cert is None:
                    continue

                if choice == "1":
                    inspect_certificate(cert)

                elif choice == "2":
                    print(expiry_report(cert))

                elif choice == "3":
                    print(verify_certificate(cert))

                elif choice == "5":
                    revoke_certificate(cert)

            else:
                print("Invalid option.")

        except KeyboardInterrupt:
            print("\nOperation interrupted.")
            print("Existing files preserved. Check CA state.")

        except EOFError:
            break

        except subprocess.CalledProcessError as error:
            print("OpenSSL operation failed.")
            print(error.stderr or "Check terminal output.")

        except (OSError, ValueError) as error:
            print("Operation failed:", error)


if __name__ == "__main__":
    main()
