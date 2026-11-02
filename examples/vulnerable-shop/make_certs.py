"""Generate throwaway certificates and a private key for the demo (never commit these)."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

SHA256_WITH_RSA = bytes.fromhex("300d06092a864886f70d01010b0500")
SHA1_WITH_RSA = bytes.fromhex("300d06092a864886f70d0101050500")


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _tlv(tag: int, body: bytes) -> bytes:
    size = len(body)
    if size < 0x80:
        return bytes([tag, size]) + body
    encoded = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + body


def sha1_signed(builder: x509.CertificateBuilder, key: rsa.RSAPrivateKey) -> x509.Certificate:
    """Modern cryptography refuses SHA-1 certificate signatures, so re-sign the TBS bytes directly.

    This reproduces the kind of legacy certificate that still turns up in older systems.
    """
    tbs = builder.sign(key, hashes.SHA256()).tbs_certificate_bytes.replace(SHA256_WITH_RSA, SHA1_WITH_RSA, 1)
    signature = key.sign(tbs, padding.PKCS1v15(), hashes.SHA1())
    return x509.load_der_x509_certificate(_tlv(0x30, tbs + SHA1_WITH_RSA + _tlv(0x03, b"\x00" + signature)))


def main(target: Path) -> None:
    target.mkdir(parents=True, exist_ok=True)
    now = datetime.now(UTC)

    legacy_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    legacy = (
        x509.CertificateBuilder()
        .subject_name(_name("legacy.shop.example.com"))
        .issuer_name(_name("legacy.shop.example.com"))
        .public_key(legacy_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=400))
        .not_valid_after(now + timedelta(days=10))
    )
    (target / "legacy.pem").write_bytes(sha1_signed(legacy, legacy_key).public_bytes(serialization.Encoding.PEM))

    ca_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    modern = (
        x509.CertificateBuilder()
        .subject_name(_name("shop.example.com"))
        .issuer_name(_name("VulnWarden Demo CA"))
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=30))
        .not_valid_after(now + timedelta(days=300))
    )
    (target / "modern.pem").write_bytes(modern.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (target / "server.key").write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


if __name__ == "__main__":
    main(Path(__file__).resolve().parent / "certs")
    print("Wrote certs/legacy.pem, certs/modern.pem and certs/server.key")
