"""The certificates tools/interop/run.sh serves with openssl s_server: a
root, servers for localhost with P-256, P-384 and RSA keys, one for another
host, and one that has expired. Made fresh each run (keys at random) in
the directory given."""

import datetime
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

out = sys.argv[1]
now = datetime.datetime.now(datetime.timezone.utc)
day = datetime.timedelta(days=1)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def write(path, data):
    with open(os.path.join(out, path), "wb") as f:
        f.write(data)


root_key = ec.generate_private_key(ec.SECP384R1())
root = (x509.CertificateBuilder()
        .subject_name(name("nxtls interop root")).issuer_name(name("nxtls interop root"))
        .public_key(root_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - day).not_valid_after(now + 30 * day)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .sign(root_key, hashes.SHA384()))
write("root.pem", root.public_bytes(serialization.Encoding.PEM))


def server(stem, key, host, nb, na):
    cert = (x509.CertificateBuilder()
            .subject_name(name(host)).issuer_name(root.subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
            .sign(root_key, hashes.SHA384()))
    write(stem + ".pem", cert.public_bytes(serialization.Encoding.PEM))
    write(stem + ".key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))


server("p256", ec.generate_private_key(ec.SECP256R1()), "localhost", now - day, now + 10 * day)
server("p384", ec.generate_private_key(ec.SECP384R1()), "localhost", now - day, now + 10 * day)
server("rsa", rsa.generate_private_key(65537, 3072), "localhost", now - day, now + 10 * day)
server("wrong", ec.generate_private_key(ec.SECP256R1()), "wrong.example", now - day, now + 10 * day)
server("expired", ec.generate_private_key(ec.SECP256R1()), "localhost", now - 20 * day, now - 2 * day)
