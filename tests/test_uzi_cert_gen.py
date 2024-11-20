from datetime import datetime, timedelta
from app.uzi_cert_generator import UZICertificateGenerator

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import Certificate
from cryptography import x509
from datetime import timezone
from cryptography.hazmat.primitives import hashes

from app.uzi_record import UZIRecord

SAMPLE_UZI_RECORD = UZIRecord(
    'test',
    'testerson',
    '123',
    '123',
    'test',
    '123',
    'role1',
    '123',
    'test',
    '123',
)

def _generate_root_cert(private_key: rsa.RSAPrivateKey) -> Certificate:
    # Step 2: Create the certificate (Root certificate)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"My Root CA"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"My Root CA Certificate"),
    ])

    issuer = subject  # The root certificate is self-signed, so subject and issuer are the same

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
    )

    # Add basic constraints for a root certificate (CA)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),  # `ca=True` designates this as a CA certificate
        critical=True
    )

    # Sign the certificate using the private key (self-signed)
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )
    return certificate


def _create_csr(private_key: rsa.RSAPrivateKey):
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(x509.NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, u"www.mywebsite.com"),
    ])
    csr_builder = x509.CertificateSigningRequestBuilder() \
        .subject_name(subject) \
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"www.mywebsite.com"),
                x509.DNSName(u"mywebsite.com"),
            ]),
            critical=False
        )

    # Step 4: Sign the CSR with the private key (use SHA256 in this example)
    csr = csr_builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256()
    )
    return csr

def test_gen():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    root_cert = _generate_root_cert(private_key)

    lifetime = timedelta(minutes=10)
    generator = UZICertificateGenerator(lifetime, private_key, root_cert)
    csr = _create_csr(private_key)
    
    generator.generate(csr, SAMPLE_UZI_RECORD)