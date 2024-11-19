# this file can be overwritten to provide a custom ca implementation
# the methods sign_csr() and revoke_cert() must be implemented with matching function signatures
# set env var CA_ENABLED=False when providing a custom ca implementation

import asyncio
from datetime import datetime, timezone

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier

from .. import db
from ..acme.certificate.service import SerialNumberConverter
from ..config import settings

from .model import SignedCertInfo


async def sign_csr(csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]) -> SignedCertInfo:
    """
    csr: the parsed csr object
    subject_domain: the main requested domain name
    san_domains: the alternative (additional) requested domain names
    """
    if not settings.ca.enabled:
        raise Exception(  # pylint: disable=broad-exception-raised
            'internal ca is not enabled (env var CA_ENABLED)! Please provide a custom ca implementation'
        )

    ca_cert, ca_key = await load_active_ca()

    cert, cert_chain_pem = await asyncio.to_thread(generate_cert_sync, ca_key=ca_key, ca_cert=ca_cert, csr=csr, subject_domain=subject_domain, san_domains=san_domains)

    return SignedCertInfo(cert=cert, cert_chain_pem=cert_chain_pem)


async def revoke_cert(
    serial_number: str,
    revocations: set[tuple[str, datetime]],  # pylint: disable=unused-argument
) -> None:
    if not settings.ca.enabled:
        raise Exception(  # pylint: disable=broad-exception-raised
            'internal ca is not enabled (env var CA_ENABLED)! Please provide a custom ca implementation'
        )
    ca_cert, ca_key = await load_active_ca()
    _, crl_pem = await asyncio.to_thread(build_crl_sync, ca_key=ca_key, ca_cert=ca_cert, revocations=revocations)
    async with db.transaction() as sql:
        await sql.exec("""update cas set crl_pem = $1 where active = true""", crl_pem)


async def load_active_ca():
    async with db.transaction(readonly=True) as sql:
        cert_pem, key_pem_enc = await sql.record("""select cert_pem, key_pem_enc from cas where active = true""")
    return await asyncio.to_thread(load_ca_sync, cert_pem=cert_pem, key_pem_enc=key_pem_enc)


def load_ca_sync(*, cert_pem, key_pem_enc):
    f = Fernet(settings.ca.encryption_key.get_secret_value())
    key_pem = f.decrypt(key_pem_enc)
    ca_key = serialization.load_pem_private_key(key_pem, None)
    ca_cert = x509.load_pem_x509_certificate(cert_pem.encode(), None)
    return ca_cert, ca_key


def generate_cert_sync(*, ca_key: PrivateKeyTypes, ca_cert: x509.Certificate, csr: x509.CertificateSigningRequest, subject_domain: str, san_domains: list[str]):
    ca_id = SerialNumberConverter.int2hex(ca_cert.serial_number)
    
    certificate_policies_extension = x509.Extension(
        oid=x509.ObjectIdentifier("2.5.29.32"),
        critical=False,  # Or True if it's a critical extension
        # TODO Replace with policies
        value=b''
    )
    
    
    # Add Subject Alternative Name extension (OID 2.5.29.17)
    san_extension = x509.Extension(
        oid=x509.ObjectIdentifier("2.5.29.17"),
        critical=False,  # Set to True if it's critical
        # TODO replace with uzi seq bytes
        value=b''
    )
    
    subject_name = x509.Name(
        [
            x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'NL'),
            # TODO replace value with "record.GivenName + " " + record.Surname"
            x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_domain),
            # TODO replace the value with the Entity name in the request
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, 'CIBG'),
            
            # TODO replace value with surname value from record
            x509.NameAttribute(x509.NameOID.SURNAME, 'CIBG'),
            
            # TODO replace value with given name value from record
            x509.NameAttribute(x509.NameOID.GIVEN_NAME, 'CIBG'),

            # TODO replace value with uzi number from record
            x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, 'CIBG'),
        ],
    )
    
    key_usage = x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False
    )
    
    ext_key_usage = x509.ExtendedKeyUsage([
        ExtendedKeyUsageOID.CLIENT_AUTH,
        ExtendedKeyUsageOID.EMAIL_PROTECTION,
        ObjectIdentifier("1.3.6.1.4.1.311.10.3.12")  # szOID_KP_DOCUMENT_SIGNING
    ])
    cert_builder = (
        x509.CertificateBuilder(
            issuer_name=ca_cert.subject,
            subject_name=subject_name,
            serial_number=x509.random_serial_number(),
            not_valid_before=datetime.now(timezone.utc),
            not_valid_after=datetime.now(timezone.utc) + settings.ca.cert_lifetime,
            public_key=csr.public_key(),
        )
        .add_extension(certificate_policies_extension, critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san_extension, critical=False)
        .add_extension(key_usage, critical=True)
        .add_extension(ext_key_usage, critical=True)
        .add_extension(
            x509.CRLDistributionPoints(
                distribution_points=[
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier(str(settings.external_url).removesuffix('/') + f'/ca/{ca_id}/crl')],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    )

    cert = cert_builder.sign(private_key=ca_key, algorithm=hashes.SHA512())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    cert_chain_pem = (cert_pem + ca_cert_pem).decode()

    return cert, cert_chain_pem


def build_crl_sync(
    *,
    ca_key: PrivateKeyTypes,
    ca_cert: x509.Certificate,
    revocations: set[tuple[str, datetime]],
):
    now = datetime.utcnow()
    builder = x509.CertificateRevocationListBuilder(
        last_update=now,
        next_update=now + settings.ca.crl_lifetime,
        issuer_name=ca_cert.subject,
    )
    for serial_number, revoked_at in revocations:
        revoked_cert = x509.RevokedCertificateBuilder().serial_number(SerialNumberConverter.hex2int(serial_number)).revocation_date(revoked_at).build()
        builder = builder.add_revoked_certificate(revoked_cert)
    crl = builder.sign(private_key=ca_key, algorithm=hashes.SHA512())
    crl_pem = crl.public_bytes(encoding=serialization.Encoding.PEM).decode()
    return crl, crl_pem
