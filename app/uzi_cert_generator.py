from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
from cryptography import x509
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import hashes

from app.uzi_record import UZIRecord


class UZICertificateGenerator:
    _lifetime: timedelta

    _ca_key: PrivateKeyTypes
    _ca_cert: x509.Certificate

    _SZOID_KP_DOCUMENT_SIGNING_ID = ObjectIdentifier('1.3.6.1.4.1.311.10.3.12')

    def __init__(self, lifetime: timedelta, ca_key: PrivateKeyTypes, ca_cert: x509.Certificate) -> None:
        self._lifetime = lifetime
        self._ca_key = ca_key
        self._ca_cert = ca_cert

    def _resolve_cert_policies(self) -> x509.CertificatePolicies:
        policies = [
            x509.PolicyInformation(ObjectIdentifier('1.3.3.7'), None),
            x509.PolicyInformation(ObjectIdentifier('2.16.528.1.1003.1.3.5.5.3'), None),
        ]

        # uzi test
        uzi_test_policy = x509.PolicyInformation(
            ObjectIdentifier("2.16.528.1.1007.99.212"),
            policy_qualifiers=[
                x509.UserNotice(
                    notice_reference=None,
                    explicit_text='Certificaat uitsluitend gebruiken ten behoeve van de TEST van het UZI-register. Het UZI-register is in geen geval aansprakelijk voor eventuele schade.'
                ),
                
                # Interpret the string as CPS URI
                "https://acceptatie.zorgcsp.nl/cps/uzi-register.html",
            ],
        )
        policies.append(uzi_test_policy)

        return x509.CertificatePolicies(policies)

    def _build(self, csr: x509.CertificateSigningRequest, record: UZIRecord) -> x509.CertificateBuilder:
        certificate_policies_extension = self._resolve_cert_policies()

        # TODO replace value with uzi seq bytes
        san_extension = x509.SubjectAlternativeName([])

        common_name = f'{record.given_name} {record.surname}'
        subject_name = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COUNTRY_NAME, 'NL'),
                x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(x509.NameOID.SURNAME, record.surname),
                x509.NameAttribute(x509.NameOID.GIVEN_NAME, record.given_name),
                x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, record.uzi_nr),
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
            decipher_only=False,
        )

        ext_key_usage = x509.ExtendedKeyUsage(
            [
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
                self._SZOID_KP_DOCUMENT_SIGNING_ID,
            ]
        )

        not_valid_after = datetime.now(timezone.utc) + self._lifetime
        builder = (
            x509.CertificateBuilder(
                issuer_name=self._ca_cert.subject,
                subject_name=subject_name,
                serial_number=x509.random_serial_number(),
                not_valid_before=datetime.now(timezone.utc),
                not_valid_after=not_valid_after,
                public_key=csr.public_key(),
            )
            .add_extension(certificate_policies_extension, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(san_extension, critical=False)
            .add_extension(key_usage, critical=True)
            .add_extension(ext_key_usage, critical=True)
        )
        return builder

    def generate(self, csr: x509.CertificateSigningRequest, record: UZIRecord):
        cert_builder = self._build(csr, record)

        signed = cert_builder.sign(
            private_key=self._ca_key,
            algorithm=hashes.SHA512(),
        )
        return signed
