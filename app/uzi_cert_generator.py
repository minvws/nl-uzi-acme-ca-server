from cryptography.x509.oid import ExtendedKeyUsageOID, ObjectIdentifier
from cryptography import x509
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.hazmat.primitives import hashes

from pyasn1.type import univ, char, namedtype
from app.uzi_record import UZIRecord
from pyasn1.codec.der.encoder import encode





class UziSequence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "Upn",
            univ.Sequence(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType("Id", univ.ObjectIdentifier()),
                    namedtype.NamedType("Tag", char.UTF8String()),
                )
            ),
        ),
        namedtype.NamedType(
            "Uzi",
            univ.Sequence(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType("Id", univ.ObjectIdentifier()),
                    namedtype.NamedType("Tag", char.UTF8String()),
                )
            ),
        ),
    )

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
    
    def _resolve_san(self, record: UZIRecord) -> x509.SubjectAlternativeName:
        
        
        uzi_seq = UziSequence()
        upn_id = univ.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")
        uzi_seq['Upn']['Id'] = upn_id

        upn_tag = f"{record.uzi_nr}@{record.subscription_nr}"
        uzi_seq['Upn']['Tag'] = upn_tag

        uzi_id = univ.ObjectIdentifier("2.5.5.5")
        uzi_seq["Uzi"]['Id'] = uzi_id

        OID_UZI_NAMED_EMPLOYEE_TEST = "2.16.528.1.1007.99.212"
        uzi_tag = f"{OID_UZI_NAMED_EMPLOYEE_TEST}-{record.version}-{record.uzi_nr}-{record.card_type}-{record.subscription_nr}-{record.role}-{record.abg_code}"
        uzi_seq["Uzi"]['Tag'] = uzi_tag
        
        # Encode the UziSequence to DER format
        uzi_seq_der = encode(uzi_seq)

        # Add UziSequence to the SAN extension
        general_name = x509.OtherName(
            type_id=ObjectIdentifier("1.2.3.4.5.6.7.8.9"),  # Custom OID for the UziSequence
            value=uzi_seq_der
        )

        return x509.SubjectAlternativeName(general_names=[general_name])

    def _build(self, csr: x509.CertificateSigningRequest, record: UZIRecord) -> x509.CertificateBuilder:
        certificate_policies_extension = self._resolve_cert_policies()
        san_extension = self._resolve_san(record)


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
