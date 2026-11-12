"""A throwaway identity provider for tests: a key made here, its metadata, and answers signed per
case (ADR-0048). Grown from the round 4 library spike.

python3-saml's add_sign signs the element it is given, so an assertion is signed on its own and put
back into the Response, as an IdP does.
"""

import base64
import datetime as dt
import uuid
import zlib
from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlsplit
from xml.sax.saxutils import escape

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from onelogin.saml2.utils import OneLogin_Saml2_Utils

PUBLIC_URL = "https://argus.example.test"  # python3-saml refuses a host with no dot
ACS = PUBLIC_URL + "/api/v1/auth/saml/acs"
SP_ENTITY = PUBLIC_URL + "/api/v1/auth/saml/metadata"
IDP_ENTITY = "https://idp.example.test/realm"
IDP_SSO = "https://idp.example.test/sso"
PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
TRANSIENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
_ASSERTION = "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion"
_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"


def keypair(name: str = "test-idp") -> tuple[str, str]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    pem_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return pem_key, cert.public_bytes(serialization.Encoding.PEM).decode()


def _bare(cert: str) -> str:
    return "".join(line for line in cert.splitlines() if "CERTIFICATE" not in line)


def metadata(*certs: str, entity_id: str = IDP_ENTITY) -> str:
    keys = "".join(
        '<md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>'
        f"{_bare(c)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"
        for c in certs
    )
    return (
        '<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
        f'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="{entity_id}">'
        '<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
        f"{keys}"
        '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" '
        f'Location="{IDP_SSO}"/></md:IDPSSODescriptor></md:EntityDescriptor>'
    )


def request_id(location: str) -> str:
    """The AuthnRequest id from the IdP URL the login start redirected to."""
    encoded = parse_qs(urlsplit(location).query)["SAMLRequest"][0]
    xml = zlib.decompress(base64.b64decode(encoded), -15)
    return str(etree.fromstring(xml).get("ID"))


def _when(t: dt.datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Answer:
    in_response_to: str | None
    name_id: str = "nameid-alice"
    name_id_format: str = PERSISTENT
    email: str = "alice@example.test"
    groups: list[str] = field(default_factory=lambda: ["sec-team"])
    audience: str = SP_ENTITY
    destination: str = ACS
    recipient: str = ACS
    issuer: str = IDP_ENTITY
    minutes: int = 5
    issued_minutes_ago: int = 0
    assertion_id: str = field(default_factory=lambda: f"_{uuid.uuid4().hex}")
    assertions: int = 1

    def _assertion(self, number: int) -> str:
        now = dt.datetime.now(dt.UTC) - dt.timedelta(minutes=self.issued_minutes_ago)
        until = _when(now + dt.timedelta(minutes=self.minutes))
        irt = f' InResponseTo="{self.in_response_to}"' if self.in_response_to else ""
        groups = "".join(
            f"<saml:AttributeValue>{escape(g)}</saml:AttributeValue>" for g in self.groups
        )
        aid = self.assertion_id if number == 0 else f"{self.assertion_id}-{number}"
        return (
            f'<saml:Assertion ID="{aid}" Version="2.0" IssueInstant="{_when(now)}">'
            f"<saml:Issuer>{self.issuer}</saml:Issuer>"
            f'<saml:Subject><saml:NameID Format="{self.name_id_format}">{escape(self.name_id)}'
            "</saml:NameID>"
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData NotOnOrAfter="{until}" '
            f'Recipient="{self.recipient}"{irt}/>'
            "</saml:SubjectConfirmation></saml:Subject>"
            f'<saml:Conditions NotBefore="{_when(now - dt.timedelta(minutes=1))}" '
            f'NotOnOrAfter="{until}"><saml:AudienceRestriction>'
            f"<saml:Audience>{self.audience}</saml:Audience></saml:AudienceRestriction>"
            "</saml:Conditions>"
            f'<saml:AuthnStatement AuthnInstant="{_when(now)}" SessionIndex="_s1">'
            "<saml:AuthnContext><saml:AuthnContextClassRef>"
            "urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>"
            "</saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement>"
            f'<saml:Attribute Name="email"><saml:AttributeValue>{escape(self.email)}'
            "</saml:AttributeValue></saml:Attribute>"
            f'<saml:Attribute Name="groups">{groups}</saml:Attribute>'
            "</saml:AttributeStatement></saml:Assertion>"
        )

    def xml(self) -> str:
        now = _when(dt.datetime.now(dt.UTC))
        irt = f' InResponseTo="{self.in_response_to}"' if self.in_response_to else ""
        body = "".join(self._assertion(n) for n in range(self.assertions))
        return (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
            'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" '
            f'IssueInstant="{now}" Destination="{self.destination}"{irt}>'
            f"<saml:Issuer>{self.issuer}</saml:Issuer><samlp:Status>"
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>'
            f"</samlp:Status>{body}</samlp:Response>"
        )

    def signed(self, key: str, cert: str) -> str:
        """The answer with each assertion signed, base64 as the IdP posts it."""
        doc = etree.fromstring(self.xml().encode())
        for assertion in doc.findall(_ASSERTION):
            signed = OneLogin_Saml2_Utils.add_sign(
                etree.tostring(assertion),
                key,
                cert,
                sign_algorithm=_RSA_SHA256,
                digest_algorithm=_SHA256,
            )
            doc.replace(assertion, etree.fromstring(signed))
        return base64.b64encode(etree.tostring(doc)).decode()

    def unsigned(self) -> str:
        return base64.b64encode(self.xml().encode()).decode()
