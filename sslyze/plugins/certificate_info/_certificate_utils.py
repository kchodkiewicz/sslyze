from hashlib import sha256
import ipaddress
from typing import List, Dict, Union, Type, cast

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509 import ExtensionOID, ExtensionNotFound, NameOID, ObjectIdentifier
from cryptography.x509 import (DNSName, IPAddress, UniformResourceIdentifier,
                               DirectoryName, OtherName, RegisteredID, RFC822Name)
from cryptography.x509.extensions import DuplicateExtension  # type: ignore


_IP_ADDRESS_TYPE = Union[
    ipaddress.IPv4Address,
    ipaddress.IPv6Address,
    ipaddress.IPv4Network,
    ipaddress.IPv6Network,
]


def _san_to_str(san: Union[str, x509.Name, OtherName, ObjectIdentifier, _IP_ADDRESS_TYPE]) -> str:
    """"""
    if isinstance(san, x509.Name):
        return str(san.rfc4514_string())
    elif isinstance(san, OtherName):
        return f'oid={san.type_id.dotted_string}, name={san.value}'
    elif isinstance(san, ObjectIdentifier):
        return str(san.dotted_string)
    elif isinstance(san, _IP_ADDRESS_TYPE):
        return str(san)
    else:
        return san


def _extract_subject_alternative_names(certificate: x509.Certificate,
                                       san_type: Type[DNSName | IPAddress | UniformResourceIdentifier |
                                                      DirectoryName | OtherName | RegisteredID | RFC822Name]
                                       ) -> List[str]:
    """"""
    subj_alt_names: List[str] = []
    try:
        san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san_ext_value = cast(x509.SubjectAlternativeName, san_ext.value)
        san_list = san_ext_value.get_values_for_type(san_type)
        subj_alt_names = list(map(_san_to_str, san_list))
    except ExtensionNotFound:
        pass
    except DuplicateExtension:
        # Fix for https://github.com/nabla-c0d3/sslyze/issues/420
        # Not sure how browsers behave in this case but having a duplicate extension makes the certificate invalid
        # so we just return no SANs (likely to make hostname validation fail, which is fine)
        pass

    return subj_alt_names


def extract_dns_subject_alternative_names(certificate: x509.Certificate) -> List[str]:
    """Retrieve all the DNS entries of the Subject Alternative Name extension."""
    return _extract_subject_alternative_names(certificate, DNSName)


def extract_ip_subject_alternative_names(certificate: x509.Certificate) -> List[str]:
    """Retrieve all the IP Address entries of the Subject Alternative Name extension."""
    return _extract_subject_alternative_names(certificate, IPAddress)


def extract_all_subject_alternative_names(certificate: x509.Certificate) -> Dict[Type, List[str]]:
    """Retrieve all entries of the Subject Alternative Name extension.
    """
    return {
        DNSName: _extract_subject_alternative_names(certificate, DNSName),
        IPAddress: _extract_subject_alternative_names(certificate, IPAddress),
        UniformResourceIdentifier: _extract_subject_alternative_names(certificate, UniformResourceIdentifier),
        DirectoryName: _extract_subject_alternative_names(certificate, DirectoryName),
        OtherName: _extract_subject_alternative_names(certificate, OtherName),
        RFC822Name: _extract_subject_alternative_names(certificate, RFC822Name),
        RegisteredID: _extract_subject_alternative_names(certificate, RegisteredID),
    }


def get_common_names(name_field: x509.Name) -> List[str]:
    return [cn.value for cn in name_field.get_attributes_for_oid(NameOID.COMMON_NAME)]  # type: ignore


def get_public_key_sha256(certificate: x509.Certificate) -> bytes:
    pub_bytes = certificate.public_key().public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    digest = sha256(pub_bytes).digest()
    return digest
