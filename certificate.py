from pprint import pprint
from OpenSSL.crypto import load_certificate, FILETYPE_ASN1
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from dateutil.parser import parse


class Certificate():
    def __init__(self, asn1, pem):
        self.__raw = load_certificate(FILETYPE_ASN1, asn1)
        self.__certificate = pem
        self.__subject = dict((attribute, value) for ((attribute, value),) in self.__certificate.get("subject"))
        self.__issuer = dict((attribute, value) for ((attribute, value),) in self.__certificate.get("issuer"))
        self.__subject_alt_names = set((dict(self.__certificate.get("subjectAltName")).values()))
        self.__crl_distribution_points = list(self.__certificate.get("crlDistributionPoints")) \
                if self.__certificate.get("crlDistributionPoints") is not None else None
        self.__serial_number = self.__raw.get_serial_number()
        self.__not_before = parse(self.__raw.get_notBefore())
        self.__not_after = parse(self.__raw.get_notAfter())
        #self.__public_key = self.__raw.get_pubkey().to_cryptography_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        self.__key_length = self.__raw.get_pubkey().bits()
        self.__signature_algorithm = self.__raw.get_signature_algorithm().decode("utf-8")

    def get_issuer(self):
        return self.__issuer
    def get_expiry(self):
        return self.__not_before, self.__not_after
    def get_crl(self):
        return self.__crl_distribution_points
    def get_serial_number(self):
        return self.__serial_number
    def get_signature_algorithm(self):
        return self.__signature_algorithm
    def get_key_length(self):
        return self.__key_length
    def print(self):
        pprint(self.__certificate)
        
    def info(self, console):
        console.print("[u]Certificate Information[/u]", style = "bold")
        console.print("[bold]Common Name:[/bold]", self.__subject["commonName"])
        console.print("[bold]Subject Alternative Name(s):[/bold]")
        for name in self.__subject_alt_names:
            console.print("\t-", name)
        console.print("[bold]Issuer:[/bold]", self.__issuer["commonName"])
        
        console.print("[bold]Certificate Revocation List:[/bold]", end=" ")
        if self.__crl_distribution_points is not None:
            console.print()
            for crl in self.__crl_distribution_points:
                console.print("\t-", crl)
        else:
            console.print("[yellow]None[/yellow]")
        
        console.print("[bold]Serial Number:[/bold]", self.__serial_number)
        console.print("[bold]Thumbprint:[/bold]")
        console.print("[bold]Key length:[/bold]", self.__key_length)
        console.print("[bold]Signature Algorithm:[/bold]", self.__signature_algorithm)
        console.print("[bold]Validity Period:[/bold]", str(self.__not_before), "to" , str(self.__not_after))
        console.print()