import csv
from datetime import datetime
import requests
from OpenSSL.crypto import load_crl, FILETYPE_ASN1

class Validity():
    def __init__(self, certificate):
        self.__certificate = certificate
        self.__total = 0
    
    def __trust_check(self, file = "hidden/CCAD_root_intermediate.csv"):
        with open(file, "r", encoding="utf-8", newline='') as fs:
            authorities = csv.DictReader(fs, delimiter = ',', dialect = csv.unix_dialect)
            for authority in authorities:
                if self.__certificate.get_issuer()["commonName"] == authority["Certificate Name"]:
                    self.__total += 100
                    return True, 100
        fs.close()
        return False, 0
    
    def __expiry_check(self):
        today = datetime.today().timestamp()
        not_before, not_after = self.__certificate.get_expiry()
        if not_before.timestamp() <= today and not_after.timestamp() >= today:
            self.__total += 100
            return True, 100
        return False, 0

    def __invalid_check(self):
        if self.__certificate.get_crl() is None:
            self.__total += 100
            return True, 100
        
        for crl in self.__certificate.get_crl():
            response = requests.get(crl, timeout = 10)
            revoked_certs = load_crl(FILETYPE_ASN1, response.content)
            for revoked_cert in revoked_certs.get_revoked():
                if self.__certificate.get_serial_number() == revoked_cert.get_serial().decode('utf-8'):
                    return False, 0

        self.__total += 100
        return True, 100
    
    def __secure_check(self):
        secure_signatures = ["SHA1", "SHA2", "SHA3", "SHA224", "SHA256", "SHA384", "SHA512", "BLAKE2b512", \
                    "BLAKE2s256", "BLAKE2s256"]
        for hash in secure_signatures:
            if hash in self.__certificate.get_signature_algorithm().upper():
                self.__total += 100
                return True, 100
        return False, 0
    
    def run(self, result):
        status, score = self.__trust_check()
        result.add_module("Trust Check", "Certificate is signed by well known CA",
                          "[bold green]Pass[/bold green]" if status else "[bold red][Fail][/bold red]", str(score))
        
        status, score = self.__expiry_check()
        result.add_module("Expiry Check", "Certificate is not expired",
                          "[bold green]Pass[/bold green]" if status else "[bold red][Fail][/bold red]", str(score))
        
        status, score = self.__invalid_check()
        result.add_module("Invalid Check", "Certificate is not revoked (pass if CRL is absent)",
                          "[bold green]Pass[/bold green]" if status else "[bold red][Fail][/bold red]", str(score))
        
        status, score = self.__secure_check()
        result.add_module("Secure Check", "Certificate is using secure signature algorithm",
                          "[bold green]Pass[/bold green]" if status else "[bold red][Fail][/bold red]", str(score))
        return result, self.__total
    
    def get_cert(self):
        return self.__certificate