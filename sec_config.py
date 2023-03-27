import ssl
from socket import create_connection

class SecurityConfig():
    def __init__(self, host, port = 443):
        self.__host = host
        self.__port = port
        self.__connection = None
        self.__certificate = None
        self.__total = 0
    
    def __del__(self):
        if self.__connection is not None:
            self.__connection.close()
        
    def __protocols(self):
        min = self.__connection.context.minimum_version
        if min == ssl.TLSVersion.SSLv3:
            self.__total += 25
            return "SSLv3.0", 25
        elif min == ssl.TLSVersion.TLSv1:
            self.__total += 50
            return "TLSv1.0", 50
        elif min == ssl.TLSVersion.TLSv1_1:
            self.__total += 75
            return "TLSv1.1", 75
        elif min == ssl.TLSVersion.TLSv1_2:
            self.__total += 100
            return "TLSv1.2", 100
        elif min == ssl.TLSVersion.TLSv1_3:
            self.__total += 100
            return "TLSv1.3", 100
        else:
            return "SSLv2.0", 0

    def __key_strength(self):
        length = self.__certificate.get_key_length()
        if length < 256:
            return length, 0
        elif length < 512:
            self.__total += 25
            return length, 25
        elif length < 1024:
            self.__total += 50
            return length, 50
        elif length >= 1024:
            self.__total += 100
            return length, 100
        else:
            raise Exception("Key length unclassified:", length)
    
    def __symmetric_cipher_strength(self):
        length = self.__connection.cipher()[2]
        if length < 128:
            return length, 0
        elif length < 256:
            self.__total += 50
            return length, 50
        elif length >= 256:
            self.__total += 100
            return length, 100
        else:
            raise Exception("Key length unclassified:", length)
    
    def run(self, result):
        status, score = self.__protocols()
        result.add_module("Protocols Supported", "Minimum version of SSL/TLS supported", status, str(score))
        
        status, score = self.__key_strength()
        result.add_module("Key Exchange Supported", "Length of private-public key pair", str(status), str(score))
        
        status, score = self.__symmetric_cipher_strength()
        result.add_module("Symmetric Cipher Supported", "Length of secret key", str(status), str(score))
        
        return result, self.__total
    
    def update(self, certificate):
        self.__certificate = certificate
    
    def connect(self):
        context = ssl.create_default_context()
        context.set_ciphers("ALL")
        context.set_ciphers('DEFAULT@SECLEVEL=1')
        context.check_hostname = False
        
        self.__connection = context.wrap_socket(
            create_connection((self.__host, self.__port), timeout=5),
            server_hostname = self.__host,
        )
        
        asn1 = self.__connection.getpeercert(True)
        pem = self.__connection.getpeercert()

        return asn1, pem
