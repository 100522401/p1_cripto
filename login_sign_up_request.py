import json
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

class SignUp:
    def __init__(self, username, password):
        self._username = username
        password = password.encode()      # Scrypt solo acepta bytes
        #genero hash de la password con scrypt
        #Uso scrypt ya que SHA fue diseñado para detectar cambios de datos y no para autenticacion
        #SHA + rápido --> + vulnerable a ataques fuerza bruta
        #Scrypt fue diseñado para proteger contraseñas(bloquea ram para evitar ataques masivos && salt evita rainbow tables)
        self._salt_auth = os.urandom(16)
        kdf_auth = Scrypt(
            salt=self._salt_auth,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )

        self._password_hash = kdf_auth.derive(password)

        #AES-GCM
        private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        )   

        public_key = private_key.public_key()

        #Serializar claves
        #Usaremos DER ya que es más compacto y ocupa menos espacio

        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            # PKCS8:Un formato más moderno para serializar claves que permite un mejor cifrado. Elija esta opción a menos que tenga requisitos explícitos de compatibilidad con versiones anteriores.        
            format=serialization.PrivateFormat.PKCS8,    
            # No necesito encriptar aqui ya que lo hare en aesgcm.encrypt         
            encryption_algorithm=serialization.NoEncryption()
        )

        self._public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,   
            # SubjectPublicKeyInfo: Este es el formato típico de clave pública. Consiste en un identificador de algoritmo y la clave pública como una cadena de bits. Opte por esta opción a menos que tenga necesidades específicas.
            format=serialization.PublicFormat.SubjectPublicKeyInfo  
        )

        self._salt_ec = os.urandom(16)
        kdf_ec = Scrypt(
            salt=self._salt_ec,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )

        AES_key = kdf_ec.derive(password)
        aesgcm = AESGCM(AES_key)
        self._nonce = os.urandom(12)
        aad = self._username.encode()
        self._ec_private_key_bytes = aesgcm.encrypt(self._nonce, private_key_bytes, aad)


    def to_json(self):
        return {
            "username": self._username,
            "password_hash": self._password_hash.hex(),
            "public_key": self._public_key_bytes.hex(),
            "ec_private_key_bytes": self._ec_private_key_bytes.hex(),
            "salt_auth": self._salt_auth.hex(),
            "salt_ec": self._salt_ec.hex(),
            "nonce": self._nonce.hex()
        }