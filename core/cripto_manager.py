"""
Implementación de cifrado y descifrado de archivos con AES-256-GCM.
La clase simétrica se protege cifrándola con la clave pública RSA del usuario.
"""
import base64, json, os
from core.json_manager import ensure_dir, write_json, delete_file, read_json
from core.user_manager import get_admin_public_key, get_user_rol
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

USER_FILE = os.path.join("jsons", "users.json")

    #TODO: hay que manejar correctamente los errores
def aes_encrypt_data(aes_key, nonce, plaintext):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    return  encryptor.tag, ciphertext

def aes_decrypt_data(aes_key, nonce, tag, ciphertext):
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext

def rsa_encrypt_key(aes_key: bytes, public_key_pem: str):
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    enc_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return enc_key

def rsa_decrypt_key(enc_key: str, private_key_pem: str, password: bytes):

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=password
    )

    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return aes_key

def load_user_certificate(username):
    cert_path = f"AC1/nuevoscerts/{username}.crt.pem"
    if not os.path.exists(cert_path):
        raise ValueError(f"El certificado del usuario '{username}' no existe.")
    
    with open(cert_path, "rb") as f:
        cert_pem = f.read()
        cert = x509.load_pem_x509_certificate(cert_pem)
    return cert

def load_ca_certificate():
    ac_cert_path = "AC1/ac1cert.pem"
    if not os.path.exists(ac_cert_path):
        raise ValueError("El certificado de la CA no existe.")
    
    with open(ac_cert_path, "rb") as f:
        ac_cert_pem = f.read()
        ac_cert = x509.load_pem_x509_certificate(ac_cert_pem)
    return ac_cert

def encrypt_file(filepath, username, private_key_pem, password, output_dir="data"):
    """Cifra un archivo con AES-GCM y protege la clave AES con RSA"""
    try:
        ensure_dir(output_dir)

        # Leer archivo
        with open(filepath, "rb") as f:
            plaintext = f.read()
        
        # Generar clave AES y nonce
        aes_key = os.urandom(32)
        nonce = os.urandom(12)

        # Cifrar con AES-GCM
        encryptor_tag, ciphertext = aes_encrypt_data(aes_key, nonce, plaintext)

        # Firmar el archivo
        signature = sign_file(plaintext, private_key_pem, password)
        
        # Obtener y cifrar claves
        public_key_pem = get_public_key(username)
        enc_key_user = rsa_encrypt_key(aes_key, public_key_pem)
        
        # Cifrar también con clave del admin
        try:
            admin_pub = get_admin_public_key()
            enc_key_admin = rsa_encrypt_key(aes_key, admin_pub)
        except Exception as e:
            print(f"Advertencia: No se pudo cifrar con clave admin: {e}")
            enc_key_admin = b""

        # Guardar archivo cifrado
        filename = os.path.basename(filepath)
        bin_path = os.path.join(output_dir, f"{filename}.bin")
        
        with open(bin_path, "wb") as f:
            f.write(nonce + encryptor_tag + ciphertext)
        
        # Guardar metadatos
        metadata = {
            "filename": filename,
            "signer": username,
            "enc_key_user": base64.b64encode(enc_key_user).decode(),
            "enc_key_admin": base64.b64encode(enc_key_admin).decode() if enc_key_admin else "",
            "algorithm": "AES-256-GCM",
            "signature": base64.b64encode(signature).decode(),
            "signature_algorithm": get_signature_algorithm_info()
        }
        
        write_json(os.path.join(output_dir, f"{filename}.json"), metadata)
        delete_file(filepath)
        
        print(f"Archivo '{filename}' cifrado y firmado correctamente")
        return filename
        
    except Exception as e:
        print(f"Error al cifrar archivo: {e}")
        raise ValueError(f"Error en cifrado: {str(e)}")


def decrypt_file(filename, private_key_pem, password, username=None, input_dir="data"):
    """Descifra un archivo cifrado con AES-GCM"""
    try:
        bin_path = os.path.join(input_dir, f"{filename}.bin")
        json_path = os.path.join(input_dir, f"{filename}.json")

        if not os.path.exists(bin_path) or not os.path.exists(json_path):
            raise ValueError("Archivos cifrados no encontrados")

        # Leer metadatos
        meta = read_json(json_path)
        role = get_user_rol(username) if username else "user"
        
        # Seleccionar clave según rol
        if role == "admin" and meta.get("enc_key_admin"):
            enc_key = base64.b64decode(meta["enc_key_admin"])
        else:
            enc_key = base64.b64decode(meta["enc_key_user"])
            
        signature = base64.b64decode(meta["signature"])
        signer = meta["signer"]

        # Leer datos cifrados
        with open(bin_path, "rb") as f:
            nonce = f.read(12)
            tag = f.read(16)
            ciphertext = f.read()

        # Descifrar clave AES
        aes_key = rsa_decrypt_key(enc_key, private_key_pem, password)

        # Descifrar con AES-GCM
        plaintext = aes_decrypt_data(aes_key, nonce, tag, ciphertext)

        # Verificar certificado y firma
        cert_user = load_user_certificate(signer)
        cert_ca = load_ca_certificate()

        if not verify_signature_signed_by_ca(cert_user, cert_ca):
            raise ValueError("Certificado del usuario no verificado por la CA")

        public_key = cert_user.public_key()

        if not verify_signature(signature, plaintext, public_key):
            raise ValueError("Firma digital inválida - archivo posiblemente manipulado")

        # Guardar archivo descifrado
        original_name = meta.get("filename", filename)
        nombre_sin_ext, ext = os.path.splitext(original_name)
        output_path = os.path.join(input_dir, f"{nombre_sin_ext}_descifrado{ext}")
        
        with open(output_path, "wb") as f:
            f.write(plaintext)
        
        print(f"Archivo '{filename}' descifrado y verificado correctamente")
        return output_path
        
    except Exception as e:
        print(f"Error al descifrar archivo: {e}")
        raise ValueError(f"Error en descifrado: {str(e)}")
    
def get_signature_algorithm_info():
    """Devuelve información sobre el algoritmo de firma utilizado"""
    return {
        "algorithm": "RSA-PSS",
        "hash": "SHA256",
        "padding": "PSS with MGF1",
        "key_size": 2048
    }

def sign_file(plaintext, private_key_pem, password):
    """Firma un archivo usando RSA-PSS con SHA256"""
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=password
        )
        
        signature = private_key.sign(
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        algo_info = get_signature_algorithm_info()
        print(f"Archivo firmado correctamente - Algoritmo: {algo_info['algorithm']}, Hash: {algo_info['hash']}")
        
        return signature
        
    except Exception as e:
        print(f"Error al firmar archivo: {e}")
        raise ValueError(f"Error en firma digital: {str(e)}")

def verify_signature(signature, plaintext, public_key):
    """Verifica una firma digital usando RSA-PSS con SHA256"""
    # public_key_pem viene como str, hay que pasarlo a bytes
    try:
        public_key.verify(
            signature,
            plaintext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"Firma digital inválida: {e}")
        return False


def verify_signature_signed_by_ca(cert_user, cert_ca):
    """Verifica que el certificado del usuario esté firmado por la CA"""
    ca_public_key = cert_ca.public_key()

    try:
        ca_public_key.verify(
            cert_user.signature,
            cert_user.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_user.signature_hash_algorithm
        )
    except Exception as e:
        print(f"Firma digital inválida: {e}")
        return False
    
    return True

def get_public_key(username: str):
    """Devuelve la clave pública PEM de un usuario."""
    users = read_json(USER_FILE)

    # Verificar que el usuario existe
    if username not in users:
        raise ValueError(f"⚠️ El usuario '{username}' no existe en users.json.")

    try:
        # Recuperar public_key desde Base64 y convertirlo a string PEM
        public_pem_b64 = users[username]["public_key"]
        public_pem = base64.b64decode(public_pem_b64).decode()
        return public_pem

    except Exception as e:
        raise ValueError(f"⚠️ Error al recuperar la clave pública de '{username}': {e}")
   
#__all__ = ["encrypt_file", "decrypt_file"]