"""
Implementación de cifrado y descifrado de archivos con AES-256-GCM.
La clase simétrica se protege cifrándola con la clave pública RSA del usuario.
"""
import base64, json, os
from core.json_manager import ensure_dir, write_json, delete_file, read_json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
# TODO: refactorizar lo que se pueda con json_manager
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



def encrypt_file(filepath, public_key_pem, output_dir="data"):
    """Cifra un archivo con AES-GCM y protege la clave AES con RSA"""

    # se crea el directorio 'data' en caso de que no exista
    ensure_dir(output_dir)

    # Leer archivo
    with open(filepath, "rb") as f:
        plaintext = f.read()
    
    # Generar clave AES y nonce
    aes_key = os.urandom(32)
    nonce = os.urandom(12)

    # Cifrar con AES-GCM
    encryptor_tag, ciphertext = aes_encrypt_data(aes_key, nonce, plaintext)

    # Cifrar clave AES con RSA pública
    enc_key = rsa_encrypt_key(aes_key, public_key_pem)

    # Guardar archivo binario (.bin)
    filename = os.path.basename(filepath)
    with open(os.path.join(output_dir, f"{filename}.bin"), "wb") as f:
        f.write(nonce + encryptor_tag + ciphertext)
    
    # Guardar metadatos (.json)
    metadata = {
        "filename": filename,
        "enc_key": base64.b64encode(enc_key).decode(),
        "algorithm": "AES-256-GCM"
    }
    write_json(os.path.join(output_dir, f"{filename}.json"), metadata)
    
    #with open(os.path.join(output_dir, f"{filename}.json"), "w") as f:
     #  json.dump(metadata, f, indent=4)


    #os.remove(filepath)
    # Borrar archivo original
    delete_file(filepath)
    print(f"Archivo '{filename}' cifrado correctamente")

    return filename


def decrypt_file(filename, private_key_pem, password, input_dir="data"):
    """Descifra un archivo cifrado con AES-GCM, usando RSA para recuperar la clave"""
    #with open(os.path.join(input_dir, f"{filename}.json"), "r") as f:
     #   meta = json.load(f)
    
    bin_path = os.path.join(input_dir, f"{filename}.bin")
    json_path = os.path.join(input_dir, f"{filename}.json")

    # Leer metadatos
    meta = read_json(json_path)
    enc_key = base64.b64decode(meta["enc_key"])

    # Leer binario 
    with open(bin_path, "rb") as f:
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    # Descifrar clave AES
    aes_key = rsa_decrypt_key(enc_key, private_key_pem, password)

    # Descifrar con AES-GCM
    plaintext = aes_decrypt_data(aes_key, nonce, tag, ciphertext)

    output_path = os.path.join(input_dir, f"{filename}_descifrado.txt")
    with open(output_path, "wb") as f:
        f.write(plaintext)
    
    print(f"Archivo '{filename}' descifrado correctamente")
    
    return output_path

#__all__ = ["encrypt_file", "decrypt_file"]