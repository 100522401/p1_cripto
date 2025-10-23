"""
Implementación de cifrado y descifrado de archivos con AES-256-GCM.
La clase simétrica se protege cifrándola con la clave pública RSA del usuario.
"""
import base64, json, os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

def encrypt_file(filepath, public_key_pem, output_dir="data"):
    """Cifra un archivo con AES-GCM y protege la clave AES con RSA"""
    with open(filepath, "rb") as f:
        plaintext = f.read()
    
    key = os.urandom(32)
    nonce = os.urandom(12)

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    enc_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # se crea el directorio 'data' en caso de que no exista
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    filename = os.path.basename(filepath)
    with open(os.path.join(output_dir, f"{filename}.bin"), "wb") as f:
        f.write(nonce + encryptor.tag + ciphertext)
    
    metadata = {
        "filename": filename,
        "enc_key": base64.b64encode(enc_key).decode(),
        "algorithm": "AES-256-GCM"
    }
    with open(os.path.join(output_dir, f"{filename}.json"), "w") as f:
        json.dump(metadata, f, indent=4)
    
    os.remove(filepath)
    print(f"Archivo '{filename}' cifrado correctamente")


def decrypt_file(filename, private_key_pem, password, input_dir="data"):
    """Descifra un archivo cifrado con AES-GCM, usando RSA para recuperar la clave"""
    with open(os.path.join(input_dir, f"{filename}.bin"), "rb") as f:
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()
    with open(os.path.join(input_dir, f"{filename}.json"), "r") as f:
        meta = json.load(f)
    
    enc_key = base64.b64decode(meta["enc_key"])

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=password
    )

    key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    output_path = os.path.join(input_dir, f"{filename}_descifrado.txt")
    with open(output_path, "wb") as f:
        f.write(plaintext)
    
    print(f"Archivo '{filename}' descifrado correctamente")


__all__ = ["encrypt_file", "decrypt_file"]