"""
Implementación de cifrado y descifrado de archivos con AES-256-GCM.
La clase simétrica se protege cifrándola con la clave pública RSA del usuario.
"""
import base64, json, os
from core.json_manager import ensure_dir, write_json, delete_file, read_json
from core.user_manager import get_admin_public_key, get_user_rol
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

USER_FILE = os.path.join("jsons", "users.json")

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



def encrypt_file(filepath, public_key_pem, private_key_pem, password, output_dir="data"):
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

    signature = sign_file(plaintext, private_key_pem, password)

    # Cifrar clave AES con RSA pública del usuario
    enc_key_user = rsa_encrypt_key(aes_key, public_key_pem)
    
    # Clave cifrada con pública del admin
    try:
        admin_pub = get_admin_public_key()
        enc_key_admin = rsa_encrypt_key(aes_key, admin_pub)
    except Exception as e:
        raise ValueError(f"No se pudo obtener la clave pública del admin: {e}")
    
    # Se crea el directorio 'data' en caso de que no exista (destino de archivos cifrados/descifrados por defecto)
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Guardar archivo cifrado binario (.bin)
    filename = os.path.basename(filepath)
    with open(os.path.join(output_dir, f"{filename}.bin"), "wb") as f:
        f.write(nonce + encryptor_tag + ciphertext)
    
    # Guardar metadatos (.json)
    metadata = {
        "filename": filename,
        "enc_key_user": base64.b64encode(enc_key_user).decode(),
        "enc_key_admin": base64.b64encode(enc_key_admin).decode(),
        "algorithm": "AES-256-GCM",
        "signature": base64.b64encode(signature).decode()

    }
    write_json(os.path.join(output_dir, f"{filename}.json"), metadata)
    
    #with open(os.path.join(output_dir, f"{filename}.json"), "w") as f:
     #  json.dump(metadata, f, indent=4)


    #os.remove(filepath)
    
    # Borrar archivo original
    delete_file(filepath)
    print(f"Archivo '{filename}' cifrado correctamente")

    return filename


def decrypt_file(filename, private_key_pem, public_key_pem, password, username=None, input_dir="data"):
    """Descifra un archivo cifrado con AES-GCM, usando RSA para recuperar la clave"""
    #with open(os.path.join(input_dir, f"{filename}.json"), "r") as f:
     #   meta = json.load(f)
    
    bin_path = os.path.join(input_dir, f"{filename}.bin")
    json_path = os.path.join(input_dir, f"{filename}.json")

    # Leer metadatos
    meta = read_json(json_path)
    role = get_user_rol(username)
    if role == "admin":
        enc_key = base64.b64decode(meta["enc_key_admin"])
    else:
        enc_key = base64.b64decode(meta["enc_key_user"])
    signature = base64.b64decode(meta["signature"])
    # Leer binario 
    with open(bin_path, "rb") as f:
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    # Descifrar clave AES
    aes_key = rsa_decrypt_key(enc_key, private_key_pem, password)

    # Descifrar con AES-GCM
    plaintext = aes_decrypt_data(aes_key, nonce, tag, ciphertext)
    try:
        verify_signature(signature, plaintext, public_key_pem)
    except Exception as e:
        print(f"Error: {e}", "Acceso al archivo denegado")
        raise e

    # Recuperar nombre original y extensión
    original_name = meta.get("filename", filename)
    nombre_sin_ext, ext = os.path.splitext(original_name)
    output_path = os.path.join(input_dir, f"{nombre_sin_ext}_descifrado{ext}")
    
    with open(output_path, "wb") as f:
        f.write(plaintext)
    
    print(f"Archivo '{filename}' descifrado correctamente")
    

def sign_file(plaintext, private_key_pem, password):
    """Firma"""

    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=password
    )
    
    signature = private_key.sign(plaintext,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )

    return signature

def verify_signature(signature, plaintext, public_key_pem):
    """Verificación"""
    public_key = serialization.load_pem_public_key(public_key_pem)

    public_key.verify(
        signature,
        plaintext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

        
#__all__ = ["encrypt_file", "decrypt_file"]