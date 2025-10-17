import os, json, base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def encrypt_file(filepath, public_key_pem):
    # Leer archivo
    with open(filepath, "rb") as f:
        plaintext = f.read()

    # Generar clave AES y nonce
    key = os.urandom(32)
    nonce = os.urandom(12)

    # Cifrado autenticado (AES-GCM)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Cifrar la clave AES con la clave pública RSA
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    enc_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Crear carpeta si no existe
    if not os.path.exists("data"):
        os.mkdir("data")

    # Guardar archivo cifrado
    filename = os.path.basename(filepath)
    with open(f"data/{filename}.bin", "wb") as f:
        f.write(nonce + encryptor.tag + ciphertext)

    # Guardar metadatos
    metadata = {
        "filename": filename,
        "enc_key": base64.b64encode(enc_key).decode(),
        "algorithm": "AES-256-GCM"
    }
    with open(f"data/{filename}.json", "w") as f:
        json.dump(metadata, f, indent=4)

    os.remove(filepath)
    print(f"Archivo '{filename}' cifrado correctamente.")


def decrypt_file(filename, private_key_pem, password=None):
    # Cargar archivo cifrado
    with open(f"data/{filename}.bin", "rb") as f:
        nonce = f.read(12)
        tag = f.read(16)
        ciphertext = f.read()

    # Cargar metadatos
    with open(f"data/{filename}.json", "r") as f:
        meta = json.load(f)
    enc_key = base64.b64decode(meta["enc_key"])

    # Descifrar clave AES con RSA
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Descifrar archivo
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(f"data/{filename}_descifrado.txt", "wb") as f:
        f.write(plaintext)

    print(f"Archivo '{filename}' descifrado correctamente.")


# BLOQUE DE PRUEBA INDEPENDIENTE
if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    # Generar claves RSA para pruebas
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    # Crear archivo de prueba
    with open("prueba.txt", "w") as f:
        f.write("Prueba criptojifewoijfweofiwejofwjefijweojfieowf owie foiwejf iweo .")

    # Cifrar y descifrar
    print("Cifrando archivo...")
    encrypt_file("prueba.txt", public_pem)
    print("Descifrando archivo...")
    decrypt_file("prueba.txt", private_pem)
    print("Prueba finalizada.")
