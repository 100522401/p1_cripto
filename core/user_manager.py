import os
import base64
from core.json_manager import read_json, write_json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

USER_FILE = os.path.join("jsons", "users.json")

def sign_up(username: str, password: str) -> bool:
    """Registra un nuevo usuario si no existe ya."""
    if not username or not password:
        raise ValueError("Usuario y contraseña no pueden estar vacíos.")

    users = read_json(USER_FILE)

    if username in users:
        return False

    # Derivo hash y salt con Scrypt
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )

    password_hash = kdf.derive(password.encode())

    #Genero claves RSA (pública y privada)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    print(private_key)
    public_key = private_key.public_key()

    #Serializo las claves
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Convertir los bytes en texto base64 para que JSON pueda guardarlos
    users[username] = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "password_hash": base64.b64encode(password_hash).decode("utf-8"),
        "public_key": base64.b64encode(public_pem).decode(),
        "private_key_enc": base64.b64encode(private_pem).decode()
    }

    # escribimos en el fichero de datos los datos del usuario
    write_json(USER_FILE, users)
    print(f"Usuario '{username}' registrado correctamente.")

    return True

def log_in(username: str, password: str) -> bool:
    """Comprueba si las credenciales del usuario son correctas."""
    users = read_json(USER_FILE)
    if username not in users:
        print("❌ Usuario no encontrado.")
        return False

    salt = base64.b64decode(users[username]["salt"])
    stored_hash = base64.b64decode(users[username]["password_hash"])

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    try:
        kdf.verify(password.encode(), stored_hash)
    except Exception:
        print("Usuario o contraseña incorrectos.")
        return False

    # Cargo claves desde JSON
    private_pem_enc = base64.b64decode(users[username]["private_key_enc"])
    public_pem = base64.b64decode(users[username]["public_key"])

    # Descifro la clave privada con la contraseña
    try:
            
        private_key = serialization.load_pem_private_key(
            private_pem_enc,
            password=password.encode()
        )
    except:
        print("Error al descifrar la clave privada.")

    print(f"Usuario '{username}' autenticado correctamente.")
    print(private_key)

    return private_key, public_pem