import os
import base64
from core.json_manager import read_json, write_json
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

USER_FILE = os.path.join("jsons", "users.json")

def sign_up(username: str, password: str) -> bool:
    """Registra un nuevo usuario si no existe ya."""
    if not username or not password:
        raise ValueError("Usuario y contraseña no pueden estar vacíos.")

    users = read_json(USER_FILE)

    if username in users:
        return False

    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )

    # password.encode() --> Scrypt solo acepta bytes
    password_hash = kdf.derive(password.encode())

    # Convertir los bytes en texto base64 para que JSON pueda guardarlos
    users[username] = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "password_hash": base64.b64encode(password_hash).decode("utf-8"),
    }

    # escribimos en el fichero de datos los datos del usuario
    write_json(USER_FILE, users)

    return True

def log_in(username: str, password: str) -> bool:
    """Comprueba si las credenciales del usuario son correctas."""
    users = read_json(USER_FILE)
    if username not in users:
        return False

    import base64
    salt = base64.b64decode(users[username]["salt"])
    stored_hash = base64.b64decode(users[username]["password_hash"])

    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    try:
        kdf.verify(password.encode(), stored_hash)
        return True
    except Exception:
        return False
