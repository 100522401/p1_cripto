import os
import base64
import re
import subprocess
from core.json_manager import read_json, write_json
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

USER_FILE = os.path.join("jsons", "users.json")


# Regex para contraseñas:
#  - al menos 8 caracteres
#  - una mayúscula
#  - un número
#  - un símbolo
PASSWORD_REGEX = re.compile(r"^(?=.*[A-Z])(?=.*\d)(?=.*[^\w\s]).{8,}$")

def validate_password(password: str):
    """Valida que la contraseña cumpla la política de seguridad."""
    return bool(PASSWORD_REGEX.match(password))

def derive_kdf(salt:bytes):
    """Crea un objeto KDF (Scrypt)"""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf

def verify_password(kdf, password, stored_hash):
    """Verifica si una contraseña es correcta comparando hashes Scrypt."""
    try:
        kdf.verify(password.encode(), stored_hash)
    except Exception as e:
        print(f"Error en la verificación de la contraseña: {e}")
        return False
    return True
    

def generate_rsa_keys(password):
    """Genera claves RSA (pública + privada) y cifra la privada con la password"""
    try:

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        #print(private_key)
        public_key = private_key.public_key()

        # Se serializan las claves
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print("[RSA] Claves RSA generadas correctamente")
    except Exception as e:
        print(f"Error al generar claves RSA: {e}")
    return public_pem, private_pem


def get_user_rol(username: str):
    """Devuelve el rol del usuario ('user' o 'admin')."""
    users = read_json(USER_FILE)
    print(users.get(username, {}).get("rol", "user"))
    return users.get(username, {}).get("rol", "user")

def get_admin_public_key():
    """Devuelve la clave pública del usuario con rol 'admin'."""
    users = read_json(USER_FILE)

    for username, data in users.items():
        if data.get("rol") == "admin":
            return base64.b64decode(data["public_key"]).decode()

    # Si no hay ninguno
    raise ValueError("⚠️ No se encontró ningún usuario con rol 'admin' en users.json.")

def generate_csr(username, private_key_pem, password):
    """Genera un CSR y lo guarda en AC1/solicitudes"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=password.encode()
    )

    path = f"AC1/solicitudes/{username}.csr.pem"
    #Se crea la solicitud
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        #   x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        #   x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        #   x509.NameAttribute(NameOID.LOCALITY_NAME, "Getafe"),
        #   x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M"),
        #   x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "INF"),
          x509.NameAttribute(NameOID.COMMON_NAME, username),
    #Se firma la solicitud con la privada del usuario
    ])).sign(private_key, hashes.SHA256())

    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    return path

# def sign_csr_AC1(username):

#     csr_path = f"AC1/solicitudes/{username}.csr.pem"

#     args = ["openssl", "ca", "-in",
#              csr_path, "-notext", "-config",
#             "AC1/openssl_AC1.cnf"]

#     result = subprocess.run(args, capture_output=True, text=True)

#     if result.returncode != 0:
#         raise ValueError(f"Error al firmar el CSR: {result.stderr}")

#     cert_path = rename_cert(username)

#     return cert_path

def get_serial_for_user(username):
    """Le el ficheor index.txt y devulve el serial del usuario"""
    index_file = "AC1/index.txt"

    if not os.path.exists(index_file):
        return None
    
    with open(index_file, "r") as f:
        for line in f:
            if f"/CN={username}" in line:
                tokens = line.strip().split("\t")
                serial = tokens[3].strip()
                print(serial)
                return serial
        return None
    

def rename_cert(username):
    """Renombra el certificado del usuario"""

    #Ya fue renombrado
    renamed = f"AC1/nuevoscerts/{username}.crt.pem"
    if os.path.exists(renamed):
        return renamed
    
    #busca el serial
    
    serial = get_serial_for_user(username)  
    if not serial:
        return False
    
    old_path = f"AC1/nuevoscerts/{serial}.pem"
    new_path = f"AC1/nuevoscerts/{username}.crt.pem"

    if not os.path.exists(old_path):
        raise ValueError(f"El certificado {old_path} no existe")
    
    #Renombra
    os.rename(old_path, new_path)

    return new_path    
    
def check_cert(username):
    """Comprueba si se ha emitido el certificado del usuario"""

    users = read_json(USER_FILE)
    user = users.get(username)
    if not user:
        return False
    
    # cert_path existe y guardado en el json
    cert_path = user.get("cert_path")
    if cert_path and os.path.exists(cert_path):
        return True
    
    # cert_path existe con el nombre del usuario y no esta guardado en el json
    expected_path = f"AC1/nuevoscerts/{username}.crt.pem"
    if os.path.exists(expected_path):
        users[username]["cert_path"] = expected_path
        write_json(USER_FILE, users)
        return True

    # Caso en el que el certificado existe pero no ha sido renombrado
    renamed_path = rename_cert(username)
    if renamed_path and os.path.exists(renamed_path):
        users[username]["cert_path"] = renamed_path
        write_json(USER_FILE, users)
        return True
    
    return False

def sign_up(username: str, password: str): 
    """Registra un nuevo usuario"""

    if not username or not password:
        raise ValueError("Usuario y contraseña no pueden estar vacíos.")

    if not validate_password(password):
        raise ValueError(
            "La contraseña no cumple la política: "
            "mínimo 8 caracteres, una mayúscula, un número y un símbolo."
        )

    try:
        users = read_json(USER_FILE)
    except Exception as e:
        print("Error al leer el archivo de usuarios: {e}")
        return False
    
    if username in users:
        raise ValueError("El usuario ya existe. Escoja otro nombre.")

    try:
        # Generar salt y derivar hash de la password
        salt = os.urandom(16)
        kdf = derive_kdf(salt)
        password_hash = kdf.derive(password.encode())
        print("[Scrypt] Hash derivado correctamente")

        #Genero claves RSA (pública y privada)
        public_pem, private_pem = generate_rsa_keys(password)

        #Creo CSR
        csr_path = generate_csr(username, private_pem.decode(), password)

        #Se firma la CSR y se obtiene el CA (TODO: No sé si se debiera hacer aqui)

        #cert_path = sign_csr_AC1(username)

        # Convertir los bytes en texto base64 para que JSON pueda guardarlos
        users[username] = {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "password_hash": base64.b64encode(password_hash).decode("utf-8"),
            "public_key": base64.b64encode(public_pem).decode(),
            "private_key_enc": base64.b64encode(private_pem).decode(),
            "rol": "user",
            "cert_path": None,
            "csr_path": csr_path,
        }

        # Escribir en el fichero de datos los datos del usuario
        write_json(USER_FILE, users)
        print(f"Usuario '{username}' registrado correctamente.")

        return True
    
    except Exception as e:
        print(f"Error durante el registro: {e}")
        return False

def log_in(username: str, password: str) -> bool:
    """Comprueba si las credenciales del usuario son correctas."""
    try:
        users = read_json(USER_FILE)
    except Exception as e:
        print("Error al leer el archivo de usuarios: {e}")
        return False
    
    if username not in users:
        print("Usuario no encontrado.")
        return False

    try:

        salt = base64.b64decode(users[username]["salt"])
        stored_hash = base64.b64decode(users[username]["password_hash"])

        # Verficiar Hash de la contraseña
        kdf = derive_kdf(salt)
        if not verify_password(kdf, password, stored_hash):
            print("Usuario o contraseña erróneos.")
            return False
        

        # Cargo claves desde JSON
        private_pem_enc = base64.b64decode(users[username]["private_key_enc"])
        public_pem = base64.b64decode(users[username]["public_key"])

        # Descifrar clave privada
        try:
                
            private_key = serialization.load_pem_private_key(
                private_pem_enc,
                password=password.encode()
            )
        except Exception as e:
            print("Error al descifrar la clave privada.")
            return False

        
        if not check_cert(username):
            print("El certificado no ha sido emitido por la CA")
            return False

        print(f"Usuario '{username}' autenticado correctamente.")
        #print(private_key)

        return private_key, public_pem
    except Exception as e:
        print(f"Error durante el inicio de sesión: {e}")
        return False