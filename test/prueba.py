from core.user_manager import sign_up, log_in
from core.cripto_manager import encrypt_file, decrypt_file
from cryptography.hazmat.primitives import serialization
import os

USER = "prueba_user"
PASS = "Password123!"
FICHERO = "test.txt"

# Crear archivo de prueba
with open(FICHERO, "w") as f:
    f.write("Texto secreto de prueba")

print("\n>> Registro")
try:
    sign_up(USER, PASS)
except:
    print("Usuario ya existía, continuando...")

print("\n>> Login")
private_key, public_pem = log_in(USER, PASS)

# Convertir clave privada a PEM cifrado
private_pem_str = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.BestAvailableEncryption(PASS.encode())
).decode()

print("\n>> Cifrado")
encrypt_file(FICHERO, public_pem.decode() if isinstance(public_pem, bytes) else public_pem)

print("\n>> Descifrado")
decrypt_file("test.txt", private_pem_str, PASS.encode(), username=USER)

print("\n< Prueba finalizada correctamente >")
