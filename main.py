import tkinter as tk
from tkinter import messagebox
import json
import os
import base64

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# ====================================================
# FUNCIONES PRINCIPALES
# ====================================================

def iniciar_sesion():
    #coge datos de interfaz
    username = entry_username_login.get()
    password = entry_password_login.get()

    #Error en caso de no introducir los campos necesarios
    if not username or not password:
        messagebox.showwarning("Campos vacíos", "Por favor, rellene todos los campos.")
    else:
        #Cargamos fichero users.json
        with open(f"jsons/users.json", "r", encoding="utf-8") as f:
            user_data = json.load(f)

        if username not in user_data:
            messagebox.showerror("Error", "Usuario no encontrado.")
            return

        salt_b64 = user_data[username]["salt"]
        hash_b64_user = user_data[username]["password_hash"]

        #pasamos la salt y el hash de la password de b64 -> binario
        salt = base64.b64decode(salt_b64)
        user_password_hash = base64.b64decode(hash_b64_user)

            
        kdf_auth = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )

        #hacemos el hash de la password que ha entrado como input

        try:
            #verificar contraseña
            #verify ya hace el hash internamente y lo compara, por lo tanto no es necesairo usar derive
            kdf_auth.verify(password.encode(), user_password_hash)
            messagebox.showinfo("Inicio de sesión", f"Bienvenido, {username}!")
        except Exception:
            messagebox.showerror("Error", "Contraseña incorrecta.")



def registrar_user():
    username = entry_username_reg.get()
    password = entry_password_reg.get()

    if not username or not password:
        messagebox.showwarning("Campos vacíos", "Por favor, complete todos los campos.")
    else:
        

        #genero hash de la password con scrypt
        #Uso scrypt ya que SHA fue diseñado para detectar cambios de datos y no para autenticacion
        #SHA + rápido --> + vulnerable a ataques fuerza bruta
        #Scrypt fue diseñado para proteger contraseñas(bloquea ram para evitar ataques masivos && salt evita rainbow tables)
        salt = os.urandom(16)
        kdf_auth = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        )

        # password.encode() --> Scrypt solo acepta bytes
        password_hash = kdf_auth.derive(password.encode())


        # Convertir los bytes en texto base64 para que JSON pueda guardarlos

        salt_b64 = base64.b64encode(salt).decode("utf-8")
        hash_b64 = base64.b64encode(password_hash).decode("utf-8")

        # Si el archivo existe, lo cargamos

        if os.path.exists("jsons/users.json"):
            with open("jsons/users.json", "r", encoding="utf-8") as f:
                try:
                    users = json.load(f)
                except json.JSONDecodeError:
                    users = {}
        else:
            users = {}


        # Verificar si ya existe el usuario
        if username in users:
            messagebox.showerror("Error", "El usuario ya existe.")
            return


        # escribimos en el fichero de datos los datos del usuario

        users[username] = {
        "password_hash": hash_b64,
        "salt": salt_b64
        }

        # Guardar todo el diccionario actualizado
        with open("jsons/users.json", "w", encoding="utf-8") as f:
            json.dump(users, f, indent=4)

        messagebox.showinfo("Registro exitoso", f"username '{username}' registrado correctamente.")
        mostrar_login()


def mostrar_registro():
    frame_login.pack_forget()
    frame_registro.pack(expand=True)


def mostrar_login():
    frame_registro.pack_forget()
    frame_login.pack(expand=True)


# ====================================================
# CONFIGURACIÓN DE LA VENTANA PRINCIPAL
# ====================================================

root = tk.Tk()
root.title("🔐 Sistema de Login y Registro")
root.geometry("400x400")
root.configure(bg="#E8EEF1")  # Fondo general gris-azulado
root.resizable(False, False)

# ====================================================
# ESTILOS REUTILIZABLES
# ====================================================

COLOR_PRINCIPAL = "#2D6A4F"   # Verde oscuro
COLOR_SECUNDARIO = "#95D5B2"  # Verde claro
COLOR_TEXTO = "#1B4332"       # Texto principal

fuente_titulo = ("Helvetica", 16, "bold")
fuente_label = ("Helvetica", 11)
fuente_boton = ("Helvetica", 10, "bold")

# ====================================================
# FRAME LOGIN
# ====================================================

frame_login = tk.Frame(root, bg="#E8EEF1")
frame_login.pack(expand=True)

tk.Label(frame_login, text="INICIO DE SESIÓN", font=fuente_titulo, fg=COLOR_TEXTO, bg="#E8EEF1").pack(pady=15)

tk.Label(frame_login, text="Usuario:", font=fuente_label, bg="#E8EEF1").pack()
entry_username_login = tk.Entry(frame_login, width=30, bd=2, relief="groove", justify="center")
entry_username_login.pack(pady=8)

tk.Label(frame_login, text="Contraseña:", font=fuente_label, bg="#E8EEF1").pack()
entry_password_login = tk.Entry(frame_login, show="*", width=30, bd=2, relief="groove", justify="center")
entry_password_login.pack(pady=8)

tk.Button(
    frame_login,
    text="Iniciar sesión",
    command=iniciar_sesion,
    bg=COLOR_PRINCIPAL,
    fg="white",
    font=fuente_boton,
    activebackground=COLOR_SECUNDARIO,
    relief="flat",
    width=20,
    height=1
).pack(pady=15)

tk.Button(
    frame_login,
    text="Crear cuenta nueva",
    command=mostrar_registro,
    bg="#CAD2C5",
    fg=COLOR_TEXTO,
    font=fuente_boton,
    relief="flat"
).pack()

# ====================================================
# FRAME REGISTRO
# ====================================================

frame_registro = tk.Frame(root, bg="#E8EEF1")

tk.Label(frame_registro, text="REGISTRO DE username", font=fuente_titulo, fg=COLOR_TEXTO, bg="#E8EEF1").pack(pady=15)

tk.Label(frame_registro, text="Nuevo username:", font=fuente_label, bg="#E8EEF1").pack()
entry_username_reg = tk.Entry(frame_registro, width=30, bd=2, relief="groove", justify="center")
entry_username_reg.pack(pady=8)

tk.Label(frame_registro, text="Contraseña:", font=fuente_label, bg="#E8EEF1").pack()
entry_password_reg = tk.Entry(frame_registro, show="*", width=30, bd=2, relief="groove", justify="center")
entry_password_reg.pack(pady=8)

tk.Button(
    frame_registro,
    text="Registrar",
    command=registrar_user,
    bg=COLOR_PRINCIPAL,
    fg="white",
    font=fuente_boton,
    activebackground=COLOR_SECUNDARIO,
    relief="flat",
    width=20,
    height=1
).pack(pady=15)

tk.Button(
    frame_registro,
    text="Volver al inicio",
    command=mostrar_login,
    bg="#CAD2C5",
    fg=COLOR_TEXTO,
    font=fuente_boton,
    relief="flat"
).pack()

# ====================================================
# BUCLE PRINCIPAL
# ====================================================

root.mainloop()
