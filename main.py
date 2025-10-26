import os
import tkinter as tk
from cryptography.hazmat.primitives import serialization
from tkinter import messagebox
from tkinter import filedialog
from core.user_manager import sign_up, log_in
from core.cripto_manager import encrypt_file, decrypt_file

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



def user_sign_up():
    # strip elimina los huecos en blanco
    username = entry_username_reg.get().strip()
    password = entry_password_reg.get()

    if not username or not password:
        messagebox.showwarning("Campos vacíos", "Por favor, complete todos los campos.")
        return

    try:
        registrado = sign_up(username, password)
        if registrado:
            messagebox.showinfo("Registro exitoso", f"Usuario '{username}' registrado correctamente.")
            clean_form_signup()
            show_log_in()
        else:
            messagebox.showerror("Error", "El usuario ya existe.")
    except ValueError as e:
        messagebox.showerror("Error", str(e))


def user_log_in():
    username = entry_username_login.get().strip()
    password = entry_password_login.get()

    if not username or not password:
        messagebox.showwarning("Campos vacíos", "Por favor, rellene todos los campos.")
        return

    resultado = log_in(username, password)
    clean_form_login()

    if resultado:
        private_key, public_key = resultado
        messagebox.showinfo("Inicio de sesión", f"Bienvenido, {username}!")
        # Serializamos la clave privada cifrada con la contraseña
        show_vault_screen(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
            ).decode(),
            public_key,
            password,
            username
        )
    else:
        messagebox.showerror("Error", "Usuario o contraseña incorrectos.")

def clean_form_login():
    """Vacía los campos del formulario de inicio de sesión."""
    entry_username_login.delete(0, tk.END)
    entry_password_login.delete(0, tk.END)

def clean_form_signup():
    """Vacía los campos del formulario de registro."""
    entry_username_reg.delete(0, tk.END)
    entry_password_reg.delete(0, tk.END)

def show_sign_up():
    frame_login.pack_forget()
    frame_registro.pack(expand=True)
    root.bind('<Return>', lambda event=None: user_sign_up())


def show_log_in():
    frame_registro.pack_forget()
    frame_login.pack(expand=True)
    clean_form_login()
    clean_form_signup()
    root.bind('<Return>', lambda event=None: user_log_in())


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
    command=user_log_in,
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
    command=show_sign_up,
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
    command=user_sign_up,
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
    command=show_log_in,
    bg="#CAD2C5",
    fg=COLOR_TEXTO,
    font=fuente_boton,
    relief="flat"
).pack()

# ====================================================
# FRAME CIFRADO/DESCIFRADO
# ====================================================

def show_vault_screen(private_pem, public_pem, password, username):
    # Oculta las otras pantallas
    frame_login.pack_forget()
    frame_registro.pack_forget()

    frame_vault = tk.Frame(root, bg="#E8EEF1")
    frame_vault.pack(expand=True)

    tk.Label(frame_vault, text="Almacén seguro", font=fuente_titulo, bg="#E8EEF1").pack(pady=15)

    def encrypt():
        ruta = filedialog.askopenfilename(title="Selecciona un archivo para cifrar")
        if not ruta:
            return
        encrypt_file(ruta, public_pem.decode() if isinstance(public_pem, bytes) else public_pem)
        messagebox.showinfo("Éxito", "Archivo cifrado correctamente.")

    def decrypt():
        """Permite seleccionar y descifrar un archivo .bin con la clave privada del usuario."""

        # Seleccionar un .bin
        ruta = filedialog.askopenfilename(title="Selecciona un archivo .bin para descifrar")
        if not ruta.endswith(".bin"):
            messagebox.showerror("Error", "Selecciona un archivo con extensión .bin.")
            return

        # Usuario cancela
        if not ruta:
            return
        
        # Nombre del archivo sin extensión
        nombre = os.path.splitext(os.path.basename(ruta))[0]
        
        try:
            output_path = decrypt_file(nombre, private_pem, password=password.encode(), username=username)
            messagebox.showinfo("Éxito", "Archivo descifrado correctamente.")
        except Exception as e:
            messagebox.showinfo(f"Error: {e}", "Acceso al archivo denegado")

    tk.Button(frame_vault, text="Cifrar archivo", command=encrypt,
              bg=COLOR_PRINCIPAL, fg="white", font=fuente_boton, width=20).pack(pady=10)
    tk.Button(frame_vault, text="Descifrar archivo", command=decrypt,
              bg=COLOR_PRINCIPAL, fg="white", font=fuente_boton, width=20).pack(pady=10)
    
    def log_out():
        frame_vault.pack_forget()
        frame_vault.destroy()
        show_log_in()
        
    
    tk.Button(frame_vault, text="Cerrar sesión", command=log_out,
              bg="#CAD2C5", fg=COLOR_TEXTO, font=fuente_boton, width=20).pack(pady=20)


# ====================================================
# BUCLE PRINCIPAL
# ====================================================

# Permitir iniciar sesión con la tecla Enter
root.bind('<Return>', lambda event=None: user_log_in())

root.mainloop()
