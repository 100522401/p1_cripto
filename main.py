import tkinter as tk
from tkinter import messagebox
from core.user_manager import sign_up, log_in

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

    if  log_in(username, password):
        messagebox.showinfo("Inicio de sesión", f"Bienvenido, {username}!")
    else:
        messagebox.showerror("Error", "Usuario o contraseña incorrectos.")




def show_sign_up():
    frame_login.pack_forget()
    frame_registro.pack(expand=True)


def show_log_in():
    frame_registro.pack_forget()
    frame_login.pack(expand=True)


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
# BUCLE PRINCIPAL
# ====================================================

root.mainloop()
