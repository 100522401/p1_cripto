import os
import json


"""     JSON MANAGER    """
def ensure_dir(path: str):
    """Crea el directorio del archivo si no existe."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)

def read_json(path: str) -> dict:
    """Lee un archivo JSON y devuelve un diccionario. Si no existe o está corrupto, devuelve {}."""
    ensure_dir(path)
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}
        
def write_json(path: str, data: dict):
    """Guarda un diccionario en un archivo JSON, creando directorios si es necesario."""
    ensure_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def delete_file(path: str):
    """Elimina un archivo si existe. Devuelve True si se eliminó."""
    try:
        if os.path.exists(path):
            os.remove(path)
            return True
    except Exception:
        pass
    return False
