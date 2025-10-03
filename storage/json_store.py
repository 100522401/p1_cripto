import json
import os

class JsonStore():

    _data_list = []
    _file_name = ""

    def __init__(self):
        self.load_list_from_file()

    def save_list_to_file(self):
        """Guarda la lista en la store"""
        try:
            with open(self._file_name, "w", encoding="utf-8", newline="") as file:
                json.dump(self._data_list, file, indent=2)
        except FileNotFoundError as ex:
            raise Exception("path erróneo")

    def load_list_from_file(self):
        """Carga la lista de elementos de la store"""

        try:
            with open(self._file_name, "r", encoding="utf-8", newline="") as file:
                self._data_list = json.load(file)
        except FileNotFoundError:
            self._data_list = []
        except FileNotFoundError as ex:
            raise FileNotFoundError("Path erróneo") from ex

    def add_item(self, item):
        """añade un nuevo elemento a la store"""
        self.load_list_from_file()
        self._data_list.append(item.to_json())
        self.save_list_to_file()
