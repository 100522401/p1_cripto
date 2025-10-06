import json
from storage.json_store import JsonStore

class UsersStore(JsonStore):
    
    class __UsersStore(JsonStore):
        _file_name = "jsons/users.json"
        

        def add_item(self, item):
            for user in self._data_list:
                #Interpreto que Nombre == nombre
                if user["username"].lower() == item["username"].lower():
                    raise Exception("Cuenta ya existente")
            super().add_item(item)
            return self._data_list

    __instance = None

    def __new__(cls):
        if not UsersStore.__instance:
            UsersStore.__instance = UsersStore.__UsersStore()
        return UsersStore.__instance