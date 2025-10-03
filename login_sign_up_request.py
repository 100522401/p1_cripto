import json

class LoginSignUpRequest:
    def __init__(self, username, password):
        self._username = username
        self._password = password
    #validar username(regex)
    #validar password(requisitos minimos)

    def to_json(self):
        return {
            "username": self._username,
            "password": self._password
        }