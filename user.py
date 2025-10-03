from storage.users_store import UsersStore
from login_sign_up_request import LoginSignUpRequest

class User:
    def __init__(self):
        pass

    def sign_up(self, username, password):
        request = LoginSignUpRequest(username, password)
        users_store = UsersStore()
        users_store.add_item(request)

    def log_in(self, username, password):
        request = LoginSignUpRequest(username, password)
        users_store = UsersStore()
        return users_store.login(request)

def main():
    username = "Hector"
    password = "AAAAAA"
    user = User()
    user.sign_up(username, password)


if __name__ == "__main__":
    main()
