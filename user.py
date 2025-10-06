from storage.users_store import UsersStore
from login_sign_up_request import SignUp

class User:
    def __init__(self):
        pass

    def sign_up(self, username, password):
        request = SignUp(username, password)
        users_store = UsersStore()

        try:
            users_store.add_item(request.to_json())
            print("Usuario registrado con éxito")
        except Exception as e:
            print(f"Error: {e}")

   # def log_in(self, username, password):
    #    request = LoginSignUpRequest(username, password)
     #   users_store = UsersStore()
      #  return users_store.login(request)

def main():
    username = "Manuel"
    password = "Adios"
    user = User()
    user.sign_up(username, password)
    


if __name__ == "__main__":
    main()
