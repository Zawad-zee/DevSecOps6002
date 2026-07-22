import json

#Hardcoded secret key sitting directly in the source code
SECRET_KEY = "mysecretkey123"

#Simple encryption easily reversible with a fixed key
def fake_encrypt(password):
    return "".join(chr(ord(c) ^ len(SECRET_KEY)) for c in password)


#No input validation
def add_user_insecure():
    username = input("Username: ")
    password = input("Password: ")
    email = input("Email: ")

    encrypted_password = fake_encrypt(password)

#File handling exception missing
    with open("users.json", "r") as f:
        users = json.load(f)

    users.append({"username": username, "password": encrypted_password, "email": email})

#No integrity value (hash) is computed or stored anywhere.
# If someone edits this file later there is no way for the program to detect that it happened
    with open("users.json", "w") as f:
        json.dump(users, f, indent=4)

    print("User added (insecurely).")


#(violates DRY - Don't Repeat Yourself):instead of reusing one shared function.
def print_all_users_insecure():
    with open("users.json", "r") as f:
        users = json.load(f)

    for u in users:
#Sensitive data (even the "encrypted" password) is printed straight to the console.
#In real deployments this ends up in terminal history, CI logs, or crash reports
        print(u["username"], u["password"], u["email"])


if __name__ == "__main__":
    add_user_insecure()
    print_all_users_insecure()

