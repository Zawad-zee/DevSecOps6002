import json
import hashlib
import logging
from cryptography.fernet import Fernet

KEY_FILE = "secret.key"
LOG_FILE = "security_audit.log"

#Instead of printing confidential data on the console
#All integrity checks are now written to a persistent log file
# (with a timestamp) In a real system this log file is what a SIEM tool like Splunk 
# would monitor to alert a security team the moment tampering is detected.
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

#Key is no longer hardcoded in the source code. its stored in own file,
# which in a real deployment would be restricted with
# file permissions or moved to a secrets manager.
def load_or_create_key():
    try:
        with open(KEY_FILE, "rb") as f:
            return f.read()
    except FileNotFoundError:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        return key


#Real encryption (AES-based, via Fernet).
KEY = load_or_create_key()
fernet = Fernet(KEY)
def encrypt_password(password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()


def compute_hash(username, password, email):
    record_string = username + password + email
    return hashlib.sha256(record_string.encode()).hexdigest()

#Basic input validation - rejects empty fields, short
# passwords, and clearly malformed emails.
def validate_input(username, password, email):
    if not username or not password or not email:
        return False, "Username, password, and email cannot be empty."
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if "@" not in email or "." not in email:
        return False, "Email address does not look valid."
    return True, ""

# Implementing DRY principle. Handles a missing or corrupt file gracefully instead of crashing.
def load_users(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        logging.warning(f"{filename} not found - starting with empty list.")
        return []
    except json.JSONDecodeError:
        logging.error(f"{filename} is not valid JSON.")
        return []


def save_users(users, filename):
    with open(filename, "w") as f:
        json.dump(users, f, indent=4)

def add_user_secure(username, password, email,
                     input_file="users.json", output_file="secure_users.json"):
    ok, message = validate_input(username, password, email)
    if not ok:
        logging.warning(f"Rejected new user '{username}': {message}")
        print(f"[REJECTED] {message}")
        return

    users = load_users(input_file)
    users.append({"username": username, "password": password, "email": email})
    save_users(users, input_file)

    secure_store(input_file, output_file)
    logging.info(f"User '{username}' added successfully.")
    print(f"[OK] User '{username}' added securely.")


def secure_store(input_file="users.json", output_file="secure_users.json"):
    users = load_users(input_file)
    secure_users = []
    reference_hashes = {}

    for user in users:
        username = user["username"]
        password = user["password"]
        email = user["email"]

#Integrity hash computed and stored per record,
#any later change to the data can be detected.       
        record_hash = compute_hash(username, password, email)
        reference_hashes[username] = record_hash

        secure_users.append({
            "username": username,
            "password": encrypt_password(password),
            "email": email,
            "integrity_hash": record_hash
        })

    save_users(secure_users, output_file)
    with open("reference_hashes.json", "w") as f:
        json.dump(reference_hashes, f, indent=4)
    logging.info(f"secure_store: processed {len(secure_users)} records into {output_file}")


#Never prints raw or encrypted passwords
def print_all_users_secure(secure_file="secure_users.json"):
    users = load_users(secure_file)
    for u in users:
        print(u["username"], "********", u["email"])


def verify_integrity(secure_file="secure_users.json"):
    """Checks secure_users.json against its own embedded hashes."""
    users = load_users(secure_file)
    print(f"\n--- Verifying integrity of '{secure_file}' ---")
    for user in users:
        decrypted = decrypt_password(user["password"])
        recomputed = compute_hash(user["username"], decrypted, user["email"])
        if recomputed == user["integrity_hash"]:
            print(f"  [PASS] {user['username']}")
            logging.info(f"Integrity check PASSED for user '{user['username']}'")
        else:
            print(f"  [FAIL] {user['username']} (tampering detected)")
            logging.warning(f"INTEGRITY VIOLATION detected for user '{user['username']}'")


def check_for_tampering(reference_hash_file="reference_hashes.json",
                         file_to_check="users_tampered.json"):
    """
    Task 4: compares a possibly-tampered file (users_tampered.json)
    against the ORIGINAL reference hashes saved by secure_store().
    Every result - pass or fail - is written to security_audit.log,
    simulating what a log-monitoring tool (e.g. Splunk) would record.
    """
    with open(reference_hash_file, "r") as f:
        reference_hashes = json.load(f)

    users = load_users(file_to_check)

    print(f"\n--- Checking '{file_to_check}' against original hashes ---")
    logging.info(f"Starting tamper check on '{file_to_check}'")
    tampered_found = False

    for user in users:
        username = user["username"]
        password = user["password"]
        email = user["email"]

        current_hash = compute_hash(username, password, email)
        original_hash = reference_hashes.get(username)

        if current_hash == original_hash:
            print(f"  [PASS] {username}: no tampering detected")
            logging.info(f"Tamper check PASSED for user '{username}'")
        else:
            print(f"  [FAIL] {username}: TAMPERING DETECTED")
            logging.warning(f"TAMPERING DETECTED in '{file_to_check}' for user '{username}' "
                             f"- expected hash {original_hash}, got {current_hash}")
            tampered_found = True

    if tampered_found:
        print(f"\nResult: >>> Tampered record(s) found in {file_to_check} <<<")
        logging.warning(f"Tamper check complete: tampering found in {file_to_check}")
    else:
        print("\nResult: No tampering found.")
        logging.info(f"Tamper check complete: no tampering found in {file_to_check}")

    return tampered_found

def console_input():
    username = input("Username: ")
    password = input("Password: ")
    email = input("Email: ")
    add_user_secure(username,password,email)

if __name__ == "__main__":
    print("=" * 60)
    print("PHASE 2 - TASK 2: Secure Data Storage")
    print("=" * 60)
    secure_store("users.json", "secure_users.json")
    print_all_users_secure("secure_users.json")
    verify_integrity("secure_users.json")

    print("\n" + "=" * 60)
    print("PHASE 2 - TASK 4: Data Integrity Verification (Tamper Detection)")
    print("=" * 60)
    check_for_tampering("reference_hashes.json", "users_tampered.json")

    print(f"\n[i] Full audit trail written to {LOG_FILE} - open it to see every")
    print("    PASS/FAIL event with a timestamp, as a log-monitoring tool would.")

# Demo: input validation rejecting a weak password "gina", "123", "gina@example.com"
#   console_input()    
# Demo: valid new user "henry", "HenrySecure2024!", "henry@example.com"
#   console_input()
