import base64, getpass, json, secrets, string,  os, sys, time
os.environ["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] ="yes"
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dataclasses import dataclass

# configuring SQLite3 might be a better option
CONFIG = {
    'salt_file': 'salt.bin',
    'data_file': 'data.encrypted'
}

# Constants
MIN_LENGTH = 8
MIN_MASTER_LENGTH = 12
DEFAULT_PASSWORD_LENGTH = 23
CHARS = string.ascii_letters + string.digits + string.punctuation
MAX_RETRIES = 3
DELAY = 2
VERSION = "3.4.6"

@dataclass
class Account:
    service: str
    username: str
    password: str

class PasswordManager:
    def __init__(self):
        self.accounts = []
        self.salt = None
        self.fernet = None
        self.load_or_initialize()

    def load_or_initialize(self):
        if os.path.exists(CONFIG['salt_file']) and os.path.exists(CONFIG['data_file']):
            self.load_salt()
            self.authenticate()
            self.load_data()
        else:
            master_password = getpass.getpass("Create master password: ")
            confirmed_password = getpass.getpass("Confirm: ")
            self.initialize(master_password, confirmed_password)

    def load_salt(self):
        with open('salt.bin', 'rb') as f:
            self.salt = f.read()

    def initialize(self, master_password, confirmed_password):
        for _ in range(0, MAX_RETRIES):
            if master_password == confirmed_password and strong_password(master_password):
                self.salt = os.urandom(16)
                with open(CONFIG['salt_file'], 'wb') as f:
                    f.write(self.salt)
                self.derive_key(master_password)
                self.save_data()
                return
            if master_password != confirmed_password:
                print("[-] Passwords do not match. Please try again.")
            if not strong_password(master_password):
                print("[-] Strong password required!!")
                print(f"[-] {MASTER_PASSWORD_TEXT}")
            time.sleep(DELAY)
        print("[-] Maximum retries exceeded.")
        print_message("[-] Exiting PVolt...")
        sys.exit()

    def authenticate(self):
        for _ in range(0, MAX_RETRIES):
            # add a timer for brute force protection
            master_password = getpass.getpass("Enter master password: ")
            self.derive_key(master_password)
            with open(CONFIG['data_file'], 'rb') as f:
                data = f.read()
                self.fernet.decrypt(data)
                return
            sys.exit()
               
    def derive_key(self, master_password):
        # use an algorithm of your choice
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=600000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        self.fernet = Fernet(key)

    def save_data(self):
        data = [{'service': acc.service, 
                 'username': acc.username, 
                 'password': acc.password} 
                for acc in self.accounts]
        json_data = json.dumps(data).encode('utf-8')
        encrypted_data = self.fernet.encrypt(json_data)
        with open(CONFIG['data_file'], 'wb') as f:
            f.write(encrypted_data)

    def load_data(self):
        with open(CONFIG['data_file'], 'rb') as f:
            encrypted_data = f.read()
        json_data = self.fernet.decrypt(encrypted_data).decode('utf-8')
        data = json.loads(json_data)
        self.accounts = [Account(**item) for item in data]

    def add_account(self, service, username, password):
        self.accounts.append(Account(service, username, password))
        self.save_data()

    def get_password(self, service):
        return next((acc.password for acc in self.accounts if acc.service.lower() == service.lower()), None)
        
    def get_service(self, service):
        return next((acc.service for acc in self.accounts if acc.service.lower() == service.lower()), None)

    def list_services(self):
        return [acc.service for acc in self.accounts]

    def delete_account(self, service):
        self.accounts = [acc for acc in self.accounts 
                        if acc.service.lower() != service.lower()]
        self.save_data()

    @staticmethod
    def generate_password(length=DEFAULT_PASSWORD_LENGTH):
        while True:
            password = ''.join(secrets.choice(CHARS) for _ in range(length))
            if strong_password(password):
                return password
            
# this is for that one guy with password that goes like "password123"
def strong_password(password):
    return ((len(password) >= MIN_LENGTH) and
        any(c.islower() for c in password) and
        any(c.isupper() for c in password) and
        any(c.isdigit() for c in password) and
        any(c in string.punctuation for c in password))

def show_menu():
    print("\nMenu:")
    for i, opt in enumerate([
        "Add Account", "Get Password", "List Services",
        "Delete Account", "Generate Password", 
        "Update Master Password", "Help", "Exit"
        ], 1):
        print(f"{i}. {opt}")

def print_message(message: string):
    for characters in message:
        print(characters, end='', flush=True)
        time.sleep(0.1)

# take these to database if you have sqlite3 setup
MASTER_PASSWORD_TEXT = f"""Master Password Requirements:
   - Minimum {MIN_MASTER_LENGTH} characters
   - Must include uppercase, lowercase, numbers and special chars
   - Must be unique and not reused elsewhere
   - Change periodically for security"""

HELP_TEXT = f"""
Password Manager Help:

1. {MASTER_PASSWORD_TEXT}

2. Password Requirements:
   - Minimum {MIN_LENGTH} characters
   - Must include uppercase, lowercase, numbers and special chars

3. Security Tips:
   - Use different passwords for each service
   - Enable passkeys functionality in production
   - Keep this software updated
"""

VOLT_TEXT = f"""
\n
{'-'*70}
\t                    Altron Ink
{'-'*70}
\t      d888888,  88    88  ,d8888b,  88    88888888                   
\t      88    88  88    88  88    88  88       88                      
\t      888888P'  88    88  88    88  88       88                      
\t      88         88  88   88    88  88       88                      
\t      88          8bd8    88    88  88       88                      
\t      dP           88     'd8888P'  888888   88     {VERSION}             
{'-'*70}
 There are no secrets well kept than those that everybody guesses.
{'-'*70}

"""


def main():
    print(VOLT_TEXT)
    pm = PasswordManager()
    while True:
        show_menu()
        try:
            choice = int(input("Choice: "))

            if choice == 1:
                service = input("Enter service name: ")
                if service == pm.get_service(service):
                    print("[-] Service already exist.")
                    break
                username = input("Enter username: ")
                option = int(input("Generate(1) or Enter(2) password: "))
                if option == 1:
                    for _ in range(0, MAX_RETRIES):
                        length = int(input("Enter password length: "))
                        if (length < MIN_LENGTH):
                            print("[-] Invalid length value")
                            break
                        if (length >= MIN_LENGTH):
                            password = pm.generate_password(length)
                            print(f"Generated Password: {password}")
                            option_1b = int(input("Use this password(1) or Generate new password(2): "))
                            if option_1b == 1:
                                pm.add_account(service, username, password)
                                print("[+] Account added successfully!")
                                break
                            if option_1b == 2:
                                continue
                if option == 2:
                    password = getpass.getpass("Enter password: ")
                    if strong_password(password):
                        pm.add_account(service, username, password)
                        print("[+] Account added successfully!")
                    elif not strong_password(password):
                        print("[-] Strong password required!!")
                        print(f"[-] {MASTER_PASSWORD_TEXT}")

                if option not in (1,2):
                    print("[-] Invalid option. Please enter 1 or 2.")

            elif choice == 2:
                service = input("Enter service name: ")
                password = pm.get_password(service)
                if pm.get_service(service):
                    print(f"Password for {service}: {password}")
                else:
                    print("[-] Service not found!")

            elif choice == 3:
                services = pm.list_services()
                if services:
                    print("Stored Services:")
                    for service in services:
                        print(f"- {service}")
                else:
                    print("[-] No services stored!")

            elif choice == 4:
                if (service := pm.get_service(input("Enter service name to delete: "))):
                    pm.delete_account(service)
                    pm.save_data()
                    print("[+] Account deleted successfully!")
                print("[-] Service not found!")

            elif choice == 5:
                length = int(input("Enter password length: "))
                if length < MIN_LENGTH:
                    print("Seriously!! Password length MUST be at least 8.")
                elif length >= MIN_LENGTH:
                    password = pm.generate_password(length)
                    print(f"Generated Password: {password}")

            elif choice == 6:
                pm.authenticate()
                master_password = getpass.getpass("New master password: ")
                confirmed_password = getpass.getpass("Confirm: ")
                pm.initialize(master_password, confirmed_password)
                print("[+] Master password changed successfully!!")

            elif choice == 7:
                print(HELP_TEXT)

            elif choice == 8:
                print_message("[-] Exiting PVolt...")
                break

            else:
                print("[-] Invalid choice. Please enter a number between 1-7.")

        except KeyboardInterrupt:
            print_message("\n[-] Exiting PVolt...")
            sys.exit()
        except ValueError as e:
            print("[-] Invalid input. Please enter a valid number.")
            print(f"[-] Error: {e}")
