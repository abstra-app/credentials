from abstra.forms import run, TextInput, PasswordInput, get_user
from abstra.tables import select, insert
from cryptography.fernet import Fernet
from os import environ

# Environment variable for the master encryption key
MASTER_KEY = environ["MASTER_KEY"]

# Get the current user
user = get_user()

# Define the form page
page = [
    TextInput("Identifier", hint="It should be the service name. Ex: Webflow", key="name"),
    TextInput("Public part", hint="It should be the public part of the credential. Ex: design@abstra.app", key="login"),
    PasswordInput("Secret part", hint="It should be the secret part of the secret", key="secret"),
]

# Run the form and get user input
ans = run([page])

# Retrieve the latest Fernet key from the database
latest_key_record = select("fernet_keys", order_by="created_at", order_desc=True, limit=1)
if not latest_key_record:
    raise Exception("No Fernet key found in the database.")

latest_key = latest_key_record[0]
encrypted_fernet_key = latest_key["key_enc"]
key_id = latest_key["id"]

# Decrypt the Fernet key using the master key
master_fernet = Fernet(MASTER_KEY)
decrypted_fernet_key = master_fernet.decrypt(encrypted_fernet_key)

# Initialize Fernet encryption with the decrypted key
fernet = Fernet(decrypted_fernet_key)

# Encrypt the secret part
encrypted_secret = fernet.encrypt(ans["secret"].encode())

# Insert the credential into the 'credentials' table with the key_id reference
inserted_credential = insert("credentials", {
    "name": ans["name"],
    "public_part": ans["login"],
    "private_part_enc": encrypted_secret.decode(),  # Store as a string
    "key_id": key_id
})
