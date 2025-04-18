from abstra.forms import run, DropdownInput, MarkdownOutput, get_user
from abstra.tables import select, insert, select_by_id
from os import getenv
from cryptography.fernet import Fernet

MASTER_KEY = getenv("MASTER_KEY")
if not MASTER_KEY:
    raise ValueError("MASTER_KEY environment variable is not set")

master_fernet = Fernet(MASTER_KEY)

credentials = select("credentials", order_by="name")

ans = run([[
    DropdownInput("Select a credential", [
        {
            "label": credential['name'],
            "value": credential["id"]
        } for credential in credentials
    ], key="credential_id"),
]])

selected_credential = next(
    credential for credential in credentials if credential["id"] == ans["credential_id"]
)

fernet_row = select_by_id("fernet_keys", selected_credential["key_id"])
fernet_key_enc = fernet_row["key_enc"]

fernet_key = master_fernet.decrypt(fernet_key_enc.encode())
fernet = Fernet(fernet_key)
decrypted_private_part = fernet.decrypt(
    selected_credential["private_part_enc"].encode()
).decode()

user = get_user()

insert("credential_views", {
    "email": user.email,
    "credential_id": selected_credential["id"],
})

# Display the decrypted private part
run([[
    MarkdownOutput("\n\n".join([
        str(selected_credential['name']) + ":",
        f"**Public part:** `{selected_credential['public_part']}`",
        f"**Secret part:** `{decrypted_private_part}`",
    ]))
]])