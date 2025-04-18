import os
from cryptography.fernet import Fernet
from abstra.tables import select, insert, update_by_id, select_by_id


def update_keys():
    # Step 1: Generate a new Fernet key
    new_fernet_key = Fernet.generate_key()

    # Step 2: Encrypt the new key with the MASTER_KEY
    master_key = os.environ.get("MASTER_KEY")
    if not master_key:
        raise ValueError("MASTER_KEY environment variable is not set")

    master_fernet = Fernet(master_key)
    encrypted_new_key = master_fernet.encrypt(new_fernet_key)

    # Step 3: Insert the encrypted key into the fernet_keys table
    new_key_id = insert("fernet_keys", {
        "key_enc": encrypted_new_key.decode()
    })["id"]

    # Step 4: Retrieve all credentials
    credentials = select("credentials")

    # Step 5: Update each credential with the new key
    for credential in credentials:
        # Decrypt the old encrypted credential
        old_key_id = credential["key_id"]
        old_key_record = select_by_id("fernet_keys", old_key_id)
        old_key_enc = old_key_record["key_enc"].encode()
        old_fernet = Fernet(master_fernet.decrypt(old_key_enc))
        
        decrypted_private_part = old_fernet.decrypt(credential["private_part_enc"].encode())

        # Encrypt with the new key
        new_fernet = Fernet(new_fernet_key)
        new_encrypted_private_part = new_fernet.encrypt(decrypted_private_part).decode()

        # Update the credential with the new encrypted value and key_id
        update_by_id("credentials", credential["id"], {
            "private_part_enc": new_encrypted_private_part,
            "key_id": new_key_id
        })
