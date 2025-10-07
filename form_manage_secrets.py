from abstra.forms import run, TextInput, PasswordInput, DropdownInput, MarkdownOutput, get_user
from abstra.tables import select, insert, update, delete
from cryptography.fernet import Fernet
from os import environ

# Environment variable for the master encryption key
MASTER_KEY = environ["MASTER_KEY"]

# Get the current user
user = get_user()

print(f"User {user.email} is managing secrets")

# 1. Fetch existing credentials
credentials = select("credentials", order_by="created_at", order_desc=True)
print(f"Found {len(credentials)} existing credentials")

# Build dropdown options
options = [{"label": "➕ Novo segredo", "value": "new"}]
for cred in credentials:
    label = f"🔑 {cred['name']} ({cred['public_part']})"
    options.append({"label": label, "value": cred["id"]})

# 2. Page to select a secret
def page_select_secret(state):
    return [
        MarkdownOutput("## Gerenciar Segredos\n\nSelecione um segredo existente para editar/deletar ou crie um novo."),
        DropdownInput(
            "Selecione um segredo", 
            key="selected_id", 
            options=options
        ),
    ]

# 3. Page to edit/insert secret
def page_edit_secret(state):
    selected_id = state.get("selected_id")
    cred = next((c for c in credentials if c["id"] == selected_id), None)
    
    is_editing = cred is not None
    
    widgets = [
        MarkdownOutput(f"### {'Editar Segredo' if is_editing else 'Novo Segredo'}"),
        TextInput(
            "Identificador", 
            key="name", 
            value=cred["name"] if cred else "",
            hint="Nome do serviço. Ex: Webflow, Gmail, Stripe"
        ),
        TextInput(
            "Parte pública", 
            key="login", 
            value=cred["public_part"] if cred else "",
            hint="Login, email ou identificador público. Ex: design@abstra.app"
        ),
        PasswordInput(
            "Segredo", 
            key="secret",
            hint="Senha, token ou chave secreta" + (" - deixe em branco para manter o atual" if is_editing else ""),
            required=not is_editing
        ),
    ]
    
    return widgets

# 4. Page to confirm action
def page_confirm_action(state):
    selected_id = state.get("selected_id")
    is_new = selected_id == "new"
    
    if is_new:
        return [
            MarkdownOutput("### Confirmar ação"),
            DropdownInput(
                "O que deseja fazer?",
                key="action",
                options=[
                    {"label": "💾 Salvar novo segredo", "value": "save"}
                ]
            )
        ]
    else:
        return [
            MarkdownOutput("### Confirmar ação"),
            DropdownInput(
                "O que deseja fazer?",
                key="action",
                options=[
                    {"label": "💾 Salvar alterações", "value": "save"},
                    {"label": "🗑️ Deletar segredo", "value": "delete"}
                ]
            )
        ]

# 5. Main logic
state = run([page_select_secret, page_edit_secret, page_confirm_action])

selected_id = state.get("selected_id")
name = state.get("name")
login = state.get("login")
secret = state.get("secret")
action = state.get("action")

print(f"Action: {action}, Selected ID: {selected_id}")

# Fetch latest Fernet key
latest_key_record = select("fernet_keys", order_by="created_at", order_desc=True, limit=1)
if not latest_key_record:
    run([lambda _: [MarkdownOutput("❌ **Erro:** Nenhuma chave Fernet encontrada no banco de dados.")]])
    raise Exception("No Fernet key found in the database.")

latest_key = latest_key_record[0]
encrypted_fernet_key = latest_key["key_enc"]
key_id = latest_key["id"]

# Decrypt the Fernet key using the master key
master_fernet = Fernet(MASTER_KEY)
decrypted_fernet_key = master_fernet.decrypt(encrypted_fernet_key)
fernet = Fernet(decrypted_fernet_key)

# Handle actions
if action == "delete" and selected_id != "new":
    # Delete the credential
    delete("credentials", where={"id": selected_id})
    print(f"Credential {selected_id} deleted successfully")
    run([lambda _: [MarkdownOutput("✅ **Segredo deletado com sucesso!**")]])

elif action == "save":
    if selected_id == "new":
        # Insert new credential
        encrypted_secret = fernet.encrypt(secret.encode()).decode()
        inserted = insert("credentials", {
            "name": name,
            "public_part": login,
            "private_part_enc": encrypted_secret,
            "key_id": key_id
        })
        print(f"New credential created: {inserted['id']}")
        run([lambda _: [MarkdownOutput("✅ **Segredo criado com sucesso!**")]])
    else:
        # Update existing credential
        update_values = {
            "name": name,
            "public_part": login,
            "key_id": key_id
        }
        
        # Only update secret if provided
        if secret:
            encrypted_secret = fernet.encrypt(secret.encode()).decode()
            update_values["private_part_enc"] = encrypted_secret
        
        update("credentials", where={"id": selected_id}, values=update_values)
        print(f"Credential {selected_id} updated successfully")
        run([lambda _: [MarkdownOutput("✅ **Segredo atualizado com sucesso!**")]])
