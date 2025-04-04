import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import base64


# All the core functions from the original script
def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key


def save_private_key(private_key, filename, password=None):
    encryption_algorithm = serialization.NoEncryption()
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )
    os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
    with open(filename, 'wb') as f:
        f.write(pem)


def save_public_key(public_key, filename):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
    with open(filename, 'wb') as f:
        f.write(pem)


def load_private_key(filename, password=None):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    password_bytes = None
    if password:
        password_bytes = password.encode()
    return serialization.load_pem_private_key(
        pem_data,
        password=password_bytes
    )


def load_public_key(filename):
    with open(filename, 'rb') as f:
        pem_data = f.read()
    return serialization.load_pem_public_key(pem_data)


def encrypt_then_sign(message, encryption_key, signing_key):
    if len(message) > 140 or not all(ord(c) < 128 for c in message):
        raise ValueError("Message must be at most 140 ASCII characters.")

    ciphertext = encryption_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    signature = signing_key.sign(
        ciphertext,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(ciphertext).decode(), base64.b64encode(signature).decode()


def verify_then_decrypt(ciphertext_b64, signature_b64, decryption_key, verification_key):
    ciphertext = base64.b64decode(ciphertext_b64)
    signature = base64.b64decode(signature_b64)

    try:
        verification_key.verify(
            signature,
            ciphertext,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except InvalidSignature:
        print("Signature verification failed: Invalid signature")
        return None
    except Exception as e:
        print(f"Signature verification failed: {str(e)}")
        return None

    try:
        plaintext = decryption_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()
    except Exception as e:
        print(f"Decryption failed: {str(e)}")
        return None


def save_message(ciphertext_b64, signature_b64, filename):
    with open(filename, 'w') as f:
        f.write(f"{ciphertext_b64}\n{signature_b64}")


def load_message(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
        if len(lines) < 2:
            raise ValueError("Invalid message file format")
        return lines[0].strip(), lines[1].strip()


# Function to display file content
def display_file_content(filename):
    """Display the content of a file with line numbers."""
    try:
        with open(filename, 'r') as f:
            content = f.readlines()

        if not content:
            print(f"File {filename} is empty.")
            return

        print(f"\nContents of {filename}:")
        print("=" * 70)
        for i, line in enumerate(content, 1):
            print(f"Line {i}: {line.rstrip()}")
        print("=" * 70)
    except FileNotFoundError:
        print(f"Error: File {filename} not found.")
    except Exception as e:
        print(f"Error reading file: {str(e)}")


# Simple UI functions
def print_menu():
    print("\n========== RSA-OAEP Authenticated Encryption Tool ==========")
    print("1. Generate Keys")
    print("2. Encrypt and Sign a Message")
    print("3. Verify and Decrypt a Message")
    print("4. View Encrypted File")
    print("5. List Available Keys")
    print("0. Exit")
    print("==========================================================")
    return input("Enter your choice (0-5): ")


def generate_keys_ui():
    print("\n----- Generate Keys -----")
    name = input("Enter name for the key files (e.g., alice, bob): ")
    use_password = input("Password-protect private keys? (y/n): ").lower() == 'y'
    password = None
    if use_password:
        password = input("Enter password: ")

    key_dir = "keys"

    try:
        # Generate both encryption and signing keys
        print(f"Generating encryption key pair for {name}...")
        enc_private, enc_public = generate_keypair()

        print(f"Generating signing key pair for {name}...")
        sign_private, sign_public = generate_keypair()

        # Create the keys directory
        os.makedirs(key_dir, exist_ok=True)

        # Save the keys
        enc_private_file = os.path.join(key_dir, f"{name}_enc_private.pem")
        enc_public_file = os.path.join(key_dir, f"{name}_enc_public.pem")
        sign_private_file = os.path.join(key_dir, f"{name}_sign_private.pem")
        sign_public_file = os.path.join(key_dir, f"{name}_sign_public.pem")

        save_private_key(enc_private, enc_private_file, password)
        save_public_key(enc_public, enc_public_file)
        save_private_key(sign_private, sign_private_file, password)
        save_public_key(sign_public, sign_public_file)

        print(f"\nKeys generated and saved successfully for {name}:")
        print(f"  Encryption: {enc_private_file}, {enc_public_file}")
        print(f"  Signing: {sign_private_file}, {sign_public_file}")

        # Verify keys were created
        print("\nVerifying key files were created:")
        for filename in [enc_private_file, enc_public_file, sign_private_file, sign_public_file]:
            if os.path.exists(filename):
                print(f"  ✓ {filename} created successfully")
            else:
                print(f"  ✗ {filename} not found")
    except Exception as e:
        print(f"Error generating keys: {str(e)}")

    input("\nPress Enter to continue...")


def encrypt_message_ui():
    print("\n----- Encrypt and Sign a Message -----")
    message = input("Enter message to encrypt (max 140 ASCII chars): ")
    sender = input("Enter sender name (whose private key to use for signing): ")
    recipient = input("Enter recipient name (whose public key to use for encryption): ")
    use_password = input("Is the sender's private key password-protected? (y/n): ").lower() == 'y'
    password = None
    if use_password:
        password = input("Enter password: ")
    output_file = input("Enter output file name (default: message.txt): ") or "message.txt"

    try:
        # Check message length
        if len(message) > 140:
            print("Error: Message must be at most 140 characters")
            input("Press Enter to continue...")
            return

        # Load the recipient's public encryption key
        recipient_key_file = os.path.join("keys", f"{recipient}_enc_public.pem")
        if not os.path.exists(recipient_key_file):
            print(f"Error: Recipient key file {recipient_key_file} not found")
            input("Press Enter to continue...")
            return

        recipient_key = load_public_key(recipient_key_file)

        # Load the sender's private signing key
        sender_key_file = os.path.join("keys", f"{sender}_sign_private.pem")
        if not os.path.exists(sender_key_file):
            print(f"Error: Sender key file {sender_key_file} not found")
            input("Press Enter to continue...")
            return

        sender_key = load_private_key(sender_key_file, password)

        # Encrypt and sign the message
        print("Encrypting and signing message...")
        ciphertext, signature = encrypt_then_sign(message, recipient_key, sender_key)

        # Save the encrypted message
        save_message(ciphertext, signature, output_file)
        print(f"Encrypted message saved to {output_file}")

        # Verify file was created and display content
        if os.path.exists(output_file):
            print(f"\nFile {output_file} created successfully.")
            # Display file content
            display_file_content(output_file)

            # Show original vs encrypted
            print("\nOriginal message vs Encrypted:")
            print(f"Original ({len(message)} chars): {message}")
            encrypted_length = len(ciphertext) + len(signature)
            print(f"Encrypted ({encrypted_length} chars): {ciphertext[:30]}... (ciphertext)\n" +
                  f"                        {signature[:30]}... (signature)")
        else:
            print(f"Error: Failed to create file {output_file}")

    except Exception as e:
        print(f"Error encrypting message: {str(e)}")

    input("\nPress Enter to continue...")


def decrypt_message_ui():
    print("\n----- Verify and Decrypt a Message -----")
    input_file = input("Enter input file name (default: message.txt): ") or "message.txt"

    # Check if file exists
    if not os.path.exists(input_file):
        print(f"Error: File {input_file} not found")
        input("Press Enter to continue...")
        return

    # Display encrypted file content first
    display_file_content(input_file)

    sender = input("Enter sender name (whose public key to use for verification): ")
    recipient = input("Enter recipient name (whose private key to use for decryption): ")
    use_password = input("Is the recipient's private key password-protected? (y/n): ").lower() == 'y'
    password = None
    if use_password:
        password = input("Enter password: ")

    try:
        # Load the encrypted message
        ciphertext, signature = load_message(input_file)

        # Load the sender's public verification key
        sender_key_file = os.path.join("keys", f"{sender}_sign_public.pem")
        if not os.path.exists(sender_key_file):
            print(f"Error: Sender key file {sender_key_file} not found")
            input("Press Enter to continue...")
            return

        sender_key = load_public_key(sender_key_file)

        # Load the recipient's private decryption key
        recipient_key_file = os.path.join("keys", f"{recipient}_enc_private.pem")
        if not os.path.exists(recipient_key_file):
            print(f"Error: Recipient key file {recipient_key_file} not found")
            input("Press Enter to continue...")
            return

        recipient_key = load_private_key(recipient_key_file, password)

        # Verify and decrypt the message
        print("Verifying signature and decrypting message...")
        plaintext = verify_then_decrypt(ciphertext, signature, recipient_key, sender_key)

        if plaintext:
            print("\nDecrypted message:")
            print("=" * 50)
            print(plaintext)
            print("=" * 50)

            # Show comparison between encrypted and decrypted
            print("\nComparison:")
            print(f"Encrypted (first line): {ciphertext[:50]}...")
            print(f"Decrypted ({len(plaintext)} chars): {plaintext}")
        else:
            print("Decryption failed.")

    except Exception as e:
        print(f"Error decrypting message: {str(e)}")

    input("\nPress Enter to continue...")


def view_encrypted_file_ui():
    print("\n----- View Encrypted File -----")
    filename = input("Enter file name to view (default: message.txt): ") or "message.txt"

    if not os.path.exists(filename):
        print(f"Error: File {filename} not found")
    else:
        display_file_content(filename)

        # Show file details
        file_stats = os.stat(filename)
        print("\nFile details:")
        print(f"Size: {file_stats.st_size} bytes")
        print(f"Created: {os.path.getctime(filename)}")
        print(f"Last modified: {os.path.getmtime(filename)}")

    input("\nPress Enter to continue...")


def list_keys_ui():
    print("\n----- Available Keys -----")
    key_dir = "keys"

    if not os.path.exists(key_dir):
        print(f"Keys directory '{key_dir}' does not exist.")
        input("Press Enter to continue...")
        return

    key_files = os.listdir(key_dir)

    if not key_files:
        print("No keys found.")
        input("Press Enter to continue...")
        return

    # Group keys by user
    users = {}
    for file in key_files:
        if file.endswith('.pem'):
            # Extract username from filename (e.g., alice_enc_private.pem -> alice)
            parts = file.split('_')
            if len(parts) >= 3:
                username = parts[0]
                if username not in users:
                    users[username] = []
                users[username].append(file)

    # Display keys by user
    if not users:
        print("No valid key files found.")
    else:
        print(f"Found keys for {len(users)} users:")
        for user, files in users.items():
            print(f"\n- {user.capitalize()}:")
            for file in sorted(files):
                file_path = os.path.join(key_dir, file)
                file_size = os.path.getsize(file_path)
                print(f"  • {file} ({file_size} bytes)")

    input("\nPress Enter to continue...")


def main():
    # Check if cryptography is installed
    try:
        import cryptography
    except ImportError:
        print("Error: The 'cryptography' library is required.")
        print("Please install it with: pip install cryptography")
        input("Press Enter to exit...")
        return

    # Create keys directory if it doesn't exist
    os.makedirs("keys", exist_ok=True)

    print("Welcome to the RSA-OAEP Authenticated Encryption Tool!")
    print("This tool allows you to securely encrypt and sign messages.")

    while True:
        choice = print_menu()

        if choice == '1':
            generate_keys_ui()
        elif choice == '2':
            encrypt_message_ui()
        elif choice == '3':
            decrypt_message_ui()
        elif choice == '4':
            view_encrypted_file_ui()
        elif choice == '5':
            list_keys_ui()
        elif choice == '0':
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()