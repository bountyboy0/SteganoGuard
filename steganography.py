import os
from PIL import Image
import stepic
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from colorama import Fore, Style, init

init(autoreset=True)

TITLE = f'''{Fore.CYAN}
.d8888b.  888                                                 .d8888b.                                888 
d88P  Y88b 888                                                d88P  Y88b                               888 
Y88b.      888                                                888    888                               888 
 "Y888b.   888888 .d88b.   .d88b.   8888b.  88888b.   .d88b.  888        888  888  8888b.  888d888 .d88888 
    "Y88b. 888   d8P  Y8b d88P"88b     "88b 888 "88b d88""88b 888  88888 888  888     "88b 888P"  d88" 888 
      "888 888   88888888 888  888 .d888888 888  888 888  888 888    888 888  888 .d888888 888    888  888 
Y88b  d88P Y88b. Y8b.     Y88b 888 888  888 888  888 Y88..88P Y88b  d88P Y88b 888 888  888 888    Y88b 888 
 "Y8888P"   "Y888 "Y8888   "Y88888 "Y888888 888  888  "Y88P"   "Y8888P88  "Y88888 "Y888888 888     "Y88888 
                               888                                                                         
                          Y8b d88P                                                                         
                           "Y88P"                                                                          
                          888                           d8888  d8b                                         
                          888                          d88888  Y8P                                         
                          888                         d88P888                                              
                          88888b.  888  888          d88P 888 8888                                         
                          888 "88b 888  888         d88P  888 "888                                         
                          888  888 888  888        d88P   888  888                                         
                          888 d88P Y88b 888       d8888888888  888                                         
                          88888P"   "Y88888      d88P     888  888                                         
                                        888                    888                                         
                                   Y8b d88P                   d88P                                         
                                    "Y88P"                  888P"
{Style.RESET_ALL}'''

def ensure_extension(filename, ext):
    filename = filename.strip()
    if not filename.lower().endswith(ext.lower()):
        return filename + ext
    return filename

def generate_rsa_keys():
    print(f"\n{Fore.BLUE}🔑 Generating 4096-bit RSA key pair...{Style.RESET_ALL}")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()
    
    priv_filename = input(f"{Fore.YELLOW}📝 Enter filename to save private key (default: private_key.pem): {Style.RESET_ALL}").strip()
    if not priv_filename:
        priv_filename = "private_key.pem"
    else:
        priv_filename = ensure_extension(priv_filename, ".pem")
    
    pub_filename = input(f"{Fore.YELLOW}📝 Enter filename to save public key (default: public_key.pem): {Style.RESET_ALL}").strip()
    if not pub_filename:
        pub_filename = "public_key.pem"
    else:
        pub_filename = ensure_extension(pub_filename, ".pem")
    
    with open(priv_filename, "wb") as priv_file:
        priv_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    with open(pub_filename, "wb") as pub_file:
        pub_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )
    
    print(f"\n{Fore.GREEN}✅ Success!{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Private key saved as: {os.path.abspath(priv_filename)}")
    print(f"Public key saved as: {os.path.abspath(pub_filename)}{Style.RESET_ALL}")

def encode_message(image_path, output_path, message, rsa_public_key_path):
    print(f"\n{Fore.BLUE}📨 Starting encoding process...{Style.RESET_ALL}")
    rsa_public_key_path = ensure_extension(rsa_public_key_path, ".pem")
    try:
        with open(rsa_public_key_path, "rb") as key_file:
            public_key = serialization.load_pem_public_key(key_file.read())
    except Exception as e:
        print(f"{Fore.RED}Failed to load RSA public key. Error: {e}{Style.RESET_ALL}")
        return

    sym_key = Fernet.generate_key()
    fernet_cipher = Fernet(sym_key)
    encrypted_message = fernet_cipher.encrypt(message.encode())
    encrypted_sym_key = public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    key_length = len(encrypted_sym_key)
    packed_data = key_length.to_bytes(4, byteorder='big') + encrypted_sym_key + encrypted_message

    try:
        img = Image.open(image_path.strip().strip('\"'))
    except Exception as e:
        print(f"{Fore.RED}Failed to open image. Error: {e}{Style.RESET_ALL}")
        return

    encoded_img = stepic.encode(img, packed_data)
    output_path = output_path.strip()
    if not output_path:
        output_path = "output.png"
    else:
        output_path = ensure_extension(output_path, ".png")
    
    encoded_img.save(output_path)
    abs_path = os.path.abspath(output_path)
    print(f"\n{Fore.GREEN}✅ Message encoded and saved as: {abs_path}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Send this image securely to the receiver; they will use their private key to decrypt the hidden message.{Style.RESET_ALL}")

def decode_message(image_path, rsa_private_key_path):
    print(f"\n{Fore.BLUE}🔍 Starting decoding process...{Style.RESET_ALL}")
    try:
        img = Image.open(image_path.strip().strip('\"'))
    except Exception as e:
        print(f"{Fore.RED}Failed to open image. Error: {e}{Style.RESET_ALL}")
        return
    if img.format != 'PNG':
        print(f"{Fore.RED}Error: Only PNG images are supported for decoding. Please provide a PNG image.{Style.RESET_ALL}")
        return

    packed_data = stepic.decode(img)
    if isinstance(packed_data, str):
        packed_data = packed_data.encode('latin1')
    
    key_length = int.from_bytes(packed_data[:4], byteorder='big')
    encrypted_sym_key = packed_data[4:4+key_length]
    encrypted_message = packed_data[4+key_length:]
    rsa_private_key_path = ensure_extension(rsa_private_key_path, ".pem")
    
    try:
        with open(rsa_private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    except Exception as e:
        print(f"{Fore.RED}Failed to load RSA private key. Error: {e}{Style.RESET_ALL}")
        return
    
    try:
        sym_key = private_key.decrypt(
            encrypted_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        print(f"{Fore.RED}Failed to decrypt the symmetric key. Check your private key.{Style.RESET_ALL}")
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
        return

    fernet_cipher = Fernet(sym_key)
    try:
        decrypted_message = fernet_cipher.decrypt(encrypted_message).decode()
        print(f"\n{Fore.GREEN}✅ Decoded message: {decrypted_message}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Failed to decrypt the message. It may be corrupted or the wrong key was provided.{Style.RESET_ALL}")
        print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    print(TITLE)
    print(f"{Fore.YELLOW}🌟 Choose an option:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}1. 🔑 Generate RSA Key Pair")
    print(f"2. 📨 Encode Message")
    print(f"3. 🔍 Decode Message{Style.RESET_ALL}")
    
    option = input(f"\n{Fore.YELLOW}🛠️  Enter 1, 2, or 3: {Style.RESET_ALL}").strip()
    
    if option == '1':
        generate_rsa_keys()
    elif option == '2':
        image_path = input(f"{Fore.YELLOW}📷 Enter your image path (supports PNG, JPG, etc.): {Style.RESET_ALL}")
        message = input(f"{Fore.YELLOW}📝 Enter the message to hide: {Style.RESET_ALL}")
        output_path = input(f"{Fore.YELLOW}💾 Enter output image filename (default: output.png): {Style.RESET_ALL}")
        rsa_public_key_path = input(f"{Fore.YELLOW}🔓 Enter the RSA public key file path (PEM format): {Style.RESET_ALL}")
        encode_message(image_path, output_path, message, rsa_public_key_path)
    elif option == '3':
        image_path = input(f"{Fore.YELLOW}📷 Enter the path of the encoded image (must be PNG): {Style.RESET_ALL}")
        rsa_private_key_path = input(f"{Fore.YELLOW}🔒 Enter your RSA private key file path (PEM format): {Style.RESET_ALL}")
        decode_message(image_path, rsa_private_key_path)
    else:
        print(f"{Fore.RED}Invalid option. Please enter 1, 2, or 3.{Style.RESET_ALL}")
