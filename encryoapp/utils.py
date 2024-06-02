from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import binascii
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

def rsa_encrypt(message, public_key):
    # Deserialize the public key
    public_key_bytes = public_key.encode('utf-8')
    public_key_obj = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

    # Encrypt the message using RSA
    ciphertext = public_key_obj.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=padding.SHA256()),
            algorithm=padding.OAEP(
                algorithm=padding.SHA256(),
                mgf=padding.MGF1(algorithm=padding.SHA256()),
                label=None
            )
        )
    )

    # Convert the encrypted message to a string for display
    encrypted_message = ciphertext.hex()

    return encrypted_message


def encrypt_text(text, mode, keysize, secret_key, iv=None, output_format='Base64'):
    # Convert the secret key to bytes
    secret_key = secret_key.encode('utf-8')

    # Ensure the key is the correct length for the selected keysize
    if len(secret_key) not in [16, 24, 32]:
        raise ValueError("Invalid key size. Key must be 16, 24, or 32 bytes long.")

    # Convert the text to bytes
    text = text.encode('utf-8')

    # Generate a random IV if not provided
    if iv is None:
        iv = get_random_bytes(16)

    # Choose the AES mode
    if mode == 'ECB':
        cipher = AES.new(secret_key, AES.MODE_ECB)
    elif mode == 'CBC':
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Invalid AES mode. Use 'ECB' or 'CBC'.")

    # Pad the text to a multiple of the block size
    padded_text = pad(text, AES.block_size)

    # Encrypt the padded text
    encrypted_text = cipher.encrypt(padded_text)

    # Encode the result based on the selected output format
    if output_format == 'Base64':
        encrypted_text = base64.b64encode(encrypted_text).decode('utf-8')
    elif output_format == 'Hex':
        encrypted_text = binascii.hexlify(encrypted_text).decode('utf-8')
    else:
        raise ValueError("Invalid output format. Use 'Base64' or 'Hex'.")

    return encrypted_text


# myapp/utils.py


def decrypt_text(encrypted_text, mode, keysize, secret_key, iv=None, input_format='Base64'):
    # Convert the secret key to bytes
    secret_key = secret_key.encode('utf-8')

    # Ensure the key is the correct length for the selected keysize
    if len(secret_key) not in [16, 24, 32]:
        raise ValueError("Invalid key size. Key must be 16, 24, or 32 bytes long.")

    # Decode the input based on the selected input format
    if input_format == 'Base64':
        encrypted_text = base64.b64decode(encrypted_text)
    elif input_format == 'Hex':
        encrypted_text = binascii.unhexlify(encrypted_text)
    else:
        raise ValueError("Invalid input format. Use 'Base64' or 'Hex'.")

    # Choose the AES mode
    if mode == 'ECB':
        cipher = AES.new(secret_key, AES.MODE_ECB)
    elif mode == 'CBC':
        if iv is None:
            raise ValueError("Initialization Vector (IV) is required for CBC mode.")
        cipher = AES.new(secret_key, AES.MODE_CBC, iv)
    else:
        raise ValueError("Invalid AES mode. Use 'ECB' or 'CBC'.")

    # Decrypt the text
    decrypted_text = unpad(cipher.decrypt(encrypted_text), AES.block_size)

    # Convert the result to a string
    decrypted_text = decrypted_text.decode('utf-8')

    return decrypted_text
