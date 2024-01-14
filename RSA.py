from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.backends import default_backend


def generate_rsa_key_pair(key_size):
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=key_size,
                                           backend=default_backend())

    public_key = private_key.public_key()

    return private_key, public_key


def serialize_private_key(private_key, passphrase):
    return private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                     format=serialization.PrivateFormat.PKCS8,
                                     encryption_algorithm=serialization.BestAvailableEncryption(
                                         passphrase.encode("utf-8")))


def serialize_public_key(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo)


def load_private_key(file_path, passphrase):
    with open(file_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=passphrase.encode("utf-8"),
                                                  backend=default_backend())


def load_public_key(file_path):
    with open(file_path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def rsa_encrypt(plaintext, public_key):
    plaintext = plaintext.encode("utf-8")

    ciphertext = public_key.encrypt(
        plaintext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))

    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None))

    return plaintext.decode("utf-8")


private_key, public_key = generate_rsa_key_pair(2048)

with open("private_key.pem", "wb") as f:
    f.write(serialize_private_key(private_key, "your_passphrase"))

with open("public_key.pem", "wb") as f:
    f.write(serialize_public_key(public_key))

private_key = load_private_key("private_key.pem", "your_passphrase")
public_key = load_public_key("public_key.pem")

message = "Еман ты псих._."
encrypted_message = rsa_encrypt(message, public_key)
print("Encrypted message:", encrypted_message)

decrypted_message = rsa_decrypt(encrypted_message, private_key)
print("Decrypted message:", decrypted_message)