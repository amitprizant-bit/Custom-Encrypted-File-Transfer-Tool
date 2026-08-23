import socket
import os
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

server_ip = "127.0.0.1"
server_port = 12345


def derive_aes_key(shared_key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file-transfer",
    ).derive(shared_key)


client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_ip, server_port))

try:
    param_bytes = client_socket.recv(4096)
    parameters = serialization.load_pem_parameters(param_bytes)
    client_socket.sendall(b"ACK")

    server_key_bytes = client_socket.recv(4096)
    server_key = serialization.load_der_public_key(server_key_bytes)

    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()
    cpublic_key_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client_socket.sendall(cpublic_key_bytes)

    shared_key = client_private_key.exchange(server_key)

    aes_key = derive_aes_key(shared_key)
    aesgcm = AESGCM(aes_key)

    iv = os.urandom(12)
    file_path = Path(input("Enter file: ").strip('" '))
    file_data = file_path.read_bytes()

    encrypted_data = aesgcm.encrypt(iv, file_data, None)

    client_socket.sendall(len(iv).to_bytes(2, "big"))
    client_socket.sendall(iv)
    client_socket.sendall(len(encrypted_data).to_bytes(4, "big"))
    client_socket.sendall(encrypted_data)

finally:
    client_socket.close()
