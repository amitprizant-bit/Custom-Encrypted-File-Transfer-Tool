import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

server_ip = "127.0.0.1"
server_port = 12345


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket closed prematurely")
        data += packet
    return data


def derive_aes_key(shared_key: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file-transfer",
    ).derive(shared_key)


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_ip, server_port))
server_socket.listen(1)
print(f"Server listening on {server_ip}:{server_port}")

client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address}")

try:
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    param_bytes = parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.ParameterFormat.PKCS3
    )
    client_socket.sendall(param_bytes)

    client_socket.recv(1024)

    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()
    spublic_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    client_socket.sendall(spublic_key_bytes)

    client_key_bytes = client_socket.recv(4096)
    client_key = serialization.load_der_public_key(client_key_bytes)

    shared_key = server_private_key.exchange(client_key)

    aes_key = derive_aes_key(shared_key)
    aesgcm = AESGCM(aes_key)

    iv_len = int.from_bytes(recv_exact(client_socket, 2), "big")
    iv = recv_exact(client_socket, iv_len)
    data_len = int.from_bytes(recv_exact(client_socket, 4), "big")
    encrypted_data = recv_exact(client_socket, data_len)

    decrypted_data = aesgcm.decrypt(iv, encrypted_data, None)
    with open("received_file.txt", "wb") as f:
        f.write(decrypted_data)

finally:
    client_socket.close()
    server_socket.close()
