import os
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import scrolledtext, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 12345
STORAGE_DIR = os.path.join(BASE_DIR, "server_files")
PARAMS_FILE = os.path.join(BASE_DIR, "dh_params.pem")

CHUNK_SIZE = 64 * 1024
NONCE_LEN = 12
MAX_FRAME = 16 * 1024 * 1024


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            raise ConnectionError("Socket closed prematurely")
        data += packet
    return data


def send_frame(sock, data):
    sock.sendall(len(data).to_bytes(4, "big") + data)


def recv_frame(sock):
    length = int.from_bytes(recv_exact(sock, 4), "big")
    if length > MAX_FRAME:
        raise ValueError(f"Frame too large: {length} bytes")
    return recv_exact(sock, length)


def derive_aes_key(shared_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"file-transfer",
    ).derive(shared_key)


def load_or_create_parameters(path, key_size=2048):
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_parameters(f.read())

    parameters = dh.generate_parameters(generator=2, key_size=key_size)
    with open(path, "wb") as f:
        f.write(parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3,
        ))
    return parameters


def server_handshake(sock, parameters):
    send_frame(sock, parameters.parameter_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.ParameterFormat.PKCS3,
    ))

    private_key = parameters.generate_private_key()
    send_frame(sock, private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    peer_public_key = serialization.load_der_public_key(recv_frame(sock))
    return AESGCM(derive_aes_key(private_key.exchange(peer_public_key)))


def safe_filename(name):
    name = os.path.basename(str(name).replace("\\", "/"))
    if not name or name in (".", ".."):
        raise ValueError("Invalid file name")
    return name


def human_size(num_bytes):
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


class SecureChannel:

    def __init__(self, sock, aesgcm):
        self.sock = sock
        self.aesgcm = aesgcm
        self._seq_out = 0
        self._seq_in = 0

    def send_bytes(self, data):
        nonce = os.urandom(NONCE_LEN)
        aad = self._seq_out.to_bytes(8, "big")
        send_frame(self.sock, nonce + self.aesgcm.encrypt(nonce, data, aad))
        self._seq_out += 1

    def recv_bytes(self):
        frame = recv_frame(self.sock)
        nonce, ciphertext = frame[:NONCE_LEN], frame[NONCE_LEN:]
        aad = self._seq_in.to_bytes(8, "big")
        data = self.aesgcm.decrypt(nonce, ciphertext, aad)
        self._seq_in += 1
        return data

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class FileServer:

    def __init__(self, host, port, storage_dir, log=print, key_size=2048,
                 params_file=PARAMS_FILE):
        self.host = host
        self.port = port
        self.storage_dir = storage_dir
        self.log = log
        self.key_size = key_size
        self.params_file = params_file

        self.parameters = None
        self.client_count = 0

        self._sock = None
        self._running = False
        self._count_lock = threading.Lock()

    def start(self):
        os.makedirs(self.storage_dir, exist_ok=True)
        self._running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self):
        self._running = False
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def running(self):
        return self._running

    def _serve(self):
        try:
            if self.parameters is None:
                if not os.path.exists(self.params_file):
                    self.log("Generating Diffie-Hellman parameters, "
                             "this happens only once and can take a while...")
                self.parameters = load_or_create_parameters(
                    self.params_file, self.key_size)
                self.log("Diffie-Hellman parameters ready.")

            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.listen(5)

            self.log(f"Listening on {self.host}:{self.port}")
            self.log(f"Storage folder: {self.storage_dir}")

            while self._running:
                try:
                    conn, addr = self._sock.accept()
                except OSError:
                    break
                threading.Thread(target=self._handle_client,
                                 args=(conn, addr), daemon=True).start()

        except OSError as exc:
            self.log(f"Could not start server: {exc}")
        finally:
            self._running = False
            self.log("Server stopped.")

    def _change_count(self, delta):
        with self._count_lock:
            self.client_count += delta

    def _handle_client(self, conn, addr):
        who = f"{addr[0]}:{addr[1]}"
        self._change_count(1)
        self.log(f"[{who}] connected")
        channel = None
        try:
            channel = SecureChannel(conn, server_handshake(conn, self.parameters))
            self.log(f"[{who}] secure channel established (AES-256-GCM)")

            while True:
                request = channel.recv_json()
                command = request.get("cmd")

                if command == "LIST":
                    self._cmd_list(channel, who)
                elif command == "UPLOAD":
                    self._cmd_upload(channel, who, request)
                elif command == "DOWNLOAD":
                    self._cmd_download(channel, who, request)
                elif command == "QUIT":
                    break
                else:
                    channel.send_json({"status": "error",
                                       "message": f"Unknown command: {command!r}"})

        except ConnectionError:
            self.log(f"[{who}] disconnected")
        except InvalidTag:
            self.log(f"[{who}] SECURITY: message failed authentication, dropping client")
        except Exception as exc:
            self.log(f"[{who}] error: {exc}")
        finally:
            if channel is not None:
                channel.close()
            else:
                conn.close()
            self._change_count(-1)
            self.log(f"[{who}] closed")

    def _list_files(self):
        files = []
        for name in sorted(os.listdir(self.storage_dir)):
            path = os.path.join(self.storage_dir, name)
            if os.path.isfile(path) and not name.endswith(".part"):
                files.append({"name": name, "size": os.path.getsize(path)})
        return files

    def _cmd_list(self, channel, who):
        files = self._list_files()
        self.log(f"[{who}] LIST -> {len(files)} file(s)")
        channel.send_json({"status": "ok", "files": files})

    def _cmd_upload(self, channel, who, request):
        try:
            name = safe_filename(request.get("name"))
            size = int(request.get("size", -1))
            if size < 0:
                raise ValueError("Invalid file size")
        except (TypeError, ValueError) as exc:
            channel.send_json({"status": "error", "message": str(exc)})
            return

        channel.send_json({"status": "ok"})
        self.log(f"[{who}] UPLOAD {name} ({human_size(size)}) starting")

        final_path = os.path.join(self.storage_dir, name)
        temp_path = final_path + ".part"
        received = 0
        try:
            with open(temp_path, "wb") as f:
                while received < size:
                    chunk = channel.recv_bytes()
                    if not chunk:
                        raise ValueError("Empty chunk received")
                    f.write(chunk)
                    received += len(chunk)
            os.replace(temp_path, final_path)
        except Exception:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            raise

        self.log(f"[{who}] UPLOAD {name} complete ({human_size(received)})")
        channel.send_json({"status": "ok", "message": f"Stored {name}"})

    def _cmd_download(self, channel, who, request):
        try:
            name = safe_filename(request.get("name"))
        except ValueError as exc:
            channel.send_json({"status": "error", "message": str(exc)})
            return

        path = os.path.join(self.storage_dir, name)
        if not os.path.isfile(path):
            self.log(f"[{who}] DOWNLOAD {name} -> not found")
            channel.send_json({"status": "error", "message": f"No such file: {name}"})
            return

        size = os.path.getsize(path)
        channel.send_json({"status": "ok", "size": size})
        self.log(f"[{who}] DOWNLOAD {name} ({human_size(size)}) starting")

        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                channel.send_bytes(chunk)

        self.log(f"[{who}] DOWNLOAD {name} complete")


class ServerApp:

    def __init__(self, root):
        self.root = root
        self.server = None
        self.log_queue = queue.Queue()
        self._after_id = None

        root.title("Secure File Server")
        root.geometry("680x460")
        root.minsize(520, 360)

        self._build_widgets()
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._after_id = self.root.after(100, self._drain_queue)

        self.log(f"Storage folder: {STORAGE_DIR}")
        self.log("Press Start to begin listening.")

    def _build_widgets(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Host:").pack(side="left")
        self.host_var = tk.StringVar(value=DEFAULT_HOST)
        ttk.Entry(top, textvariable=self.host_var, width=14).pack(side="left", padx=(4, 12))

        ttk.Label(top, text="Port:").pack(side="left")
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        ttk.Entry(top, textvariable=self.port_var, width=7).pack(side="left", padx=(4, 12))

        self.start_btn = ttk.Button(top, text="Start", command=self.start_server)
        self.start_btn.pack(side="left", padx=2)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_server, state="disabled")
        self.stop_btn.pack(side="left", padx=2)

        body = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="Log").pack(anchor="w")
        self.log_box = scrolledtext.ScrolledText(body, height=18, state="disabled", wrap="word")
        self.log_box.pack(fill="both", expand=True)

        status = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        status.pack(fill="x")
        self.status_var = tk.StringVar(value="Stopped  |  connected clients: 0")
        ttk.Label(status, textvariable=self.status_var).pack(side="left")

    def log(self, message):
        self.log_queue.put(f"[{time.strftime('%H:%M:%S')}] {message}")

    def _drain_queue(self):
        while True:
            try:
                line = self.log_queue.get_nowait()
            except queue.Empty:
                break
            self.log_box.configure(state="normal")
            self.log_box.insert("end", line + "\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")

        if self.server is not None:
            state = "Running" if self.server.running else "Stopped"
            self.status_var.set(
                f"{state}  |  connected clients: {self.server.client_count}")
            if not self.server.running and str(self.stop_btn["state"]) == "normal":
                self.stop_btn.configure(state="disabled")
                self.start_btn.configure(state="normal")

        self._after_id = self.root.after(100, self._drain_queue)

    def start_server(self):
        try:
            port = int(self.port_var.get())
        except ValueError:
            self.log("Port must be a number.")
            return

        self.server = FileServer(self.host_var.get().strip(), port,
                                 STORAGE_DIR, log=self.log)
        self.server.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")

    def stop_server(self):
        if self.server is not None:
            self.server.stop()
        self.stop_btn.configure(state="disabled")
        self.start_btn.configure(state="normal")

    def _on_close(self):
        self.stop_server()
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
            self._after_id = None
        self.root.destroy()


def main():
    root = tk.Tk()
    ServerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
