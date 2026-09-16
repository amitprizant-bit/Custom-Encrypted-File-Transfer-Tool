import json
import os
import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 12345
CONNECT_TIMEOUT = 10

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


def client_handshake(sock):
    parameters = serialization.load_pem_parameters(recv_frame(sock))
    server_public_key = serialization.load_der_public_key(recv_frame(sock))

    private_key = parameters.generate_private_key()
    send_frame(sock, private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

    return AESGCM(derive_aes_key(private_key.exchange(server_public_key)))


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

    def send_json(self, obj):
        self.send_bytes(json.dumps(obj).encode("utf-8"))

    def recv_json(self):
        return json.loads(self.recv_bytes().decode("utf-8"))

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class FileClient:

    def __init__(self):
        self.channel = None
        self._lock = threading.Lock()

    @property
    def connected(self):
        return self.channel is not None

    def connect(self, host, port):
        sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        sock.settimeout(None)
        self.channel = SecureChannel(sock, client_handshake(sock))

    def disconnect(self):
        if self.channel is None:
            return
        try:
            self.channel.send_json({"cmd": "QUIT"})
        except (OSError, ConnectionError):
            pass
        self.channel.close()
        self.channel = None

    def _require_connection(self):
        if self.channel is None:
            raise ValueError("Not connected")

    def _check(self, response):
        if response.get("status") != "ok":
            raise ValueError(response.get("message", "unknown server error"))
        return response

    def list_files(self):
        self._require_connection()
        with self._lock:
            self.channel.send_json({"cmd": "LIST"})
            response = self._check(self.channel.recv_json())
        return response["files"]

    def upload(self, path, progress=None):
        self._require_connection()
        name = os.path.basename(path)
        size = os.path.getsize(path)

        with self._lock:
            self.channel.send_json({"cmd": "UPLOAD", "name": name, "size": size})
            self._check(self.channel.recv_json())

            sent = 0
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    self.channel.send_bytes(chunk)
                    sent += len(chunk)
                    if progress:
                        progress(sent, size)

            self._check(self.channel.recv_json())
        return sent

    def download(self, name, dest_path, progress=None):
        self._require_connection()
        with self._lock:
            self.channel.send_json({"cmd": "DOWNLOAD", "name": name})
            response = self._check(self.channel.recv_json())
            size = int(response["size"])

            temp_path = dest_path + ".part"
            received = 0
            try:
                with open(temp_path, "wb") as f:
                    while received < size:
                        chunk = self.channel.recv_bytes()
                        f.write(chunk)
                        received += len(chunk)
                        if progress:
                            progress(received, size)
                os.replace(temp_path, dest_path)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
        return size


class ClientApp:

    def __init__(self, root):
        self.root = root
        self.client = FileClient()
        self.log_queue = queue.Queue()
        self.busy = False
        self.files = []
        self._after_id = None

        root.title("Secure File Client")
        root.geometry("700x540")
        root.minsize(560, 420)

        self._build_widgets()
        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._after_id = self.root.after(100, self._drain_queue)

        self.log("Not connected. Enter the server address and press Connect.")
        self._update_controls()

    def _build_widgets(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Host:").pack(side="left")
        self.host_var = tk.StringVar(value=DEFAULT_HOST)
        self.host_entry = ttk.Entry(top, textvariable=self.host_var, width=14)
        self.host_entry.pack(side="left", padx=(4, 12))

        ttk.Label(top, text="Port:").pack(side="left")
        self.port_var = tk.StringVar(value=str(DEFAULT_PORT))
        self.port_entry = ttk.Entry(top, textvariable=self.port_var, width=7)
        self.port_entry.pack(side="left", padx=(4, 12))

        self.connect_btn = ttk.Button(top, text="Connect", command=self.connect)
        self.connect_btn.pack(side="left", padx=2)
        self.disconnect_btn = ttk.Button(top, text="Disconnect", command=self.disconnect)
        self.disconnect_btn.pack(side="left", padx=2)

        middle = ttk.Frame(self.root, padding=(10, 0, 10, 0))
        middle.pack(fill="both", expand=True)

        left = ttk.Frame(middle)
        left.pack(side="left", fill="both", expand=True)
        ttk.Label(left, text="Files on server").pack(anchor="w")

        list_frame = ttk.Frame(left)
        list_frame.pack(fill="both", expand=True)
        self.file_list = tk.Listbox(list_frame, height=10)
        self.file_list.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical",
                                  command=self.file_list.yview)
        scrollbar.pack(side="right", fill="y")
        self.file_list.configure(yscrollcommand=scrollbar.set)
        self.file_list.bind("<Double-Button-1>", lambda _event: self.download())

        buttons = ttk.Frame(middle, padding=(10, 18, 0, 0))
        buttons.pack(side="left", fill="y")
        self.refresh_btn = ttk.Button(buttons, text="Refresh", width=16,
                                      command=self.refresh)
        self.refresh_btn.pack(pady=3)
        self.upload_btn = ttk.Button(buttons, text="Upload file...", width=16,
                                     command=self.upload)
        self.upload_btn.pack(pady=3)
        self.download_btn = ttk.Button(buttons, text="Download selected", width=16,
                                       command=self.download)
        self.download_btn.pack(pady=3)

        progress_frame = ttk.Frame(self.root, padding=10)
        progress_frame.pack(fill="x")
        self.progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(progress_frame, variable=self.progress_var,
                                        maximum=100)
        self.progress.pack(fill="x")

        bottom = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        bottom.pack(fill="both", expand=True)
        ttk.Label(bottom, text="Log").pack(anchor="w")
        self.log_box = scrolledtext.ScrolledText(bottom, height=9, state="disabled",
                                                 wrap="word")
        self.log_box.pack(fill="both", expand=True)

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
        self._after_id = self.root.after(100, self._drain_queue)

    def _update_controls(self):
        connected = self.client.connected
        idle = not self.busy
        self.connect_btn.configure(state="normal" if (idle and not connected) else "disabled")
        self.disconnect_btn.configure(state="normal" if (idle and connected) else "disabled")
        for button in (self.refresh_btn, self.upload_btn, self.download_btn):
            button.configure(state="normal" if (idle and connected) else "disabled")
        for entry in (self.host_entry, self.port_entry):
            entry.configure(state="normal" if (idle and not connected) else "disabled")

    def _run_async(self, work):
        if self.busy:
            return
        self.busy = True
        self._update_controls()

        def worker():
            try:
                work()
            except InvalidTag:
                self.log("SECURITY: reply failed authentication - data was "
                         "corrupted or tampered with.")
            except ValueError as exc:
                self.log(f"Server refused: {exc}")
            except (ConnectionError, OSError) as exc:
                self.log(f"Connection problem: {exc}")
                self.client.channel = None
            except Exception as exc:
                self.log(f"Error: {exc}")
            finally:
                self.root.after(0, self._finish)

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self):
        self.busy = False
        self.progress_var.set(0)
        self._update_controls()

    def _set_progress(self, done, total):
        percent = 100.0 if total == 0 else (done / total) * 100
        self.root.after(0, lambda: self.progress_var.set(percent))

    def _show_files(self, files):
        self.files = files
        self.file_list.delete(0, "end")
        for entry in files:
            self.file_list.insert("end", f"{entry['name']}   ({human_size(entry['size'])})")

    def connect(self):
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get())
        except ValueError:
            self.log("Port must be a number.")
            return

        self.log(f"Connecting to {host}:{port} ...")

        def work():
            self.client.connect(host, port)
            self.log("Connected. Diffie-Hellman handshake done, "
                     "channel is AES-256-GCM encrypted.")
            files = self.client.list_files()
            self.root.after(0, lambda: self._show_files(files))

        self._run_async(work)

    def disconnect(self):
        self.client.disconnect()
        self.file_list.delete(0, "end")
        self.files = []
        self.log("Disconnected.")
        self._update_controls()

    def refresh(self):
        def work():
            files = self.client.list_files()
            self.root.after(0, lambda: self._show_files(files))
            self.log(f"Server has {len(files)} file(s).")

        self._run_async(work)

    def upload(self):
        path = filedialog.askopenfilename(title="Choose a file to upload")
        if not path:
            return

        def work():
            self.log(f"Uploading {os.path.basename(path)} ...")
            sent = self.client.upload(path, progress=self._set_progress)
            self.log(f"Upload complete ({human_size(sent)}).")
            files = self.client.list_files()
            self.root.after(0, lambda: self._show_files(files))

        self._run_async(work)

    def download(self):
        selection = self.file_list.curselection()
        if not selection:
            messagebox.showinfo("Download", "Select a file in the list first.")
            return
        name = self.files[selection[0]]["name"]

        dest = filedialog.asksaveasfilename(title="Save file as",
                                            initialfile=name)
        if not dest:
            return

        def work():
            self.log(f"Downloading {name} ...")
            size = self.client.download(name, dest, progress=self._set_progress)
            self.log(f"Saved {human_size(size)} to {dest}")

        self._run_async(work)

    def _on_close(self):
        try:
            self.client.disconnect()
        except Exception:
            pass
        if self._after_id is not None:
            self.root.after_cancel(self._after_id)
            self._after_id = None
        self.root.destroy()


def main():
    root = tk.Tk()
    ClientApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
