import socket
import ssl
import threading

from crypto_utils import verify_message

# Shared storage to hold messages for Alice and Bob
# Format: {"Alice": ["msg1", "msg2"], "Bob": ["msg3"]}
message_store = {"Alice": [], "Bob": []}
lock = threading.Lock()  # Ensures thread safety when multiple clients connect


def handle_client(conn):
    try:
        # --- Show the negotiated key exchange / cipher for this connection ---
        cipher_name, tls_version, secret_bits = conn.cipher()
        print(f"[TLS] Connection secured using {cipher_name} "
              f"({tls_version}, {secret_bits}-bit) -- key exchange: ECDHE")

        data = conn.recv(2048).decode()

        # New protocol: "Sender:Message:Signature"
        # (Signature is base64, sent as the 3rd field)
        parts = data.split(":", 2)

        if len(parts) < 2:
            conn.send("ERROR: Malformed request".encode())
            return

        sender = parts[0]
        content = parts[1]

        # Determine the other user
        recipient = "Bob" if sender == "Alice" else "Alice"

        if content == "FETCH_INBOX":
            # User wants to see their messages (no signature needed for a fetch)
            messages = message_store.get(sender, [])
            conn.send(str(messages).encode())
            # Clear their inbox after fetching (read-and-delete)
            message_store[sender] = []
            return

        # --- Sending a message: signature is REQUIRED ---
        if len(parts) < 3 or not parts[2]:
            conn.send("REJECTED: Missing signature".encode())
            return

        signature_b64 = parts[2]

        # --- Verify the sender's identity cryptographically ---
        if not verify_message(sender, content, signature_b64):
            print(f"[SECURITY] Rejected forged/invalid message claiming to be from {sender}")
            conn.send("REJECTED: Invalid signature".encode())
            return

        # Signature valid -> message is authentically from `sender`
        with lock:
            message_store[recipient].append(f"{sender}: {content}")

        conn.send(f"Message delivered to {recipient} (signature verified)".encode())

    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        conn.close()


# --- TLS Setup ---
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

# Force the server to only negotiate cipher suites that use ECDHE
# (Elliptic-Curve Diffie-Hellman Ephemeral) for key exchange.
# This makes the key exchange algorithm explicit and forward-secret,
# rather than letting TLS silently pick whatever the client offers.
context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')

# Require TLS 1.2 minimum (ECDHE cipher strings above need 1.2/1.3 anyway)
context.minimum_version = ssl.TLSVersion.TLSv1_2

bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bind_socket.bind(('localhost', 8443))
bind_socket.listen(5)

print("TLS Hub is running and listening on port 8443...")
print("Cipher policy: ECDHE-only (forward-secret key exchange enforced)\n")

while True:
    try:
        newsocket, fromaddr = bind_socket.accept()
        conn = context.wrap_socket(newsocket, server_side=True)
        # Handle each connection in a new thread
        threading.Thread(target=handle_client, args=(conn,)).start()
    except Exception as e:
        print(f"Server error: {e}")
