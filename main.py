import streamlit as st
import socket
import ssl
import ast

from crypto_utils import sign_message

# Configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 8443


def make_tls_context():
    """Builds a TLS context that forces ECDHE-based key exchange."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Only offer ECDHE cipher suites to the server -> forces a
    # forward-secret, elliptic-curve Diffie-Hellman key exchange
    # instead of letting TLS pick silently.
    context.set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20')
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def send_to_server(sender, message):
    """Signs the message with the sender's private key, then sends
    it through the encrypted TLS tunnel."""
    context = make_tls_context()

    try:
        with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:

                # --- Digital signature: proves this message really
                # came from `sender` (non-repudiation) ---
                signature = sign_message(sender, message)

                # Protocol: "Sender:Message:Signature"
                payload = f"{sender}:{message}:{signature}"
                ssock.sendall(payload.encode())

                # Expose the negotiated key exchange / cipher to the UI
                cipher_name, tls_version, secret_bits = ssock.cipher()
                st.session_state["last_cipher"] = (
                    f"{cipher_name} | {tls_version} | {secret_bits}-bit "
                    f"(key exchange: ECDHE)"
                )

                return ssock.recv(1024).decode()
    except FileNotFoundError:
        return ("Signing Error: private key file not found. "
                "Run keygen.py first.")
    except Exception as e:
        return f"Connection Error: {e}"


def fetch_inbox(user_name):
    """Retrieves messages from the secure Hub."""
    context = make_tls_context()

    try:
        with socket.create_connection((SERVER_HOST, SERVER_PORT)) as sock:
            with context.wrap_socket(sock, server_hostname=SERVER_HOST) as ssock:
                # FETCH_INBOX has no message body, so no signature needed
                ssock.sendall(f"{user_name}:FETCH_INBOX:".encode())
                response = ssock.recv(4096).decode()
                return ast.literal_eval(response)
    except Exception as e:
        return [f"Connection Error: {e}"]


# --- GUI ---
st.set_page_config(page_title="MACS902 Secure Chat", layout="centered")
st.title("🔐 Secure Two-Way TLS Messaging")

user = st.radio("Select your identity:", ["Alice", "Bob"])
st.write(f"Logged in as: **{user}**")

# Messaging Section
msg = st.text_input("Enter message for the other user:")
if st.button("Send Securely 🚀"):
    response = send_to_server(user, msg)
    if response.startswith("REJECTED") or response.startswith(("Connection Error", "Signing Error")):
        st.error(f"Hub Response: {response}")
    else:
        st.success(f"Hub Response: {response}")

# Show the negotiated key exchange / cipher info from the last send
if "last_cipher" in st.session_state:
    st.caption(f"🔑 TLS session: {st.session_state['last_cipher']}")

st.markdown("---")

# Inbox Section
if st.button("Check Inbox 📥"):
    messages = fetch_inbox(user)
    if messages:
        st.subheader("Your Messages:")
        for m in messages:
            st.chat_message("assistant").write(m)
    else:
        st.info("Inbox is empty.")
