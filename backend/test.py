# test.py

import oqs
import os

# Simulated database to store session information
session_db = {}

# Server-side: Handle session initiation
def server_session_initiate(client_public_key_hex):
    # Since Kyber doesn't require the client's public key for encapsulation,
    # we can ignore it or use it if you have a specific protocol in mind.
    
    # Server generates its Kyber key pair
    server_kem = oqs.KeyEncapsulation("Kyber512")
    server_public_key = server_kem.generate_keypair()

    # Generate a session ID
    session_id = os.urandom(16).hex()

    # Store server's private key associated with the session ID
    session_db[session_id] = {
        'server_kem': server_kem
    }

    response = {
        'sessionId': session_id,
        'serverPublicKey': server_public_key.hex(),
        # The session key will be established after client responds
    }
    return response

# Client-side: Establish session using server's public key
def client_session_establish(server_public_key_hex):
    server_public_key = bytes.fromhex(server_public_key_hex)
    client_kem = oqs.KeyEncapsulation("Kyber512")
    # Client encapsulates the shared secret using server's public key
    ciphertext, shared_secret_client = client_kem.encap_secret(server_public_key)
    return ciphertext.hex(), shared_secret_client

# Server-side: Complete the session after receiving ciphertext
def server_complete_session(session_id, ciphertext_hex):
    server_kem = session_db[session_id]['server_kem']
    ciphertext = bytes.fromhex(ciphertext_hex)
    # Server decapsulates the ciphertext to obtain the shared secret
    shared_secret_server = server_kem.decap_secret(ciphertext)
    # Store the shared secret in session_db
    session_db[session_id]['shared_secret'] = shared_secret_server
    return shared_secret_server

def main():
    # Client initiates the session (could send its public key if protocol requires)
    client_public_key_hex = ""  # Not used in this example

    # Server handles session initiation
    response = server_session_initiate(client_public_key_hex)
    session_id = response['sessionId']
    server_public_key_hex = response['serverPublicKey']

    # Client establishes session using server's public key
    ciphertext_hex, shared_secret_client = client_session_establish(server_public_key_hex)

    # Client sends ciphertext to server (in a real scenario, over the network)
    shared_secret_server = server_complete_session(session_id, ciphertext_hex)

    # Verify that both parties have the same shared secret
    if shared_secret_client == shared_secret_server:
        print("Key exchange successful!")
        print("Shared secret:", shared_secret_client.hex())
    else:
        print("Key exchange failed.")

if __name__ == "__main__":
    main()