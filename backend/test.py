import requests

BASE_URL = "http://127.0.0.1:8000"

def main():
    # Initiate session
    r = requests.post(f"{BASE_URL}/api/session/initiate")
    r.raise_for_status()
    data = r.json()
    session_id = data['session_id']
    print("Session initiated:", session_id)

    # Finalize session (server does PQC internally, no client PQC needed)
    r = requests.post(f"{BASE_URL}/api/session/finalize", json={
        'sessionId': session_id,
    })
    r.raise_for_status()
    print("Session finalized successfully.")

    # Upload data (send plaintext)
    plaintext = "Hello, this is a secret message!"
    r = requests.post(f"{BASE_URL}/api/data/upload", json={
        'sessionId': session_id,
        'plaintext': plaintext
    })
    r.raise_for_status()
    upload_resp = r.json()
    record_id = upload_resp['recordId']
    print("Data uploaded successfully, recordId:", record_id)

    # Retrieve data
    r = requests.post(f"{BASE_URL}/api/data/retrieve", json={
        'sessionId': session_id,
        'recordId': record_id
    })
    r.raise_for_status()
    retrieved = r.json()
    print("Retrieved data:", retrieved['plaintext'])

    # Check
    if retrieved['plaintext'] == plaintext:
        print("Success! The retrieved data matches the original plaintextttt.")
    else:
        print("Error: The retrieved data does not match the original plaintext.")

if __name__ == "__main__":
    main()