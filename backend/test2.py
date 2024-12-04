import requests

# Server URL (update if necessary)
BASE_URL = "http://127.0.0.1:8000/api"

# Function to retrieve data
def retrieve_data(session_id):
    data = {
        'sessionId': session_id,
        'recordId': '1'  # Assuming you want to retrieve the first record or use the actual record ID
    }
    response = requests.post(f"{BASE_URL}/data/retrieve", json=data)
    if response.status_code == 200:
        print("Retrieved data:", response.json())
    else:
        print("Error retrieving data:", response.json())

def main():
    # Assuming session_id was saved after upload, replace with the actual session_id
    session_id = "9746fd1321d7a543f27f18640c96b10d"  # Replace with the actual session_id from previous step
    
    # Step 2: Retrieve data
    retrieve_data(session_id)

if __name__ == "__main__":
    main()
