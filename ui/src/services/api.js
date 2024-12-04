import axios from 'axios';

const API_URL = 'http://127.0.0.1:8000/api';

// Initiates a session and returns the session ID and the symmetric key (base64)
export const initiateSession = async () => {
  try {
    const response = await axios.post(`${API_URL}/session/initiate`);
    if (response.status === 200) {
      const sessionData = response.data;
      return {
        sessionId: sessionData.session_id,
        symmetricKey: sessionData.shared_symmetric_key,
      };
    }
  } catch (error) {
    console.error('Error initiating session:', error);
    return null;
  }
};

// Uploads encrypted data and IV to the server
export const uploadData = async (sessionId, encryptedData, iv) => {
  try {
    const response = await axios.post(`${API_URL}/data/upload`, {
      sessionId,
      encryptedData,
      iv,
    });
    if (response.status === 200) {
      return response.data;
    }
  } catch (error) {
    console.error('Error uploading data:', error);
    return null;
  }
};

// Retrieve data from the server
export const retrieveData = async (sessionId, recordId) => {
  try {
    const response = await axios.post(`${API_URL}/data/retrieve`, {
      sessionId,
      recordId,
    });
    if (response.status === 200) {
      return response.data;
    }
  } catch (error) {
    console.error('Error retrieving data:', error);
    return null;
  }
};