import axios from 'axios';

const BASE_URL = "http://127.0.0.1:8000/api";

export async function initiateSession() {
  const response = await axios.post(`${BASE_URL}/session/initiate`);
  return response.data;
}

export async function finalizeSession(sessionId) {
  const response = await axios.post(`${BASE_URL}/session/finalize`, { sessionId });
  return response.data;
}

export async function uploadData(sessionId, plaintext) {
  const response = await axios.post(`${BASE_URL}/data/upload`, { sessionId, plaintext });
  return response.data;
}

export async function retrieveData(sessionId, recordId) {
  const response = await axios.post(`${BASE_URL}/data/retrieve`, { sessionId, recordId });
  return response.data;
}

export async function getAllData() {
  const response = await axios.get(`${BASE_URL}/data/all`);
  return response.data; 
}