// src/services/api.js

import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;

// Function to initiate a session
export const initiateSession = async () => {
  const response = await axios.post(`${API_BASE_URL}/session/initiate`, {});
  return response.data;
};

// Function to upload CVC
export const uploadCVC = async (payload) => {
  const response = await axios.post(`${API_BASE_URL}/data/upload`, payload);
  return response.data;
};

// Function to retrieve CVC
export const retrieveCVC = async (payload) => {
  const response = await axios.post(`${API_BASE_URL}/data/retrieve`, payload);
  return response.data;
};