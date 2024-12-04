import React, { useState } from 'react';
import { initiateSession, uploadData, retrieveData } from '../services/api';
import CryptoJS from 'crypto-js';

const DataUpload = () => {
  const [activeTab, setActiveTab] = useState('upload');
  const [sessionId, setSessionId] = useState(null);
  const [symmetricKey, setSymmetricKey] = useState(null);
  const [cvc, setCvc] = useState('');
  const [encryptedData, setEncryptedData] = useState('');
  const [iv, setIv] = useState('');
  const [status, setStatus] = useState('');
  const [serverResponse, setServerResponse] = useState(null);
  const [inputSessionId, setInputSessionId] = useState(''); // Input for sessionId in retrieve
  const [recordId] = useState('1');  // Hardcoded recordId

  // Function to initiate session and get symmetric key
  const initiateSessionAndEncryptData = async () => {
    setStatus('Initiating session...');
    const sessionData = await initiateSession();
    if (sessionData) {
      setSessionId(sessionData.sessionId);
      setSymmetricKey(sessionData.symmetricKey);
      setStatus('Session initiated, now input your CVC...');
    } else {
      setStatus('Error initiating session.');
    }
  };

  // Encrypt data using AES CBC mode
  const encryptData = (key, cvc) => {
    const iv = CryptoJS.lib.WordArray.random(16); // Generate random IV
    const ciphertext = CryptoJS.AES.encrypt(cvc, CryptoJS.enc.Base64.parse(key), { iv });
    const encryptedDataBase64 = ciphertext.toString();
    const ivBase64 = iv.toString(CryptoJS.enc.Base64);
    setEncryptedData(encryptedDataBase64);
    setIv(ivBase64);
    setStatus('Data encrypted, ready to upload...');
  };

  // Handle data upload
  const handleUploadData = async () => {
    if (!encryptedData || !iv) {
      setStatus('Please input your CVC and encrypt the data first.');
      return;
    }
    setStatus('Uploading data...');
    const response = await uploadData(sessionId, encryptedData, iv);
    setServerResponse(response);
    if (response) {
      setStatus('Data uploaded successfully!');
    } else {
      setStatus('Error uploading data.');
    }
  };

  // Handle data retrieval
  const handleRetrieveData = async () => {
    if (!inputSessionId) {
      setStatus('Please enter a session ID to retrieve data.');
      return;
    }
    setStatus('Retrieving data...');
    const response = await retrieveData(inputSessionId, recordId);
    if (response) {
      setServerResponse(response);
      setStatus('Data retrieved successfully!');
    } else {
      setStatus('Error retrieving data.');
    }
  };

  return (
    <div className="app-container">
      <div className="tabs">
        <button
          className={activeTab === 'upload' ? 'tab active' : 'tab'}
          onClick={() => setActiveTab('upload')}
        >
          Upload
        </button>
        <button
          className={activeTab === 'retrieve' ? 'tab active' : 'tab'}
          onClick={() => setActiveTab('retrieve')}
        >
          Retrieve
        </button>
      </div>

      <div className="content">
        {activeTab === 'upload' ? (
          <>
            {!sessionId ? (
              <button onClick={initiateSessionAndEncryptData} className="action-button">
                Initiate Session
              </button>
            ) : (
              <>
                <div className="input-group">
                  <label htmlFor="cvc">Enter CVC (or custom data):</label>
                  <input
                    type="text"
                    id="cvc"
                    placeholder="Enter your CVC"
                    value={cvc}
                    onChange={(e) => setCvc(e.target.value)}
                  />
                </div>

                <button onClick={() => encryptData(symmetricKey, cvc)} className="action-button">
                  Generate Encrypted Data
                </button>

                <div className="output">
                  <p><strong>Encrypted Data:</strong></p>
                  <textarea value={encryptedData} readOnly rows="4" />
                  <p><strong>IV (Initialization Vector):</strong></p>
                  <textarea value={iv} readOnly rows="2" />
                </div>

                <button onClick={handleUploadData} className="action-button">
                  Upload Data
                </button>
              </>
            )}
          </>
        ) : (
          <>
            <div className="input-group">
              <label htmlFor="sessionId">Enter Session ID to Retrieve:</label>
              <input
                type="text"
                id="sessionId"
                value={inputSessionId}
                onChange={(e) => setInputSessionId(e.target.value)}
                placeholder="Session ID"
              />
            </div>

            <button onClick={handleRetrieveData} className="action-button">
              Retrieve Data
            </button>
          </>
        )}

        <p>{status}</p>
        {serverResponse && (
          <div className="server-response">
            <h3>Server Response:</h3>
            <pre>{JSON.stringify(serverResponse, null, 2)}</pre>
          </div>
        )}
      </div>

      <div className="sidebar">
        <h3>Session Info</h3>
        <p><strong>Session ID:</strong> {sessionId || 'Not initialized'}</p>
        <p><strong>Record ID:</strong> {recordId}</p>
      </div>
    </div>
  );
};

export default DataUpload;