import React, { useState } from 'react';
import { retrieveData } from '../services/api';

const DataRetrieve = ({ sessionId }) => {
  const [recordId, setRecordId] = useState('');
  const [retrievedData, setRetrievedData] = useState('');
  const [status, setStatus] = useState('');

  const handleRetrieve = async () => {
    if (!recordId) {
      setStatus('Please provide a record ID.');
      return;
    }
    setStatus('Retrieving...');
    try {
      const response = await retrieveData(sessionId, recordId);
      setRetrievedData(response.decryptedData);
      setStatus('Data retrieved successfully.');
    } catch (error) {
      setStatus('Error retrieving data');
    }
  };

  return (
    <div className="card">
      <h2>Retrieve Data</h2>
      <input
        type="text"
        placeholder="Record ID"
        value={recordId}
        onChange={(e) => setRecordId(e.target.value)}
      />
      <button onClick={handleRetrieve}>Retrieve Data</button>
      <p>{status}</p>
      {retrievedData && (
        <div className="data-output">
          <h3>Decrypted Data:</h3>
          <pre>{retrievedData}</pre>
        </div>
      )}
    </div>
  );
};

export default DataRetrieve;