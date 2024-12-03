// src/components/CVCRetrieve.js

import React, { useState } from 'react';
import { TextField, Button, Typography, CircularProgress, Box } from '@mui/material';
import axios from 'axios';
import { decryptData } from '../utils/crypto';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;

function CVCRetrieve({ session, aesKey, onNotify }) {
  const [recordId, setRecordId] = useState('');
  const [retrievedCvc, setRetrievedCvc] = useState('');
  const [loading, setLoading] = useState(false);

  const handleRetrieve = async () => {
    if (!recordId) {
      onNotify('Record ID cannot be empty.', 'warning');
      return;
    }

    setLoading(true);
    try {
      // Fetch encrypted data from the server
      const retrieveResponse = await axios.post(`${API_BASE_URL}/data/retrieve`, {
        sessionId: session.sessionId,
        recordId: recordId,
      });

      const {
        salt,
        iv,
        dataHash,
        encryptedData,
        kemCiphertext,
        clientEcdhPublicKey,
        serverEcdhPublicKey,
      } = retrieveResponse.data;

      // Decrypt CVC using AES-GCM
      const decryptedCvc = await decryptData(aesKey, encryptedData, iv);

      // Optionally, verify data hash
      const encoder = new TextEncoder();
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', encoder.encode(decryptedCvc));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const computedHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      if (computedHash !== dataHash) {
        onNotify('Data integrity check failed.', 'error');
        return;
      }

      setRetrievedCvc(decryptedCvc);
      onNotify('CVC retrieved successfully!', 'success');
    } catch (error) {
      console.error('Error retrieving CVC:', error);
      onNotify('Failed to retrieve CVC.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Retrieve CVC
      </Typography>
      <TextField
        label="Record ID"
        variant="outlined"
        fullWidth
        value={recordId}
        onChange={e => setRecordId(e.target.value)}
        sx={{ mb: 2 }}
      />
      <Button variant="contained" color="secondary" onClick={handleRetrieve} disabled={loading}>
        {loading ? <CircularProgress size={24} color="inherit" /> : 'Retrieve CVC'}
      </Button>

      {retrievedCvc && (
        <Box sx={{ mt: 3 }}>
          <Typography variant="subtitle1">Retrieved CVC:</Typography>
          <Typography variant="h6" color="primary">
            {retrievedCvc}
          </Typography>
        </Box>
      )}
    </Box>
  );
}

export default CVCRetrieve;