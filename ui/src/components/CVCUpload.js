// src/components/CVCUpload.js

import React, { useState } from 'react';
import { TextField, Button, Typography, CircularProgress, Box } from '@mui/material';
import axios from 'axios';
import { encryptData, generateRandomSalt } from '../utils/crypto';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;

function CVCUpload({ session, aesKey, onNotify }) {
  const [cvc, setCvc] = useState('');
  const [loading, setLoading] = useState(false);

  const handleUpload = async () => {
    if (!cvc) {
      onNotify('CVC cannot be empty.', 'warning');
      return;
    }

    setLoading(true);
    try {
      // Encrypt CVC using AES-GCM
      const { ciphertext, iv } = await encryptData(aesKey, cvc);

      // Compute SHA-256 hash of the CVC
      const encoder = new TextEncoder();
      const dataHashBuffer = await window.crypto.subtle.digest('SHA-256', encoder.encode(cvc));
      const dataHashArray = Array.from(new Uint8Array(dataHashBuffer));
      const dataHash = dataHashArray.map(b => b.toString(16).padStart(2, '0')).join('');

      // Placeholder for KEM ciphertext (since Kyber isn't implemented in JS)
      const kemCiphertext = btoa('kem-ciphertext-placeholder');

      // Export client's ECDHE public key
      const exportedClientKey = await window.crypto.subtle.exportKey('spki', session.clientKeyPair.publicKey);
      const clientKeyB64 = btoa(String.fromCharCode(...new Uint8Array(exportedClientKey)));

      // Generate random salt
      const salt = generateRandomSalt();

      // Prepare payload
      const payload = {
        sessionId: session.sessionId,
        encryptedData: ciphertext,
        salt: salt,
        iv: iv,
        hash: dataHash,
        kemCiphertext: kemCiphertext,
        clientEcdhPublicKey: clientKeyB64,
      };

      // Send data to the server
      const uploadResponse = await axios.post(`${API_BASE_URL}/data/upload`, payload);

      onNotify('CVC uploaded successfully!', 'success');
      setCvc('');
    } catch (error) {
      console.error('Error uploading CVC:', error);
      onNotify('Failed to upload CVC.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Upload CVC
      </Typography>
      <TextField
        label="CVC Code"
        variant="outlined"
        fullWidth
        value={cvc}
        onChange={e => setCvc(e.target.value)}
        sx={{ mb: 2 }}
        inputProps={{ maxLength: 10 }}
      />
      <Button variant="contained" color="primary" onClick={handleUpload} disabled={loading}>
        {loading ? <CircularProgress size={24} color="inherit" /> : 'Upload CVC'}
      </Button>
    </Box>
  );
}

export default CVCUpload;