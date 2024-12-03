// src/components/SessionInitiation.js

import React from 'react';
import { Button, Typography, CircularProgress, Box } from '@mui/material';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_BASE_URL;

function SessionInitiation({ onSessionInitiated, onNotify }) {
  const [loading, setLoading] = React.useState(false);

  const initiateSession = async () => {
    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE_URL}/session/initiate`, {});
      const { sessionId, kyberPublicKey, ecdhePublicKey } = response.data;

      // Generate client's ECDHE key pair
      const keyPair = await window.crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: 'P-384',
        },
        true,
        ['deriveKey']
      );

      onSessionInitiated(
        { sessionId, kyberPublicKey, ecdhePublicKey },
        { publicKey: keyPair.publicKey, privateKey: keyPair.privateKey }
      );

      onNotify('Session initiated successfully!', 'success');
    } catch (error) {
      console.error('Error initiating session:', error);
      onNotify('Failed to initiate session.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box textAlign="center">
      <Typography variant="h6" gutterBottom>
        Start a New Session
      </Typography>
      <Button variant="contained" color="primary" onClick={initiateSession} disabled={loading}>
        {loading ? <CircularProgress size={24} color="inherit" /> : 'Initiate Session'}
      </Button>
    </Box>
  );
}

export default SessionInitiation;