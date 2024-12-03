// src/App.js

import React, { useState, useEffect } from 'react';
import { Container, Typography, Box, Paper } from '@mui/material';
import SessionInitiation from './components/SessionInitiation';
import CVCUpload from './components/CVCUpload';
import CVCRetrieve from './components/CVCRetrieve';
import Notification from './components/Notification';
import { deriveSharedKey } from './utils/crypto';

function App() {
  const [session, setSession] = useState(null);
  const [clientKeyPair, setClientKeyPair] = useState(null);
  const [serverECDHPublicKey, setServerECDHPublicKey] = useState(null);
  const [aesKey, setAesKey] = useState(null);
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' });

  // Function to handle session initiation
  const handleSessionInitiated = async (sessionData, clientKeys) => {
    setSession(sessionData);
    setClientKeyPair(clientKeys);

    // Import server's ECDHE public key
    const serverKeyBuffer = Uint8Array.from(atob(sessionData.ecdhePublicKey), c => c.charCodeAt(0));
    const importedServerKey = await window.crypto.subtle.importKey(
      'spki',
      serverKeyBuffer.buffer,
      {
        name: 'ECDH',
        namedCurve: 'P-384',
      },
      true,
      []
    );

    setServerECDHPublicKey(importedServerKey);

    // Derive shared AES key
    const derivedKey = await deriveSharedKey(clientKeys.privateKey, importedServerKey);
    setAesKey(derivedKey);
  };

  // Function to derive shared AES key
  const deriveSharedKey = async (privateKey, publicKey) => {
    try {
      const sharedSecret = await window.crypto.subtle.deriveBits(
        {
          name: 'ECDH',
          public: publicKey,
        },
        privateKey,
        256
      );

      // Derive AES key from shared secret using SHA-256
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', sharedSecret);
      const aesKey = await window.crypto.subtle.importKey(
        'raw',
        hashBuffer,
        {
          name: 'AES-GCM',
        },
        false,
        ['encrypt', 'decrypt']
      );

      return aesKey;
    } catch (error) {
      console.error('Error deriving shared key:', error);
      setSnackbar({ open: true, message: 'Failed to derive shared key.', severity: 'error' });
      return null;
    }
  };

  // Function to handle notifications
  const handleNotification = (message, severity) => {
    setSnackbar({ open: true, message, severity });
  };

  // Function to close Snackbar
  const handleCloseSnackbar = () => {
    setSnackbar({ ...snackbar, open: false });
  };

  return (
    <Container maxWidth="md" sx={{ mt: 5, mb: 5 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h4" align="center" gutterBottom>
          CVC Manager
        </Typography>

        {/* Session Initiation */}
        <Box sx={{ mt: 4 }}>
          <SessionInitiation onSessionInitiated={handleSessionInitiated} onNotify={handleNotification} />
        </Box>

        {/* CVC Upload and Retrieve - Render only if session and AES key are available */}
        {session && aesKey && (
          <>
            <Box sx={{ mt: 4 }}>
              <CVCUpload session={session} aesKey={aesKey} onNotify={handleNotification} />
            </Box>
            <Box sx={{ mt: 4 }}>
              <CVCRetrieve session={session} aesKey={aesKey} onNotify={handleNotification} />
            </Box>
          </>
        )}
      </Paper>

      {/* Notification Component */}
      <Notification snackbar={snackbar} onClose={handleCloseSnackbar} />
    </Container>
  );
}

export default App;