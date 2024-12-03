// src/components/Notification.js

import React from 'react';
import { Snackbar, Alert } from '@mui/material';

function Notification({ snackbar, onClose }) {
  return (
    <Snackbar
      open={snackbar.open}
      autoHideDuration={6000}
      onClose={onClose}
      anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
    >
      <Alert onClose={onClose} severity={snackbar.severity} sx={{ width: '100%' }}>
        {snackbar.message}
      </Alert>
    </Snackbar>
  );
}

export default Notification;