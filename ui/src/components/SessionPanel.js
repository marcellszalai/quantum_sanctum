// SessionPanel.js
import React from 'react';
import { Paper, Typography, TextField, Button, Stack } from '@mui/material';

const SessionPanel = ({
  sessionId,
  onInitiate,
  onFinalize,
  onChangeSessionId,
}) => {
  return (
    <Paper
      sx={{
        p: 3,
        mb: 3,
        borderRadius: 2,
        boxShadow: 3,
        backgroundColor: '#ffffff',
      }}
    >
      <Typography variant="h6" gutterBottom>
        Session Management
      </Typography>
      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        spacing={2}
        alignItems="flex-end"
      >
        <TextField
          label="Session ID"
          value={sessionId}
          onChange={(e) => onChangeSessionId(e.target.value)}
          placeholder="Session ID will appear here"
          fullWidth
        />
        <Button variant="contained" color="primary" onClick={onInitiate}>
          Initiate
        </Button>
        <Button
          variant="contained"
          color="success"
          onClick={onFinalize}
          disabled={!sessionId}
        >
          Finalize
        </Button>
      </Stack>
    </Paper>
  );
};

export default SessionPanel;