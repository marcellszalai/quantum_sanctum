// DataPanel.js
import React, { useState } from 'react';
import {
  Paper,
  Typography,
  TextField,
  Button,
  List,
  ListItem,
  ListItemText,
  Stack,
  Divider,
} from '@mui/material';

const DataPanel = ({ sessionId, records, onUpload, onRetrieve }) => {
  const [plaintext, setPlaintext] = useState('');

  const handleUploadClick = () => {
    if (!plaintext.trim()) return;
    onUpload(plaintext.trim());
    setPlaintext('');
  };

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
        Session Data Operations
      </Typography>
      <Typography variant="body2" color="text.secondary" gutterBottom>
        Upload plaintext data to the current session and retrieve them later.
      </Typography>
      <Stack
        direction={{ xs: 'column', sm: 'row' }}
        spacing={2}
        alignItems="flex-start"
        mb={2}
      >
        <TextField
          label="Plaintext Data"
          multiline
          rows={3}
          fullWidth
          value={plaintext}
          onChange={(e) => setPlaintext(e.target.value)}
          placeholder="Enter data here..."
        />
        <Button
          variant="contained"
          color="primary"
          onClick={handleUploadClick}
          disabled={!sessionId || !plaintext.trim()}
          sx={{ height: '56px' }}
        >
          Upload
        </Button>
      </Stack>
      <Divider sx={{ mb: 2 }} />
      <Typography variant="subtitle1" gutterBottom>
        Uploaded Records for This Session
      </Typography>
      {records.length === 0 ? (
        <Typography variant="body2" color="text.secondary">
          No records uploaded yet.
        </Typography>
      ) : (
        <List>
          {records.map((r) => (
            <ListItem
              key={r.recordId}
              secondaryAction={
                !r.plaintext && (
                  <Button
                    variant="outlined"
                    color="secondary"
                    onClick={() => onRetrieve(r.recordId)}
                  >
                    Retrieve
                  </Button>
                )
              }
              sx={{ mb: 1, borderRadius: 1, backgroundColor: '#f9f9f9' }}
            >
              <ListItemText
                primary={`Record ID: ${r.recordId}`}
                secondary={
                  r.plaintext
                    ? `Plaintext: ${r.plaintext}`
                    : 'Click "Retrieve" to view plaintext'
                }
              />
            </ListItem>
          ))}
        </List>
      )}
    </Paper>
  );
};

export default DataPanel;