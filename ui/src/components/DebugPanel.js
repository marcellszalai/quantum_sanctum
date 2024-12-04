// DebugPanel.js
import React, { useState } from 'react';
import {
  Paper,
  Typography,
  IconButton,
  Collapse,
  List,
  ListItem,
  ListItemText,
  Divider,
  Stack,
} from '@mui/material';
import { ExpandMore, ExpandLess } from '@mui/icons-material';

const DebugPanel = ({ logs }) => {
  const [open, setOpen] = useState(false);

  return (
    <Paper
      sx={{
        p: 3,
        borderRadius: 2,
        boxShadow: 3,
        backgroundColor: '#ffffff',
      }}
    >
      <Stack
        direction="row"
        justifyContent="space-between"
        alignItems="center"
        mb={1}
      >
        <Typography variant="h6">Debug Information</Typography>
        <IconButton onClick={() => setOpen(!open)}>
          {open ? <ExpandLess /> : <ExpandMore />}
        </IconButton>
      </Stack>
      <Collapse in={open}>
        {logs.length === 0 ? (
          <Typography variant="body2" color="text.secondary">
            No API calls made yet.
          </Typography>
        ) : (
          <List dense>
            {logs.map((log, i) => (
              <React.Fragment key={i}>
                <ListItem alignItems="flex-start">
                  <ListItemText
                    primary={`${log.method.toUpperCase()} ${log.endpoint}`}
                    secondary={
                      <>
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          component="span"
                        >
                          Request Data:
                        </Typography>
                        <pre
                          style={{
                            fontSize: '0.8rem',
                            background: '#f0f0f0',
                            padding: '8px',
                            borderRadius: '4px',
                            overflowX: 'auto',
                          }}
                        >
                          {JSON.stringify(log.requestData, null, 2)}
                        </pre>
                        <Typography
                          variant="body2"
                          color="text.secondary"
                          sx={{ mt: 1 }}
                          component="span"
                        >
                          Response:
                        </Typography>
                        <pre
                          style={{
                            fontSize: '0.8rem',
                            background: '#f0f0f0',
                            padding: '8px',
                            borderRadius: '4px',
                            overflowX: 'auto',
                          }}
                        >
                          {JSON.stringify(log.responseData, null, 2)}
                        </pre>
                      </>
                    }
                  />
                </ListItem>
                <Divider />
              </React.Fragment>
            ))}
          </List>
        )}
      </Collapse>
    </Paper>
  );
};

export default DebugPanel;