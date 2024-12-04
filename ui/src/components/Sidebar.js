// Sidebar.js
import React from 'react';
import {
  Drawer,
  Box,
  Typography,
  List,
  ListItem,
  ListItemText,
  Divider,
  Button,
  Stack,
} from '@mui/material';

const Sidebar = ({ adminRecords, onSelectRecord, onRefresh, drawerWidth }) => {
  return (
    <Drawer
      anchor="left"
      variant="permanent"
      sx={{
        width: drawerWidth,
        flexShrink: 0,
        [`& .MuiDrawer-paper`]: {
          width: drawerWidth,
          boxSizing: 'border-box',
          borderRight: '1px solid #ccc',
          p: 2,
          backgroundColor: '#ffffff',
        },
      }}
    >
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
        }}
      >
        <Typography variant="h6" sx={{ mb: 1, textAlign: 'center' }}>
          All Uploaded Data
        </Typography>
        <Stack direction="row" spacing={1} mb={2} justifyContent="center">
          <Button variant="outlined" size="small" onClick={onRefresh}>
            Refresh
          </Button>
        </Stack>
        <Divider sx={{ mb: 2 }} />
        <Box sx={{ flexGrow: 1, overflowY: 'auto' }}>
          {adminRecords.length === 0 ? (
            <Typography
              variant="body2"
              color="text.secondary"
              sx={{ textAlign: 'center' }}
            >
              No data found.
            </Typography>
          ) : (
            <List dense>
              {adminRecords.map((r) => (
                <ListItem
                  button
                  key={r.recordId}
                  onClick={() => onSelectRecord(r.recordId)}
                >
                  <ListItemText
                    primary={`Record: ${r.recordId}`}
                    secondary={
                      <>
                        Session: {r.sessionId}
                        <br />
                        Uploaded: {new Date(r.uploaded_at).toLocaleString()}
                      </>
                    }
                  />
                </ListItem>
              ))}
            </List>
          )}
        </Box>
      </Box>
    </Drawer>
  );
};

export default Sidebar;