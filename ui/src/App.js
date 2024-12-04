// App.js
import React, { useEffect, useState } from 'react';
import { Box, CssBaseline } from '@mui/material';
import './index.css';
import {
  initiateSession,
  finalizeSession,
  uploadData,
  retrieveData,
  getAllData,
} from './services/api';
import SessionPanel from './components/SessionPanel';
import DataPanel from './components/DataPanel';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import DebugPanel from './components/DebugPanel';

const drawerWidth = 300;

function App() {
  const [sessionId, setSessionId] = useState('');
  const [records, setRecords] = useState([]);
  const [adminRecords, setAdminRecords] = useState([]);
  const [logs, setLogs] = useState([]);

  const addLog = (method, endpoint, requestData, responseData) => {
    setLogs((prev) => [
      ...prev,
      { method, endpoint, requestData, responseData },
    ]);
  };

  const fetchAdminData = async () => {
    try {
      const data = await getAllData();
      addLog('GET', '/data/all', {}, data);
      setAdminRecords(data);
    } catch (e) {
      console.error('Failed to fetch all data:', e);
    }
  };

  useEffect(() => {
    fetchAdminData();
  }, []);

  const handleInitiate = async () => {
    try {
      const data = await initiateSession();
      addLog('POST', '/session/initiate', {}, data);
      setSessionId(data.session_id);
      alert(`Session initiated: ${data.session_id}`);
    } catch (e) {
      console.error(e);
      alert('Failed to initiate session');
    }
  };

  const handleFinalize = async () => {
    if (!sessionId) return;
    try {
      const data = await finalizeSession(sessionId);
      addLog('POST', '/session/finalize', { sessionId }, data);
      alert('Session finalized successfully!');
    } catch (e) {
      console.error(e);
      alert('Failed to finalize session');
    }
  };

  const handleUpload = async (plaintext) => {
    try {
      const data = await uploadData(sessionId, plaintext);
      addLog('POST', '/data/upload', { sessionId, plaintext }, data);
      const newRecord = { recordId: data.recordId, plaintext: null };
      setRecords((prev) => [...prev, newRecord]);
      setAdminRecords((prev) => [
        ...prev,
        {
          recordId: data.recordId,
          sessionId,
          uploaded_at: new Date().toISOString(),
        },
      ]);
    } catch (e) {
      console.error(e);
      alert('Failed to upload data');
    }
  };

  const handleRetrieve = async (recordId) => {
    try {
      const data = await retrieveData(sessionId, recordId);
      addLog('POST', '/data/retrieve', { sessionId, recordId }, data);
      setRecords((prev) =>
        prev.map((r) =>
          r.recordId === recordId ? { ...r, plaintext: data.plaintext } : r
        )
      );
    } catch (e) {
      console.error(e);
      alert('Failed to retrieve data');
    }
  };

  const handleAdminSelectRecord = async (recordId) => {
    if (!sessionId) {
      alert(
        'Set or create a session ID and finalize it first before retrieving data from these records.'
      );
      return;
    }
    try {
      const data = await retrieveData(sessionId, recordId);
      addLog('POST', '/data/retrieve', { sessionId, recordId }, data);
      alert(`Record ${recordId} plaintext: ${data.plaintext}`);
    } catch (e) {
      console.error(e);
      alert(
        'Failed to retrieve data (maybe session is not correct or not finalized)'
      );
    }
  };

  return (
    <Box sx={{ display: 'flex', height: '100vh', bgcolor: '#f5f5f5' }}>
      <CssBaseline />
      <Sidebar
        adminRecords={adminRecords}
        onSelectRecord={handleAdminSelectRecord}
        onRefresh={fetchAdminData}
        drawerWidth={drawerWidth}
      />
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          ml: `${drawerWidth}px`,
          display: 'flex',
          flexDirection: 'column',
          height: '100vh',
          overflow: 'hidden',
        }}
      >
        <Header />
        <Box
          sx={{
            flexGrow: 1,
            display: 'flex',
            flexDirection: 'row',
            padding: 2,
            overflow: 'hidden',
          }}
        >
          <Box
            sx={{
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              overflowY: 'auto',
              paddingRight: 1,
            }}
          >
            <SessionPanel
              sessionId={sessionId}
              onInitiate={handleInitiate}
              onFinalize={handleFinalize}
              onChangeSessionId={setSessionId}
            />
            <DataPanel
              sessionId={sessionId}
              records={records}
              onUpload={handleUpload}
              onRetrieve={handleRetrieve}
            />
            <DebugPanel logs={logs} />
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

export default App;