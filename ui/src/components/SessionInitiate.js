import React, { useState } from 'react';
import { initiateSession } from '../services/api';

const SessionInitiate = ({ onSessionInitiated }) => {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [sessionData, setSessionData] = useState(null);

  const handleInitiateSession = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await initiateSession();
      setSessionData(data);
      onSessionInitiated(data);
    } catch (err) {
      setError('Failed to initiate session');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>Initiate Session</h2>
      <button onClick={handleInitiateSession} disabled={loading}>
        {loading ? 'Loading...' : 'Start Session'}
      </button>

      {error && <p className="error">{error}</p>}

      {sessionData && (
        <div className="session-info">
          <h3>Session Details</h3>
          <p><strong>Session ID:</strong> {sessionData.session_id}</p>
          <p><strong>Kyber Public Key:</strong> {sessionData.kyberPublicKey}</p>
          <p><strong>ECDHE Public Key:</strong> {sessionData.ecdhePublicKey}</p>
          <p><strong>Symmetric Key:</strong> {sessionData.shared_symmetric_key}</p>
        </div>
      )}
    </div>
  );
};

export default SessionInitiate;