import React from 'react';
import DataUpload from './components/DataUpload';
import './styles/global.css';

const App = () => {
  return (
    <div className="app">
      <h1>Secure Data Upload and Retrieval</h1>
      <DataUpload />
    </div>
  );
};

export default App;