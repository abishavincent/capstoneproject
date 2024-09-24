import React from 'react';
import ReactDOM from 'react-dom';
import './index.css'; // Optional: If you have global styles for your app
import App from './App';
import 'bootstrap/dist/css/bootstrap.min.css';

//import reportWebVitals from './reportWebVitals'; // Optional, for measuring performance

ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);

// Optional: For measuring performance
//reportWebVitals();
