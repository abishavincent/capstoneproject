import React, { useState } from 'react';
import './Signin.css';
import { useNavigate } from 'react-router-dom';

function Signin({ setIsLoggedIn }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState('');
  const [successMessage, setSuccessMessage] = useState('');

  const navigate = useNavigate();

  // Handle user registration
  const handleRegister = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    
    if (!username || !password) {
      setErrorMessage('Please fill in all fields.');
      return;
    }

    try {
      const response = await fetch('https://capstoneproject-zr13.onrender.com/api/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const data = await response.json();
        setErrorMessage(data.message || 'Registration failed.');
        return;
      }

      setSuccessMessage('Registration successful. Please sign in.');
      setUsername('');
      setPassword('');
    } catch (error) {
      console.error('Error during registration:', error);
      setErrorMessage('Something went wrong. Please try again.');
    }
  };

  // Handle user sign-in
  const handleSignIn = async (e) => {
    e.preventDefault();
    setErrorMessage('');
    setSuccessMessage('');
    
    if (!username || !password) {
      setErrorMessage('Please fill in all fields.');
      return;
    }

    try {
      const response = await fetch('https://capstoneproject-zr13.onrender.com/api/signin', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const data = await response.json();
        setErrorMessage(data.message || 'Login failed.');
        return;
      }

      const data = await response.json();
      localStorage.setItem('token', data.token);
      setSuccessMessage('Login successful!');
      
      // Update login state in the parent component (App)
      setIsLoggedIn(true);

      setTimeout(() => {
        navigate('/'); // Redirect to the home page after successful login
      }, 2000);

    } catch (error) {
      console.error('Error during sign in:', error);
      setErrorMessage('Something went wrong. Please try again.');
    }
  };

  return (
    <div className="signin-container">
      <h2>Sign In / Register</h2>
      {errorMessage && <div className="alert alert-danger">{errorMessage}</div>}
      {successMessage && <div className="alert alert-success">{successMessage}</div>}
      <form>
        <div className="form-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            className="form-control"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            required
          />
        </div>
        <div className="form-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            className="form-control"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            required
          />
        </div>
        <button type="button" onClick={handleRegister} className="btn btn-primary">
          Register
        </button>
        <button type="button" onClick={handleSignIn} className="btn btn-secondary">
          Sign In
        </button>
      </form>
    </div>
  );
}

export default Signin;
