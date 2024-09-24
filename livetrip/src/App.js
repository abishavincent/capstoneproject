import React, { useState } from 'react';
import './App.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import { BrowserRouter as Router, Route, Routes, Link } from 'react-router-dom';
import Home from './components/Home';
import About from './components/About';
import ContactUs from './components/ContactUs';
import Destinations from './components/Destinations';
import BlogPosts from './components/BlogPosts';
import Signin from './components/Signin';

function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('token'));

  const handleSignOut = () => {
    localStorage.removeItem('token');
    setIsLoggedIn(false);
  };

  return (
    <Router>
      <div className="App">
        <header>
          <div className="navbar1">
            <div className="logo">
              <Link to="/" className="site-name">LiveTrip</Link>
            </div>
            <ul className="nav-links">
              <li><Link to="/">Home</Link></li>
              <li><Link to="/destinations">Destinations</Link></li>
              <li><Link to="/blog-posts">Blog Posts</Link></li>
              <li><Link to="/about">About</Link></li>
              <li><Link to="/contact">Contact Us</Link></li>
              <li>
                {isLoggedIn ? (
                  <button onClick={handleSignOut} className="btn btn-danger">
                    Sign Out
                  </button>
                ) : (
                  <Link to="/signin" className="btn btn-primary">
                    Sign In
                  </Link>
                )}
              </li>
            </ul>
          </div>
        </header>

        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/destinations" element={<Destinations />} />
          <Route path="/blog-posts" element={<BlogPosts />} />
          <Route path="/about" element={<About />} />
          <Route path="/contact" element={<ContactUs />} />
          <Route
            path="/signin"
            element={<Signin setIsLoggedIn={setIsLoggedIn} />}
          />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
