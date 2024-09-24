// src/components/About.js
import React from 'react';
import './About.css'; // Create and style this CSS file accordingly

function About() {
  return (
    <div className="about">
      <div className="container">
        <h2>About Us</h2>
        <p>Welcome to LiveTrip! We are dedicated to providing you with the best travel experiences and insights. Whether you're looking for your next vacation destination or just some travel inspiration, we've got you covered.</p>
        
        <h3>Our Mission</h3>
        <p>Our mission is to make travel planning easy and enjoyable. We strive to offer a comprehensive platform where travelers can find the best destinations, share their travel stories, and get tips from fellow adventurers.</p>

        <h3>Meet the Team</h3>
        <p>Our team is passionate about travel and committed to helping you make the most of your trips. We come from diverse backgrounds and bring a wealth of experience in travel, technology, and customer service.</p>

        <h3>Contact Us</h3>
        <p>If you have any questions or feedback, feel free to reach out to us through our <a href="/contact">Contact Us</a> page.</p>
      </div>
    </div>
  );
}

export default About;
