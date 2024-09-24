// src/components/ContactUs.js
import React from 'react';
import './ContactUs.css'; // Create and style this CSS file accordingly

function ContactUs() {
  return (
    <div className="contact-us">
      <div className="container">
        <h2>Contact Us</h2>
        <div className="contact-info">
          <p>If you have any questions, feel free to reach out to us:</p>
          <address>
            <p><strong>Email:</strong> contact@livetrip.com</p>
            <p><strong>Phone:</strong> +123 456 7890</p>
            <p><strong>Address:</strong> 123 Travel Lane, Wanderlust City, TC 45678</p>
          </address>
        </div>
        
        <form className="contact-form">
          <h3>Send us a Message</h3>
          <div className="form-group">
            <label htmlFor="name">Your Name</label>
            <input type="text" id="name" placeholder="Your Name" required />
          </div>
          <div className="form-group">
            <label htmlFor="email">Your Email</label>
            <input type="email" id="email" placeholder="Your Email" required />
          </div>
          <div className="form-group">
            <label htmlFor="message">Message</label>
            <textarea id="message" placeholder="Your Message" rows="4" required></textarea>
          </div>
          <button type="submit" className="btn btn-primary">Send Message</button>
        </form>
        
        {/* Optional: Add a map to show your location */}
        <div className="map">
          <h3>Our Location</h3>
          <iframe
            title="Location Map"
            src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3153.137151053594!2d-122.41941868468135!3d37.77492927975982!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x8085808b7b0a583b%3A0x68b7f44ae9e3e2!2sSan%20Francisco%2C%20CA%2C%20USA!5e0!3m2!1sen!2sin!4v1614387598255!5m2!1sen!2sin"
            width="600"
            height="450"
            style={{ border: 0 }}
            allowFullScreen=""
            loading="lazy"
          ></iframe>
        </div>
      </div>
    </div>
  );
}

export default ContactUs;
