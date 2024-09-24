
// src/components/Destinations.js
import React from 'react';
import './Destinations.css'; // Optional, you can style this separately

function Destinations() {
  const destinations = ['Indonesia', 'Malaysia', 'Australia', 'Thailand'];

  return (
    <div className="destinations-page">
      <h2 className="page-heading">Explore Our Destinations</h2>
      <div className="destination-grid">
        {destinations.map((destination, index) => (
          <div key={index} className="destination-card">
            <img
              src={require(`../img/img${index + 3}.jpg`)} // Adjust the image paths as needed
              alt={destination}
              className="destination-image"
            />
            <h3>{destination}</h3>
          </div>
        ))}
      </div>
    </div>
  );
}

export default Destinations;

