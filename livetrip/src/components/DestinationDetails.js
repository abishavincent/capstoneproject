import React from 'react';
import { useParams } from 'react-router-dom';

const destinations = [
  { name: 'Indonesia', description: 'Beautiful beaches and rich culture.', details: 'Detailed info about Indonesia.' },
  { name: 'Malaysia', description: 'A vibrant city with diverse culture.', details: 'Detailed info about Malaysia.' },
  // Add more destinations
];

function DestinationDetail() {
  const { name } = useParams();
  const destination = destinations.find(dest => dest.name === name);

  return (
    <div>
      <h2>{destination?.name}</h2>
      <p>{destination?.details}</p>
      <button>Book Now</button>
    </div>
  );
}

export default DestinationDetail;
