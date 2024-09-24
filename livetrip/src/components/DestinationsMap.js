import React from 'react';
import { MapContainer, TileLayer, Marker, Popup } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

const destinations = [
  { name: 'Indonesia', position: [ -8.4089, 114.5594 ] },
  { name: 'Malaysia', position: [ 4.2105, 101.9758 ] },
  // Add more destinations
];

function DestinationsMap() {
  return (
    <MapContainer center={[0, 0]} zoom={2} style={{ height: "500px", width: "100%" }}>
      <TileLayer
        url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
        attribution='© OpenStreetMap contributors'
      />
      {destinations.map((dest, index) => (
        <Marker key={index} position={dest.position}>
          <Popup>{dest.name}</Popup>
        </Marker>
      ))}
    </MapContainer>
  );
}

export default DestinationsMap;
