

import React from 'react'; 
import './Home.css'; // Ensure you have your CSS file properly set up

function Home() {
    return (
        <div className="home">
            {/* Hero Section */}
            <div className="hero-section">
                <h1>Welcome to LiveTrip!</h1>
                <p>Your ultimate travel companion for discovering the world's best destinations.</p>
                <button className="btn btn-primary">Get Started</button>
            </div>

            {/* Featured Destinations Section */}
            <section className="featured-destinations">
                <h2>Featured Destinations</h2>
                <div className="destination-cards">
                    <div className="card">
                        <img src="/img/destination1.jpg" alt="Bali, Indonesia" />
                        <h3>Bali, Indonesia</h3>
                        <p>Experience the serene beauty of Bali's beaches and temples.</p>
                    </div>
                    <div className="card">
                        <img src="/img/destination2.jpg" alt="Tokyo, Japan" />
                        <h3>Tokyo, Japan</h3>
                        <p>Immerse yourself in Tokyo's vibrant culture and technology.</p>
                    </div>
                    <div className="card">
                        <img src="/img/destination3.jpg" alt="Paris, France" />
                        <h3>Paris, France</h3>
                        <p>Explore the romantic city of Paris with its iconic landmarks.</p>
                    </div>
                </div>
            </section>

            {/* Call to Action Section */}
            <section className="call-to-action">
                <h2>Start Your Adventure Today</h2>
                <p>Join us and explore the world's most exciting destinations. Share your experiences and make new memories.</p>
                <button className="btn btn-primary">Explore Now</button>
            </section>

            {/* Testimonials Section */}
            <section className="testimonials">
                <h2>What Our Users Say</h2>
                <div className="testimonial-cards">
                    <div className="testimonial-card">
                        <p>"LiveTrip made planning my vacation a breeze! The recommendations were spot on."</p>
                        <h4>Jane Doe</h4>
                    </div>
                    <div className="testimonial-card">
                        <p>"I love how easy it is to find great travel destinations. Thanks, LiveTrip!"</p>
                        <h4>John Smith</h4>
                    </div>
                </div>
            </section>
        </div>
    );
}

export default Home;













