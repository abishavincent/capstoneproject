import React from 'react';
import './BlogPosts.css'; // Import your custom styles
import 'bootstrap/dist/css/bootstrap.min.css';

const blogPosts = [
  {
    imgSrc: 'https://drive.google.com/file/d/1xZcEYXa-Ggm4lXbB2mCRBNsETMPeDly1/view?usp=drive_link',
    title: 'Trip to Indonesia',
    description: 'Discover the lush landscapes and vibrant culture of Indonesia, a paradise for every traveler.',
  },
  {
    imgSrc: require('../img/post2.jpg'),
    title: 'Exploring Malaysia',
    description:  'Embark on an unforgettable journey through Malaysias rich heritage, diverse wildlife, and stunning landscapes.' },
  {
    imgSrc: require('../img/post3.jpg'),
    title: 'Discovering Australia',
    description: 'Discover the breathtaking beauty of Australia, from its iconic landmarks to its vibrant wildlife and pristine beaches.'
  },
  {
    imgSrc: require('../img/post4.jpg'),
    title: 'Adventure in Thailand',
    description: 'Embark on an unforgettable adventure in Thailand, where vibrant culture meets stunning landscapes and exotic flavors.',
  },
];

function BlogPosts() {
  return (
    <div id="BlogCarousel" className="carousel slide vh-100" data-bs-ride="carousel">
      <div className="carousel-inner vh-100">
        {blogPosts.map((post, index) => (
          <div key={index} className={`carousel-item vh-100 ${index === 0 ? 'active' : ''}`}>
            <img src={post.imgSrc} className="d-block w-100 h-100" alt={post.title} />
            <div className="carousel-caption d-none d-md-block">
              <h5>{post.title}</h5>
              <p>{post.description}</p>
            </div>
          </div>
        ))}
      </div>
      <button className="carousel-control-prev" type="button" data-bs-target="#BlogCarousel" data-bs-slide="prev">
        <span className="carousel-control-prev-icon" aria-hidden="true"></span>
        <span className="visually-hidden">Previous</span>
      </button>
      <button className="carousel-control-next" type="button" data-bs-target="#BlogCarousel" data-bs-slide="next">
        <span className="carousel-control-next-icon" aria-hidden="true"></span>
        <span className="visually-hidden">Next</span>
      </button>
    </div>
  );
}

export default BlogPosts;
