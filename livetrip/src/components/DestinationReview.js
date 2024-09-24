import React, { useState } from 'react';

function DestinationReview() {
  const [review, setReview] = useState('');
  const [rating, setRating] = useState(1);

  const handleSubmit = (e) => {
    e.preventDefault();
    // Handle review submission
    console.log('Review submitted:', review, rating);
  };

  return (
    <form onSubmit={handleSubmit}>
      <textarea
        value={review}
        onChange={(e) => setReview(e.target.value)}
        placeholder="Write your review here"
        required
      />
      <div>
        <label>Rating:</label>
        <select
          value={rating}
          onChange={(e) => setRating(Number(e.target.value))}
        >
          {[1, 2, 3, 4, 5].map((rate) => (
            <option key={rate} value={rate}>{rate}</option>
          ))}
        </select>
      </div>
      <button type="submit">Submit Review</button>
    </form>
  );
}

export default DestinationReview;
