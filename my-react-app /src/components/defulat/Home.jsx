import React from "react";
import "bootstrap/dist/css/bootstrap.min.css";
import "../../styles/componentscss/Home.css";

function Home() {
  return (
    <div className="home">
      <div className="hero-section text-center text-white d-flex justify-content-center align-items-center">
        <div>
          <h1 className="hero-title">Welcome to YOURFLIX</h1>
          <p className="hero-subtitle">
            Stream your favorite movies and TV shows anytime, anywhere.
          </p>
          <form className="search-form">
            <div className="search-container">
              <input
                type="text"
                className="search-input"
                placeholder="Search for movies, TV shows..."
              />
              <button type="submit" className="search-button">
                Search
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}

export default Home;
