import React from "react";
import { Link } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import "../../styles/componentscss/Navbar.css";

function Navbar({ isLoggedIn, username, handleLogout }) {
  return (
    <nav className="navbar navbar-expand-lg navbar-dark bg-darkes ">
      <div className="container-fluid">
        <Link to="/" className="navbar-brand">
          YOURFLIX
        </Link>
        <button
          className="navbar-toggler"
          type="button"
          data-bs-toggle="collapse"
          data-bs-target="#navbarNav"
          aria-controls="navbarNav"
          aria-expanded="false"
          aria-label="Toggle navigation"
        >
          <span className="navbar-toggler-icon"></span>
        </button>
        <div className="collapse navbar-collapse" id="navbarNav">
          <ul className="navbar-nav ms-auto">
            {!isLoggedIn ? (
              <>
                <li className="nav-item">
                  <Link to="/login" className="nav-link">
                    Sign In
                  </Link>
                </li>
                <li className="nav-item">
                  <Link to="/register" className="nav-link">
                    Register
                  </Link>
                </li>
              </>
            ) : (
              <li className="nav-item d-flex align-items-center">
                <span className="nav-link user-name">{username}</span>
                <button className="btn btn-danger ms-2" onClick={handleLogout}>
                  Logout
                </button>
              </li>
            )}
          </ul>
        </div>
      </div>
    </nav>
  );
}

export default Navbar;
