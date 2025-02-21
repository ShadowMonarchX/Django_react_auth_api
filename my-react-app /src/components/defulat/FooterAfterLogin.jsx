import React from "react";
import { Link } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";
import "../../styles/componentscss/Footer.css";

function FooterAfterLogin() {
  return (
    <footer className="footer bg-dark text-white mt-5">
      <div className="container py-5">
        <div className="row">
          <div className="col-12 col-md-6 col-lg-3 mb-4">
            <h5>
              Questions? Call{" "}
              <Link to="tel:000-800-919-1694">000-800-919-1694</Link>
            </h5>
          </div>
          <div className="col-12 col-md-6 col-lg-3 mb-4">
            <ul className="list-unstyled">
              <li>
                <Link to="/faq">FAQ</Link>
              </li>
              <li>
                <Link to="/help-center">Help Center</Link>
              </li>
              <li>
                <Link to="/account">Account</Link>
              </li>
              <li>
                <Link to="/media-center">Media Center</Link>
              </li>
            </ul>
          </div>
          <div className="col-12 col-md-6 col-lg-3 mb-4">
            <ul className="list-unstyled">
              <li>
                <Link to="/investor-relations">Investor Relations</Link>
              </li>
              <li>
                <Link to="/jobs">Jobs</Link>
              </li>
              <li>
                <Link to="/ways-to-watch">Ways to Watch</Link>
              </li>
              <li>
                <Link to="/terms-of-use">Terms of Use</Link>
              </li>
            </ul>
          </div>
          <div className="col-12 col-md-6 col-lg-3 mb-4">
            <ul className="list-unstyled">
              <li>
                <Link to="/privacy">Privacy</Link>
              </li>
              <li>
                <Link to="/cookie-preferences">Cookie Preferences</Link>
              </li>
              <li>
                <Link to="/corporate-information">Corporate Information</Link>
              </li>
              <li>
                <Link to="/contact-us">Contact Us</Link>
              </li>
            </ul>
          </div>
        </div>
        <div className="row">
          <div className="col-12 text-center">
            <select className="form-select bg-dark text-white d-inline-block w-auto">
              <option value="en">English</option>
              <option value="es">Español</option>
              <option value="fr">Français</option>
              <option value="de">Deutsch</option>
            </select>
          </div>
        </div>
        <div className="row mt-4">
          <div className="col-12 text-center">
            <p>
              &copy; 2025 YOURFLIX Media & Entertainment. All rights reserved.
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default FooterAfterLogin;
