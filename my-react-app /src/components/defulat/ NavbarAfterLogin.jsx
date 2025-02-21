import React from "react";
import { FiSearch, FiBell, FiHelpCircle, FiSettings } from "react-icons/fi";
import { MdLanguage, MdPlaylistPlay } from "react-icons/md";
import "../../styles/private/PrivteNavbar.css";

const NavbarAfterLogin = () => {
  return (
<nav className="navbar-container-main">
  {/* Left Section */}
  <div className="navbar-left">
    <div className="logo">
      <span>YOURFLIX</span>
    </div>

    <div className="nav-links-main">
      <a href="/home" className="active-main nav-links-main">Home</a>
      <a href="#" className="">Shows</a>
      <a href="/trailers">Upcoming</a>
      <a href="/news">News</a>
    </div>
  </div>

  {/* Right Section */}
  <div className="navbar-right-main">
    <div className="search-container">
      <FiSearch className="search-icon" />
      <input type="text" placeholder="Search movies, shows..." />
    </div>

    <div className="nav-icons">
      <button className="icon-btn"><MdPlaylistPlay /> Watchlist</button>

      <div className="profile-dropdown">
        <img src="profile-icon.png" alt="Profile" />
        <div className="dropdown-content">
          <a href="/settings"><FiSettings /> Settings</a>
          <a href="/create-list">Create List</a>
          <a href="/logout">Log Out</a>
        </div>
      </div>
    </div>
  </div>
</nav>

  );
};

export default NavbarAfterLogin;


