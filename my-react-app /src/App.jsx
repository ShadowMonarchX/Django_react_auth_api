import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
// import { Navigate } from "react-router-dom";

import Home from "./components/defulat/Home";
import "bootstrap/dist/css/bootstrap.min.css";
import "./styles/componentscss/App.css";
import Login from "./components/auth/Login";
import Register from "./components/auth/Register";
import OtpUser from "./components/auth/OtpUser";
import AdditionalUser from "./components/auth/AdditionalUser";
import ForgotPassword from "./components/auth/ForgotPassword";
import ResetPassword from "./components/auth/ResetPassword";
import Dashboard from "./components/defulat/Dashboard";
import RouteHandler from "./RouteHandler";  



function App() {
  return (
    <Router>
      <Routes>
        {/* RouteHandler will manage conditional Navbar and Footer rendering */}
        <Route element={<RouteHandler />}>
          <Route path="/" element={<Home />} />
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/OtpUser" element={<OtpUser />} />
          <Route path="/AdditionalUser" element={<AdditionalUser />} />
          <Route path="/forget-password" element={<ForgotPassword />} />
          <Route path="/password-reset-confirm/:uidb64/:token" element={<ResetPassword />} />
          <Route path="/Dashboard" element={<Dashboard />} />
        </Route>
      </Routes>
    </Router>
  );
}

export default App;
