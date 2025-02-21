import { Navigate, Outlet } from "react-router-dom";
import { getToken } from "./services/LocalStorageService";
import NavbarAfterLogin from"./components/defulat/ NavbarAfterLogin";
import FooterAfterLogin from "./components/defulat/FooterAfterLogin";
import Footer from "./components/defulat/Footer";
import Navbar from "./components/defulat/Navbar";
import React from "react";



const RouteHandler = () => {
  const token = getToken();
  let navbar 
  let footer
  if(token){
    navbar = <NavbarAfterLogin /> ;
    footer = <FooterAfterLogin/>;
  }
  else{
    navbar = <Navbar />;
    footer =  <Footer />;
  }
  

  return (
    <div>
      {navbar}
      <Outlet />
      {footer}
    </div>
  );
};

// Make sure you're exporting it as default
export default RouteHandler;
