import { useNavigate } from "react-router-dom";
// import { jwt_decode } from "jwt-decode";


// Store token in localStorage
const storeToken = (token) => {
  if (!token?.data?.access_token || !token?.data?.refresh_token) {
    console.error("Invalid token data received:", token);
    return;
  }

  console.log("Storing token:", token.data.access_token);
  localStorage.setItem("access_token", token.data.access_token);
  localStorage.setItem("refresh_token", token.data.refresh_token);
};

// Retrieve token from localStorage
const getToken = () => {
  const access_token = localStorage.getItem("access_token");
  const refresh_token = localStorage.getItem("refresh_token");

  if (
    !access_token ||
    access_token === "undefined" ||
    access_token === "null"
  ) {
    console.warn("Access token is invalid");
    removeToken();
    return null;
  }

  if (
    !refresh_token ||
    refresh_token === "undefined" ||
    refresh_token === "null"
  ) {
    console.warn("Refresh token is invalid");
    removeToken();
    return null;
  }

  return { access_token, refresh_token };
};

// Remove token from localStorage
const removeToken = () => {
  localStorage.removeItem("access_token");
  localStorage.removeItem("refresh_token");
};

// Check if the token is expired using jwt_decode
const isTokenExpired = (token) => {
  if (!token) return true;
  try {
    const decodedToken = jwt_decode(token);
    return decodedToken.exp * 1000 < Date.now(); // Check if token is expired
  } catch (error) {
    console.error("Invalid token format:", error);
    return true;
  }
};

// Check token expiration and redirect to login if expired
const checkTokenExpiration = () => {
  const navigate = useNavigate();
  const { access_token } = getToken() || {};

  if (!access_token || isTokenExpired(access_token)) {
    console.error("Access token is expired. Redirecting to login.");
    removeToken();
    navigate("/login");
  }
};



export {
  storeToken,
  getToken,
  removeToken,
  isTokenExpired,
  checkTokenExpiration,
};
