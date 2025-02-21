import { useState, useEffect } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useDispatch } from "react-redux";
import logo1 from "../../assets/netflix-icon.png"; 
import logo2 from "../../assets/google-logo.png";
import { getToken, storeToken } from "../../services/LocalStorageService";
import { useLoginUserMutation } from "../../services/UserAuthApi";
import { setUserToken } from "../../app/features/authSlice"; 
import "../../styles/componentscss/NetflixClone.css";

function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [serverError, setServerError] = useState({});
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const [loginUser, { isLoading }] = useLoginUserMutation();

  // Check for stored token on page load
  useEffect(() => {
    const tokenData = getToken();
    if (tokenData && tokenData.access_token) {
      dispatch(setUserToken({ access_token: tokenData.access_token }));
      navigate("/Dashboard");
    }
  }, [dispatch, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setServerError({}); // Reset previous errors

    const user = { email, password };
    console.log(user)

    try {
      const res = await loginUser(user);


      if (res.error) {
        console.error("Login Error:", res.error);
        setServerError(res.error.data?.errors || { general: "Login failed" });
      } else if (res.data) {
        if (!res.data.is_verified) {
          navigate("/OtpUser");
          return;
        }

        
        storeToken({
          access_token: res.data.access_token,
          refresh_token: res.data.refresh_token,
        });
        dispatch(setUserToken({ access_token: res.data.access_token }));
        navigate("/Dashboard");
      }
    } catch (error) {
      console.error("Login Error:", error);
      setServerError({ general: "Something went wrong. Try again." });
    }
  };

  return (
    <div className="home">
      <div className="hero-section text-center text-white d-flex justify-content-center align-items-center">
        <div className="auth-container">
          <h1 className="auth-form-title">Sign In</h1>

          <form className="auth-form" onSubmit={handleSubmit}>
            <input
              type="email"
              placeholder="Email or phone number"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            {serverError.email && <span className="error">{serverError.email}</span>}
            
            <input
              type="password"
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            {serverError.password && <span className="error">{serverError.password}</span>}

            <button type="submit" className="btn-signin" disabled={isLoading}>
              {isLoading ? "Signing In..." : "Sign In"}
            </button>

            {serverError.general && <span className="error">{serverError.general}</span>}

            <div className="social-login">
              <button className="btn-social google-btn">
                <img src={logo2} alt="Google" />
                Sign in with Google
              </button>
              <button className="btn-social netflix-btn">
                <img src={logo1} alt="Netflix" />
                Sign in with Netflix
              </button>
            </div>

            <div className="form-help">
              <div className="aggrement-container">
                <div className="agrement-checkbox">
                  <input className="margin-bt0" type="checkbox" name="tc" />
                </div>
                <div>Remember me</div>
              </div>
            </div>
            <Link to="/forget-password">Need help?</Link>
          </form>

          <div className="form-signup">
            <span>New to YourFlix? </span>
            <Link to="/register">Sign up now</Link>.
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;
