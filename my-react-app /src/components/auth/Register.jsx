import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useRegisterUserMutation } from "../../services/UserAuthApi";
// import { storeToken } from "../../services/LocalStorageService";
import logo1 from "../../assets/netflix-icon.png";
import logo2 from "../../assets/google-logo.png";
import { Link } from "react-router-dom";
import "../../styles/componentscss/NetflixClone.css";

function Register() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [tc, setTc] = useState(false);
  const [serverError, setServerError] = useState(null);
  const [registerUser, { isLoading }] = useRegisterUserMutation();

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password.length < 6) {
      setServerError({ password: "Password must be at least 6 characters long" });
      return;
    }

    try {
      const res = await registerUser({ email, password, tc });

      if (res.error) {
        setServerError({ general: res.error?.data?.error || "Registration failed." });
      } else {
        navigate("/OtpUser");
      }
    } catch (error) {
      setServerError({ general: "Something went wrong. Please try again." });
    }
  };

  return (
    <div className="home">
      <div className="hero-section text-center text-white d-flex justify-content-center align-items-center">
        <div className="auth-container">
          <h1 className="auth-form-title">Register</h1>
          <form className="auth-form" onSubmit={handleSubmit}>
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
            {serverError?.email && (
              <p className="error-text">{serverError.email}</p>
            )}

            <input
              type="password"
              placeholder="Password "
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
            />
            {serverError?.password && (
              <p className="error-text">{serverError.password}</p>
            )}

            <div className="aggrement-container">
              <div className="cheak-box-css">
                <input
                  type="checkbox"
                  checked={tc}
                  onChange={(e) => setTc(e.target.checked)}
                  required
                />
              </div>
              <div>
                <span>I agree to the terms and conditions</span>
              </div>
            </div>

            <button type="submit" className="btn-signin" disabled={isLoading}>
              {isLoading ? "Processing..." : "Continue"}
            </button>
          </form>

          {serverError?.general && (
            <div className="error-message">{serverError.general}</div>
          )}

          <div className="social-login">
            <button className="btn-social google-btn">
              <img src={logo2} alt="Google" />
              Sign up with Google
            </button>
            <button className="btn-social netflix-btn">
              <img src={logo1} alt="Netflix" />
              Sign up with Netflix
            </button>
          </div>

          <div className="form-signup">
            <span>Already have an account? </span>
            <Link to="/login">Sign in now</Link>.
          </div>
        </div>
      </div>
    </div>
  );
}

export default Register;
