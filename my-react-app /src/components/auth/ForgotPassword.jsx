import { useState } from "react";
import { Link } from "react-router-dom";
import { useDispatch } from "react-redux";
import { toast } from "react-toastify";
import { useForgotPasswordMutation } from "../../services/UserAuthApi";
import "../../styles/componentscss/NetflixClone.css";
function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [forgotPassword, { isLoading }] = useForgotPasswordMutation();
  const dispatch = useDispatch();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await forgotPassword({ email }).unwrap();
      toast.success(response.message);
    } catch (error) {
      toast.error(error.data?.message || "Something went wrong");
    }
  };

  return (
    <div className="home">
      <div className="hero-section text-center text-white d-flex justify-content-center align-items-center">
        <div className="auth-container">
          <h1 className="auth-form-title">Forgot Password</h1>
          <form className="auth-form" onSubmit={handleSubmit}>
            <input
              type="email"
              placeholder="Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
            />
            <button type="submit" className="reset-btn" disabled={isLoading}>
              {isLoading ? "Processing..." : "Reset Password"}
            </button>
          </form>
          <div className="form-signup">
            <Link to="/login" className="back-signin">
              Back to Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ForgotPassword;
