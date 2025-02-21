import { useState, useEffect } from "react";
import { Link, useParams, useNavigate } from "react-router-dom";
import {
  useResetPasswordMutation,
  useValidateResetTokenQuery,
} from "../../services/UserAuthApi";
import { toast } from "react-toastify";

const ResetPassword = () => {
  const { uidb64, token } = useParams();
  const navigate = useNavigate();
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [isValid, setIsValid] = useState(false);

  const [resetPassword, { isLoading }] = useResetPasswordMutation();
//   console.log("token :", token);
//   console.log("uidb64 :", uidb64);
  const { data, error } = useValidateResetTokenQuery({ uidb64, token });
  useEffect(() => {
    const validateToken = async () => {
      try {
        if (error) {
          toast.error("Invalid or expired reset link");
          navigate("/forget-password");
        } else if (data) {
          setIsValid(true);
        }
      } catch (error) {
        console.log(error);
        toast.error("Something went wrong!");
        navigate("/forget-password");
      }
    };

    validateToken();
  }, [uidb64, token, navigate, data, error]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (password !== confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }

    try {
      const response = await resetPassword({
        password,
        confirmPassword,
        uidb64,
        token,
      }).unwrap();
      toast.success("Password reset successful! Please login.");
      navigate("/login");
    } catch (error) {
      toast.error(error?.data?.message || "Failed to reset password");
    }
  };

  return (
    <div className="home">
      <div className="hero-section text-center text-white d-flex justify-content-center align-items-center">
        <div className="auth-container">
          <h1 className="auth-form-title">New Password</h1>
          {isValid ? (
            <form className="auth-form" onSubmit={handleSubmit}>
              <input
                type="password"
                placeholder="New Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="new-password"
              />

              <input
                type="password"
                placeholder="Confirm Password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                autoComplete="new-password"
              />

              <button type="submit" className="btn-signin" disabled={isLoading}>
                {isLoading ? "Processing..." : "Set Password"}
              </button>
            </form>
          ) : (
            <p className="error-text">Invalid or expired reset link</p>
          )}

          <div className="form-signup">
            <Link to="/login" className="back-signin">
              Back to Sign In
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ResetPassword;
