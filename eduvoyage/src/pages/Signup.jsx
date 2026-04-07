import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

const API_URL = "http://localhost:5000"; // backend base URL

export default function Signup() {
  const navigate = useNavigate();

  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [step, setStep] = useState("signup");
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSignup = async (e) => {
    e.preventDefault();

    if (password !== confirmPassword) {
      alert("Passwords do not match");
      return;
    }

    try {
      setLoading(true);

      const res = await fetch(`${API_URL}/api/auth/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: name,
          email,
          password,
        }),
      });

      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        data = { message: text || "Unknown server response" };
      }

      if (!res.ok) {
        setStatus(data.message || "Signup failed");
        return;
      }

      setStatus(data.message || "OTP sent to your email. Verify to create account.");
      setStep("verify");
    } catch (err) {
      console.error("Signup request failed:", err);
      setStatus("Signup failed: cannot reach backend (check backend running + CORS)");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();

    if (!otp) {
      setStatus("Enter the verification code.");
      return;
    }

    try {
      setLoading(true);
      const res = await fetch(`${API_URL}/api/auth/verify-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otp }),
      });

      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch {
        data = { message: text || "Unknown server response" };
      }

      if (!res.ok) {
        setStatus(data.message || "Verification failed");
        return;
      }

      setStatus(data.message || "Email verified. Account created.");
      navigate("/login");
    } catch (err) {
      console.error("OTP verify request failed:", err);
      setStatus("Verification failed: cannot reach backend.");
    } finally {
      setLoading(false);
    }
  };

  const handleResendOtp = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API_URL}/api/auth/resend-otp`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });

      const data = await res.json();
      if (!res.ok) {
        setStatus(data.message || "Resend failed");
        return;
      }

      setStatus(data.message || "OTP resent.");
    } catch (err) {
      console.error("Resend OTP failed:", err);
      setStatus("Resend failed: cannot reach backend.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-page">
      <div
        className="auth-image"
        style={{
          backgroundImage:
            'url("https://images.unsplash.com/photo-1480714378408-67cf0d13bc1b?w=800&h=1200&fit=crop")',
        }}
      >
        <div className="auth-image-content">
          <h2>Explore. Apply. Succeed.</h2>
          <p>Join students worldwide and start your study journey</p>
        </div>
      </div>

      <div className="auth-form-container">
        <Link to="/" className="back-button">
          ← Back to Home
        </Link>

        <div className="auth-card">
          <div className="auth-header">
            <h1>Create Account</h1>
            <p>Sign up to access university listings</p>
          </div>

          <form onSubmit={step === "signup" ? handleSignup : handleVerifyOtp}>
            <div className="form-group">
              <label>Full Name</label>
              <input
                type="text"
                placeholder="Enter your full name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                disabled={step === "verify"}
              />
            </div>

            <div className="form-group">
              <label>Email Address</label>
              <input
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={step === "verify"}
              />
            </div>

            <div className="form-group">
              <label>Password</label>
              <input
                type="password"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={step === "verify"}
              />
            </div>

            <div className="form-group">
              <label>Confirm Password</label>
              <input
                type="password"
                placeholder="Confirm your password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                disabled={step === "verify"}
              />
            </div>

            {step === "verify" && (
              <div className="form-group">
                <label>Verification Code</label>
                <input
                  type="text"
                  placeholder="Enter the 6-digit code"
                  value={otp}
                  onChange={(e) => setOtp(e.target.value)}
                  required
                />
              </div>
            )}

            <button type="submit" className="btn-gradient" disabled={loading}>
              {step === "signup"
                ? loading ? "Creating..." : "Create Account"
                : loading ? "Verifying..." : "Verify Code"}
            </button>

            {step === "verify" && (
              <button
                type="button"
                className="btn-secondary"
                onClick={handleResendOtp}
                disabled={loading}
              >
                Resend Code
              </button>
            )}

            {status && <p className="auth-footer">{status}</p>}

            <p className="auth-footer">
              Already have an account? <Link to="/login">Login here</Link>
            </p>
          </form>
        </div>
      </div>
    </div>
  );
}
