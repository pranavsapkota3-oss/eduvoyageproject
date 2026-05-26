import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";

export default function Login() {
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [mode, setMode] = useState("login"); // login | forgot | reset
  const [status, setStatus] = useState("");
  const [loading, setLoading] = useState(false);

  const authIntro = {
    login: {
      eyebrow: "Welcome back",
      title: "Login to EduVoyage",
      text: "Continue with your profile, scholarships, documents, and expense planning from one place.",
    },
    forgot: {
      eyebrow: "Account recovery",
      title: "Send reset code",
      text: "Enter the email you used for EduVoyage and we will send a verification code.",
    },
    reset: {
      eyebrow: "Reset password",
      title: "Create a new password",
      text: "Use the code from your email, then set a new password to regain access.",
    },
  };

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      setLoading(true);

      const res = await fetch("http://localhost:5000/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email,
          password,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        setStatus(data.message || "Login failed");
        return;
      }

      // ✅ Save token + user
      localStorage.setItem("token", data.token);
      localStorage.setItem("user", JSON.stringify(data.user));

      setStatus("Login successful!");
      if (data.user?.role === "agent" || data.user?.role === "admin") {
        navigate("/agent");
      } else {
        navigate("/");
      }
    } catch (err) {
      console.error(err);
      setStatus("Network error. Is backend running on http://localhost:5000 ?");
    } finally {
      setLoading(false);
    }
  };

  const handleSendReset = async (e) => {
    e.preventDefault();
    try {
      setLoading(true);
      const res = await fetch("http://localhost:5000/api/auth/forgot-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus(data.message || "Failed to send reset code");
        return;
      }
      setStatus(data.message || "Reset code sent to your email.");
      setMode("reset");
    } catch (err) {
      console.error(err);
      setStatus("Failed to send reset code.");
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    if (newPassword !== confirmNewPassword) {
      setStatus("Passwords do not match.");
      return;
    }

    try {
      setLoading(true);
      const res = await fetch("http://localhost:5000/api/auth/reset-password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, otp, new_password: newPassword }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus(data.message || "Reset failed");
        return;
      }
      setStatus(data.message || "Password updated.");
      setMode("login");
      setPassword("");
      setOtp("");
      setNewPassword("");
      setConfirmNewPassword("");
    } catch (err) {
      console.error(err);
      setStatus("Reset failed.");
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
          <h2>Welcome Back</h2>
          <p>Your journey continues here</p>
        </div>
      </div>

      <div className="auth-form-container">
        <Link to="/" className="back-button">
          ← Back to Home
        </Link>

        <div className="auth-card">
          <div className="auth-header">
            <span className="auth-eyebrow">{authIntro[mode].eyebrow}</span>
            <h1>{authIntro[mode].title}</h1>
            <p>{authIntro[mode].text}</p>
          </div>

          <form
            className="auth-form"
            onSubmit={mode === "login" ? handleLogin : mode === "forgot" ? handleSendReset : handleResetPassword}
          >
            <div className="form-group">
              <label>Email Address</label>
              <input
                type="email"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={mode === "reset"}
              />
            </div>

            {mode === "login" && (
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </div>
            )}

            {mode === "reset" && (
              <>
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
                <div className="form-group">
                  <label>New Password</label>
                  <input
                    type="password"
                    placeholder="Enter new password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                  />
                </div>
                <div className="form-group">
                  <label>Confirm New Password</label>
                  <input
                    type="password"
                    placeholder="Confirm new password"
                    value={confirmNewPassword}
                    onChange={(e) => setConfirmNewPassword(e.target.value)}
                    required
                  />
                </div>
              </>
            )}

            <div className="auth-actions">
              <button type="submit" className="btn-gradient" disabled={loading}>
                {mode === "login"
                  ? loading ? "Logging in..." : "Login"
                  : mode === "forgot"
                  ? loading ? "Sending..." : "Send Reset Code"
                  : loading ? "Updating..." : "Reset Password"}
              </button>

              {mode === "login" && (
                <button
                  type="button"
                  className="btn-secondary auth-secondary-btn"
                  onClick={() => {
                    setMode("forgot");
                    setStatus("");
                  }}
                >
                  Forgot password?
                </button>
              )}

              {mode !== "login" && (
                <button
                  type="button"
                  className="btn-secondary auth-secondary-btn"
                  onClick={() => {
                    setMode("login");
                    setStatus("");
                  }}
                >
                  Back to login
                </button>
              )}
            </div>

            {status && <p className="auth-status">{status}</p>}
          </form>

          <p className="auth-footer">
            Don&apos;t have an account? <Link to="/signup">Sign up here</Link>
          </p>
        </div>
      </div>
    </div>
  );
}
