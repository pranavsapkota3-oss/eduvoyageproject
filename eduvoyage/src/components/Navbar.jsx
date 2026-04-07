import { Link, useLocation, useNavigate } from "react-router-dom";
import { useState, useEffect, useRef } from "react";

export default function Navbar() {
  const navigate = useNavigate();
  const location = useLocation();
  const [open, setOpen] = useState(false);
  const [language, setLanguage] = useState(
    () => localStorage.getItem("site_language") || "EN"
  );
  const [pendingApplication, setPendingApplication] = useState(null);
  const dropdownRef = useRef(null);

  // get user from localStorage
  const user = JSON.parse(localStorage.getItem("user"));

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    navigate("/login");
  };

  useEffect(() => {
    function handleClick(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  useEffect(() => {
    localStorage.setItem("site_language", language);
  }, [language]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem("university_application_flow_v1");
      const all = raw ? JSON.parse(raw) : {};
      const pending = Object.values(all).find((item) => item?.pending_confirmation);
      setPendingApplication(pending || null);
    } catch {
      setPendingApplication(null);
    }
  }, [location.pathname, location.search]);

  const updatePendingApplication = (applied) => {
    if (!pendingApplication) return;

    try {
      const raw = localStorage.getItem("university_application_flow_v1");
      const all = raw ? JSON.parse(raw) : {};
      const key = String(pendingApplication.university_id);
      if (!all[key]) return;

      all[key] = {
        ...all[key],
        applied,
        pending_confirmation: false,
        confirmed_at: new Date().toISOString(),
      };

      localStorage.setItem("university_application_flow_v1", JSON.stringify(all));
      setPendingApplication(null);

      if (applied) {
        navigate(`/expense-tracker?university=${key}&source=application`);
      }
    } catch {
      setPendingApplication(null);
    }
  };

  const initials = (() => {
    if (!user || !user.full_name) return "?";
    return user.full_name
      .split(" ")
      .map((s) => s[0])
      .slice(0, 2)
      .join("")
      .toUpperCase();
  })();

  return (
    <>
      <nav className="navbar">
        <div className="navbar-container">
          <Link to="/" className="navbar-logo">
            EduVoyage
          </Link>

          <ul className="navbar-menu">
            <li><Link to="/" className="navbar-link">Home</Link></li>
            <li><Link to="/universities" className="navbar-link">Universities</Link></li>
            <li><Link to="/countries" className="navbar-link">Countries</Link></li>
            <li><Link to="/expense-tracker" className="navbar-link">Expense Tracker</Link></li>
            <li><Link to="/scholarships" className="navbar-link">Scholarship Finder</Link></li>
            <li><Link to="/services" className="navbar-link">Services</Link></li>
          </ul>

          <div className="navbar-buttons">
            <label className="navbar-language-shell" aria-label="Language selector">
              <span>Language</span>
              <select
                className="navbar-language"
                value={language}
                onChange={(event) => setLanguage(event.target.value)}
              >
                <option value="EN">English</option>
                <option value="NP">Nepali</option>
              </select>
            </label>
            {user ? (
              <div className="navbar-user-wrap" ref={dropdownRef}>
                <button
                  className="avatar-btn"
                  onClick={() => setOpen((v) => !v)}
                  aria-haspopup="true"
                  aria-expanded={open}
                  title={user.full_name}
                >
                  {user.avatar ? (
                    <img src={user.avatar} alt={user.full_name} className="avatar" />
                  ) : (
                    <div className="avatar avatar--initials">{initials}</div>
                  )}
                </button>

                {open && (
                  <div className="profile-dropdown" role="menu">
                    <Link to="/profile" className="dropdown-item" onClick={() => setOpen(false)}>
                      Profile
                    </Link>

                    {(user.role === "agent" || user.role === "admin") && (
                      <Link to="/agent" className="dropdown-item" onClick={() => setOpen(false)}>
                        Agent Panel
                      </Link>
                    )}

                    <Link to="/settings" className="dropdown-item" onClick={() => setOpen(false)}>
                      Settings
                    </Link>

                    <button
                      className="dropdown-item dropdown-item--danger"
                      onClick={() => {
                        setOpen(false);
                        logout();
                      }}
                    >
                      Logout
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <>
                <Link to="/signup" className="btn-secondary">Sign Up</Link>
                <Link to="/login" className="btn-primary">Login</Link>
              </>
            )}
          </div>
        </div>
      </nav>

      <div className="site-language-floating">
        <span>Language</span>
        <select
          className="site-language-floating__select"
          value={language}
          onChange={(event) => setLanguage(event.target.value)}
        >
          <option value="EN">English</option>
          <option value="NP">Nepali</option>
        </select>
      </div>

      {pendingApplication && (
        <div className="application-return-prompt">
          <p>Did you apply to {pendingApplication.university_name}?</p>
          <div className="application-return-prompt__actions">
            <button type="button" onClick={() => updatePendingApplication(true)}>Yes</button>
            <button
              type="button"
              className="application-return-prompt__ghost"
              onClick={() => updatePendingApplication(false)}
            >
              Not yet
            </button>
          </div>
        </div>
      )}
    </>
  );
}
