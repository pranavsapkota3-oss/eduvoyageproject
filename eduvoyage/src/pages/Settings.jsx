import { useEffect, useState } from "react";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const defaultPrefs = {
  email_notifications: true,
  scholarship_alerts: true,
  marketing_updates: false,
  preferred_currency: "USD",
};

export default function Settings() {
  const token = localStorage.getItem("token");
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("profile");

  const [profile, setProfile] = useState({ full_name: "", email: "", role: "student" });
  const [passwordForm, setPasswordForm] = useState({ current_password: "", new_password: "", confirm_password: "" });
  const [prefs, setPrefs] = useState(defaultPrefs);

  useEffect(() => {
    const loadSettings = async () => {
      if (!token) {
        setError("Please login first.");
        setLoading(false);
        return;
      }

      try {
        const res = await fetch("http://localhost:5000/api/settings", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();

        if (!res.ok) {
          setError(data.message || "Failed to load settings.");
          return;
        }

        setProfile(data.profile || { full_name: "", email: "", role: "student" });
        setPrefs({ ...defaultPrefs, ...(data.preferences || {}) });
      } catch {
        setError("Could not load settings.");
      } finally {
        setLoading(false);
      }
    };

    loadSettings();
  }, [token]);

  const saveProfile = async (e) => {
    e.preventDefault();
    setStatus("");
    setError("");

    try {
      const res = await fetch("http://localhost:5000/api/settings/profile", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ full_name: profile.full_name, email: profile.email }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.message || "Failed to update profile settings.");
        return;
      }

      if (data.token) localStorage.setItem("token", data.token);
      if (data.user) localStorage.setItem("user", JSON.stringify(data.user));

      setStatus("Profile settings saved.");
    } catch {
      setError("Could not update profile settings.");
    }
  };

  const changePassword = async (e) => {
    e.preventDefault();
    setStatus("");
    setError("");

    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setError("New password and confirm password do not match.");
      return;
    }

    try {
      const res = await fetch("http://localhost:5000/api/settings/password", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          current_password: passwordForm.current_password,
          new_password: passwordForm.new_password,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.message || "Failed to update password.");
        return;
      }

      setPasswordForm({ current_password: "", new_password: "", confirm_password: "" });
      setStatus("Password updated successfully.");
    } catch {
      setError("Could not update password.");
    }
  };

  const savePreferences = async (e) => {
    e.preventDefault();
    setStatus("");
    setError("");

    try {
      const res = await fetch("http://localhost:5000/api/settings/preferences", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(prefs),
      });
      const data = await res.json();

      if (!res.ok) {
        setError(data.message || "Failed to update preferences.");
        return;
      }

      setStatus("Preferences saved.");
    } catch {
      setError("Could not update preferences.");
    }
  };

  return (
    <>
      <Navbar />
      <main className="settings-page">
        <section className="settings-hero">
          <h1>Account Settings</h1>
          <p>Manage profile details, password, and notifications.</p>
        </section>

        {loading && <p className="settings-state">Loading settings...</p>}
        {!loading && error && <p className="settings-state settings-state--error">{error}</p>}
        {!loading && status && <p className="settings-state settings-state--ok">{status}</p>}

        {!loading && !error && (
          <>
            <section className="settings-tabs" aria-label="Settings sections">
              <button
                type="button"
                className={`settings-tab ${activeTab === "profile" ? "settings-tab--active" : ""}`}
                onClick={() => setActiveTab("profile")}
              >
                Profile
              </button>
              <button
                type="button"
                className={`settings-tab ${activeTab === "security" ? "settings-tab--active" : ""}`}
                onClick={() => setActiveTab("security")}
              >
                Security
              </button>
              <button
                type="button"
                className={`settings-tab ${activeTab === "preferences" ? "settings-tab--active" : ""}`}
                onClick={() => setActiveTab("preferences")}
              >
                Preferences
              </button>
            </section>

            <section className="settings-grid settings-grid--single">
              {activeTab === "profile" && (
                <article className="settings-card">
                  <h2>Profile</h2>
                  <form onSubmit={saveProfile} className="settings-form">
                    <label htmlFor="fullName">Full Name</label>
                    <input
                      id="fullName"
                      type="text"
                      value={profile.full_name}
                      onChange={(e) => setProfile((prev) => ({ ...prev, full_name: e.target.value }))}
                    />

                    <label htmlFor="email">Email</label>
                    <input
                      id="email"
                      type="email"
                      value={profile.email}
                      onChange={(e) => setProfile((prev) => ({ ...prev, email: e.target.value }))}
                    />

                    <label htmlFor="role">Role</label>
                    <input id="role" type="text" value={profile.role} disabled />

                    <button type="submit">Save Profile</button>
                  </form>
                </article>
              )}

              {activeTab === "security" && (
                <article className="settings-card">
                  <h2>Security</h2>
                  <form onSubmit={changePassword} className="settings-form">
                    <label htmlFor="currentPassword">Current Password</label>
                    <input
                      id="currentPassword"
                      type="password"
                      value={passwordForm.current_password}
                      onChange={(e) => setPasswordForm((prev) => ({ ...prev, current_password: e.target.value }))}
                    />

                    <label htmlFor="newPassword">New Password</label>
                    <input
                      id="newPassword"
                      type="password"
                      value={passwordForm.new_password}
                      onChange={(e) => setPasswordForm((prev) => ({ ...prev, new_password: e.target.value }))}
                    />

                    <label htmlFor="confirmPassword">Confirm New Password</label>
                    <input
                      id="confirmPassword"
                      type="password"
                      value={passwordForm.confirm_password}
                      onChange={(e) => setPasswordForm((prev) => ({ ...prev, confirm_password: e.target.value }))}
                    />

                    <button type="submit">Change Password</button>
                  </form>
                </article>
              )}

              {activeTab === "preferences" && (
                <article className="settings-card settings-card--wide">
                  <h2>Preferences</h2>
                  <form onSubmit={savePreferences} className="settings-form">
                    <label className="settings-checkbox">
                      <input
                        type="checkbox"
                        checked={prefs.email_notifications}
                        onChange={(e) => setPrefs((prev) => ({ ...prev, email_notifications: e.target.checked }))}
                      />
                      <span>Email notifications</span>
                    </label>

                    <label className="settings-checkbox">
                      <input
                        type="checkbox"
                        checked={prefs.scholarship_alerts}
                        onChange={(e) => setPrefs((prev) => ({ ...prev, scholarship_alerts: e.target.checked }))}
                      />
                      <span>Scholarship alerts</span>
                    </label>

                    <label className="settings-checkbox">
                      <input
                        type="checkbox"
                        checked={prefs.marketing_updates}
                        onChange={(e) => setPrefs((prev) => ({ ...prev, marketing_updates: e.target.checked }))}
                      />
                      <span>Product and feature updates</span>
                    </label>

                    <label htmlFor="currency">Preferred Currency</label>
                    <select
                      id="currency"
                      value={prefs.preferred_currency}
                      onChange={(e) => setPrefs((prev) => ({ ...prev, preferred_currency: e.target.value }))}
                    >
                      <option value="USD">USD</option>
                      <option value="CAD">CAD</option>
                      <option value="AUD">AUD</option>
                      <option value="GBP">GBP</option>
                      <option value="NPR">NPR</option>
                    </select>

                    <button type="submit">Save Preferences</button>
                  </form>
                </article>
              )}
            </section>
          </>
        )}
      </main>
      <Footer />
    </>
  );
}
