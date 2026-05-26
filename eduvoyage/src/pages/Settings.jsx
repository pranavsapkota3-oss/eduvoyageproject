import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const defaultPrefs = {
  email_notifications: true,
  scholarship_alerts: true,
  marketing_updates: false,
  preferred_currency: "USD",
  counseling_reply_alerts: true,
  document_review_alerts: true,
  expense_reminder_alerts: false,
  show_profile_to_agent: true,
  allow_agent_email_contact: true,
  allow_profile_matching: true,
  preferred_country_default: "",
  default_language: "English",
  default_intake_session: "",
  monthly_budget_target: "",
  include_part_time_income: true,
  expense_reminder_day: "",
  allowed_document_reminder: false,
  auto_lock_vault_on_logout: true,
  document_upload_reminder: false,
};

const defaultProfile = {
  full_name: "",
  email: "",
  role: "student",
  phone_number: "",
  emergency_contact: "",
  profile_photo_url: "",
};

export default function Settings() {
  const navigate = useNavigate();
  const token = localStorage.getItem("token");
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("profile");

  const [profile, setProfile] = useState(defaultProfile);
  const [passwordForm, setPasswordForm] = useState({ current_password: "", new_password: "", confirm_password: "" });
  const [prefs, setPrefs] = useState(defaultPrefs);
  const [securityInfo, setSecurityInfo] = useState({ last_login_at: null });

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

        setProfile({ ...defaultProfile, ...(data.profile || {}) });
        setPrefs({ ...defaultPrefs, ...(data.preferences || {}) });
        setSecurityInfo(data.security || { last_login_at: null });
      } catch {
        setError("Could not load settings.");
      } finally {
        setLoading(false);
      }
    };

    loadSettings();
  }, [token]);

  const clearMessages = () => {
    setStatus("");
    setError("");
  };

  const saveProfile = async (e) => {
    e.preventDefault();
    clearMessages();

    try {
      const res = await fetch("http://localhost:5000/api/settings/profile", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(profile),
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
    clearMessages();

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
    clearMessages();

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

  const logoutAllDevices = async () => {
    clearMessages();
    try {
      const res = await fetch("http://localhost:5000/api/settings/logout-all-devices", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.message || "Could not log out other devices.");
        return;
      }
      setStatus(data.message || "Logged out from all devices.");
    } catch {
      setError("Could not log out other devices.");
    }
  };

  const deactivateAccount = async () => {
    clearMessages();
    try {
      const res = await fetch("http://localhost:5000/api/settings/deactivate-account", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.message || "Could not deactivate account.");
        return;
      }
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      sessionStorage.removeItem("document_vault_session_pin_v1");
      navigate("/login");
    } catch {
      setError("Could not deactivate account.");
    }
  };

  const lastLoginLabel = securityInfo.last_login_at
    ? new Date(securityInfo.last_login_at).toLocaleString()
    : "Not available yet";

  const activeTabMeta = {
    profile: {
      title: "Profile and privacy",
      description: "Update your identity details and choose how much of your profile agents can use while helping you.",
    },
    security: {
      title: "Security and account control",
      description: "Handle password changes, device access, vault shortcuts, and account protection actions from one place.",
    },
    preferences: {
      title: "Study and product preferences",
      description: "Set how the platform behaves for alerts, study planning, expense tracking, and document reminders.",
    },
    support: {
      title: "Support and shortcuts",
      description: "Jump quickly into help, counseling, and the modules you use most often during planning.",
    },
  };

  const overviewCards = [
    {
      label: "Email and alerts",
      value: prefs.email_notifications ? "Enabled" : "Muted",
      note: prefs.scholarship_alerts ? "Scholarship updates active" : "Scholarship updates off",
    },
    {
      label: "Vault behavior",
      value: prefs.auto_lock_vault_on_logout ? "Auto-lock on" : "Manual lock",
      note: prefs.document_upload_reminder ? "Upload reminders enabled" : "Upload reminders off",
    },
    {
      label: "Default study setup",
      value: prefs.preferred_currency || "Not set",
      note: prefs.preferred_country_default || "Country default not set",
    },
    {
      label: "Account security",
      value: profile.role || "student",
      note: `Last login: ${lastLoginLabel}`,
    },
  ];

  return (
    <>
      <Navbar />
      <main className="settings-page">
        <section className="settings-hero">
          <div className="settings-hero__layout">
            <div className="settings-hero__copy">
              <p className="settings-hero__eyebrow">Settings hub</p>
              <h1>Control how EduVoyage works for you</h1>
              <p>Manage your profile, security, notifications, planning defaults, and support shortcuts from one organized place.</p>
            </div>
            <div className="settings-hero__panel">
              <span className="settings-hero__panel-label">Account snapshot</span>
              <strong>{profile.full_name || "Student account"}</strong>
              <span>{profile.email || "Email not loaded"}</span>
              <span>{lastLoginLabel}</span>
            </div>
          </div>
        </section>

        {loading && <p className="settings-state">Loading settings...</p>}
        {!loading && error && <p className="settings-state settings-state--error">{error}</p>}
        {!loading && status && <p className="settings-state settings-state--ok">{status}</p>}

        {!loading && !error && (
          <>
            <section className="settings-overview">
              {overviewCards.map((card) => (
                <article key={card.label} className="settings-overview__card">
                  <span className="settings-overview__label">{card.label}</span>
                  <strong>{card.value}</strong>
                  <p>{card.note}</p>
                </article>
              ))}
            </section>

            <section className="settings-shell">
              <aside className="settings-sidebar" aria-label="Settings sections">
                {[
                  ["profile", "Profile"],
                  ["security", "Security"],
                  ["preferences", "Preferences"],
                  ["support", "Support"],
                ].map(([key, label]) => (
                  <button
                    key={key}
                    type="button"
                    className={`settings-tab ${activeTab === key ? "settings-tab--active" : ""}`}
                    onClick={() => setActiveTab(key)}
                  >
                    {label}
                  </button>
                ))}
              </aside>

              <section className="settings-content">
                <article className="settings-section-intro">
                  <span className="settings-section-intro__eyebrow">Current section</span>
                  <h2>{activeTabMeta[activeTab].title}</h2>
                  <p>{activeTabMeta[activeTab].description}</p>
                </article>

                <section className="settings-grid">
              {activeTab === "profile" && (
                <>
                  <article className="settings-card">
                    <span className="settings-card__eyebrow">Identity</span>
                    <h2>Profile</h2>
                    <p className="settings-card__intro">Keep your visible account details updated so agent support and matching tools use the right information.</p>
                    <form onSubmit={saveProfile} className="settings-form">
                      <div className="settings-form-grid">
                        <div className="settings-field">
                          <label htmlFor="fullName">Full Name</label>
                          <input id="fullName" type="text" value={profile.full_name} onChange={(e) => setProfile((prev) => ({ ...prev, full_name: e.target.value }))} />
                        </div>

                        <div className="settings-field">
                          <label htmlFor="email">Email</label>
                          <input id="email" type="email" value={profile.email} onChange={(e) => setProfile((prev) => ({ ...prev, email: e.target.value }))} />
                        </div>

                        <div className="settings-field">
                          <label htmlFor="phoneNumber">Phone Number</label>
                          <input id="phoneNumber" type="text" value={profile.phone_number} onChange={(e) => setProfile((prev) => ({ ...prev, phone_number: e.target.value }))} />
                        </div>

                        <div className="settings-field">
                          <label htmlFor="emergencyContact">Emergency Contact</label>
                          <input id="emergencyContact" type="text" value={profile.emergency_contact} onChange={(e) => setProfile((prev) => ({ ...prev, emergency_contact: e.target.value }))} />
                        </div>
                      </div>

                      <div className="settings-field">
                        <label htmlFor="photoUrl">Profile Photo URL</label>
                        <input id="photoUrl" type="text" value={profile.profile_photo_url} onChange={(e) => setProfile((prev) => ({ ...prev, profile_photo_url: e.target.value }))} placeholder="Paste image URL" />
                      </div>

                      <div className="settings-field">
                        <label htmlFor="role">Role</label>
                        <input id="role" type="text" value={profile.role} disabled />
                      </div>

                      <button type="submit">Save Profile</button>
                    </form>
                  </article>

                  <article className="settings-card">
                    <span className="settings-card__eyebrow">Visibility</span>
                    <h2>Privacy</h2>
                    <p className="settings-card__intro">Choose what agents can view or use when recommending scholarships, universities, and support options.</p>
                    <form onSubmit={savePreferences} className="settings-form">
                      <div className="settings-toggle-list">
                        <label className="settings-checkbox">
                          <input type="checkbox" checked={prefs.show_profile_to_agent} onChange={(e) => setPrefs((prev) => ({ ...prev, show_profile_to_agent: e.target.checked }))} />
                          <span>Show profile to agent</span>
                        </label>
                        <label className="settings-checkbox">
                          <input type="checkbox" checked={prefs.allow_agent_email_contact} onChange={(e) => setPrefs((prev) => ({ ...prev, allow_agent_email_contact: e.target.checked }))} />
                          <span>Allow email contact from agent</span>
                        </label>
                        <label className="settings-checkbox">
                          <input type="checkbox" checked={prefs.allow_profile_matching} onChange={(e) => setPrefs((prev) => ({ ...prev, allow_profile_matching: e.target.checked }))} />
                          <span>Allow saved academic profile for matching</span>
                        </label>
                      </div>
                      <button type="submit">Save Privacy Settings</button>
                    </form>
                  </article>
                </>
              )}

              {activeTab === "security" && (
                <>
                  <article className="settings-card">
                    <span className="settings-card__eyebrow">Access</span>
                    <h2>Security</h2>
                    <p className="settings-card__intro">Refresh your password regularly and keep access details updated for a safer account.</p>
                    <form onSubmit={changePassword} className="settings-form">
                      <div className="settings-field">
                        <label htmlFor="currentPassword">Current Password</label>
                        <input id="currentPassword" type="password" value={passwordForm.current_password} onChange={(e) => setPasswordForm((prev) => ({ ...prev, current_password: e.target.value }))} />
                      </div>

                      <div className="settings-form-grid">
                        <div className="settings-field">
                          <label htmlFor="newPassword">New Password</label>
                          <input id="newPassword" type="password" value={passwordForm.new_password} onChange={(e) => setPasswordForm((prev) => ({ ...prev, new_password: e.target.value }))} />
                        </div>

                        <div className="settings-field">
                          <label htmlFor="confirmPassword">Confirm New Password</label>
                          <input id="confirmPassword" type="password" value={passwordForm.confirm_password} onChange={(e) => setPasswordForm((prev) => ({ ...prev, confirm_password: e.target.value }))} />
                        </div>
                      </div>

                      <button type="submit">Change Password</button>
                    </form>
                  </article>

                  <article className="settings-card">
                    <span className="settings-card__eyebrow">Control</span>
                    <h2>Account Security Actions</h2>
                    <p className="settings-card__intro">Use these controls when you want to reset device sessions, change vault access, or close the account.</p>
                    <div className="settings-form">
                      <div className="settings-summary-row">
                        <strong>Last login</strong>
                        <span>{lastLoginLabel}</span>
                      </div>
                      <div className="settings-action-row">
                        <button type="button" onClick={logoutAllDevices}>Logout from all devices</button>
                        <Link to="/document-vault" className="profile-btn">Change document vault PIN</Link>
                      </div>
                      <div className="settings-action-row">
                        <button type="button" className="profile-btn profile-btn--ghost" onClick={deactivateAccount}>Deactivate account</button>
                      </div>
                    </div>
                  </article>
                </>
              )}

              {activeTab === "preferences" && (
                <>
                  <article className="settings-card">
                    <span className="settings-card__eyebrow">Alerts</span>
                    <h2>Notifications</h2>
                    <p className="settings-card__intro">Choose which updates are worth interrupting you for while the application process is moving.</p>
                    <form onSubmit={savePreferences} className="settings-form">
                      <div className="settings-toggle-list">
                        <label className="settings-checkbox"><input type="checkbox" checked={prefs.email_notifications} onChange={(e) => setPrefs((prev) => ({ ...prev, email_notifications: e.target.checked }))} /><span>Email notifications</span></label>
                        <label className="settings-checkbox"><input type="checkbox" checked={prefs.scholarship_alerts} onChange={(e) => setPrefs((prev) => ({ ...prev, scholarship_alerts: e.target.checked }))} /><span>Scholarship alerts</span></label>
                      </div>
                      <button type="submit">Save Notification Settings</button>
                    </form>
                  </article>

                  <article className="settings-card">
                    <span className="settings-card__eyebrow">Vault behavior</span>
                    <h2>Document Vault</h2>
                    <p className="settings-card__intro">Define how strongly the vault reminds and protects you while documents are being collected.</p>
                    <form onSubmit={savePreferences} className="settings-form">
                      <div className="settings-toggle-list">
                        <label className="settings-checkbox">
                          <input type="checkbox" checked={prefs.auto_lock_vault_on_logout} onChange={(e) => setPrefs((prev) => ({ ...prev, auto_lock_vault_on_logout: e.target.checked }))} />
                          <span>Auto-lock vault on logout</span>
                        </label>
                      </div>
                      <button type="submit">Save Vault Settings</button>
                    </form>
                  </article>
                </>
              )}

              {activeTab === "support" && (
                <>
                  <article className="settings-card">
                    <span className="settings-card__eyebrow">Help</span>
                    <h2>Support</h2>
                    <p className="settings-card__intro">Keep your most common support actions close so you can move into the right workflow quickly.</p>
                    <div className="settings-form">
                      <div className="settings-link-list">
                        <Link to="/services" className="profile-btn">Contact support</Link>
                        <Link to="/services" className="profile-btn">Request counseling</Link>
                        <a href="#faq" className="profile-btn">FAQ / Help center</a>
                      </div>
                    </div>
                  </article>

                  <article className="settings-card">
                    <span className="settings-card__eyebrow">Shortcuts</span>
                    <h2>Quick Access</h2>
                    <p className="settings-card__intro">Open the modules you revisit often without going back through the main navigation every time.</p>
                    <div className="settings-form">
                      <div className="settings-link-list">
                        <Link to="/document-vault" className="profile-btn">Open document vault</Link>
                        <Link to="/expense-tracker" className="profile-btn">Open expense tracker</Link>
                        <Link to="/scholarship-finder" className="profile-btn">Open scholarship finder</Link>
                      </div>
                    </div>
                  </article>
                </>
              )}
                </section>
              </section>
            </section>
          </>
        )}
      </main>
      <Footer />
    </>
  );
}
