import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const EXPENSE_STORAGE_KEY = "expense_tracker_by_university_v1";

const sumByCategory = (items, matcher) =>
  items.reduce((total, item) => {
    const category = String(item.category || "").toLowerCase();
    return matcher(category) ? total + Number(item.amount || 0) : total;
  }, 0);

export default function Profile() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    full_name: "",
    dob: "",
    gender: "",
    country: "",
    nationality: "",
    city: "",
  });
  const [status, setStatus] = useState({ type: "", message: "" });
  const [saving, setSaving] = useState(false);

  const user = JSON.parse(localStorage.getItem("user")) || {};
  const fullName = user.full_name || "Pranav Sapkota";
  const email = user.email || "pranavsapkota3@gmail.com";
  const initials = fullName
    .split(" ")
    .map((part) => part[0])
    .slice(0, 2)
    .join("")
    .toUpperCase();
  const [expenseSummary, setExpenseSummary] = useState({
    total: 0,
    ielts: 0,
    application: 0,
  });

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) return;

    const loadProfile = async () => {
      try {
        const res = await fetch("http://localhost:5000/api/profile/personal", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data = await res.json();
        if (!data.profile) return;
        setFormData({
          full_name: data.profile.full_name || fullName,
          dob: data.profile.dob || "",
          gender: data.profile.gender || "",
          country: data.profile.country || "",
          nationality: data.profile.nationality || "",
          city: data.profile.city || "",
        });
      } catch {
        setStatus({ type: "error", message: "Failed to load profile." });
      }
    };

    loadProfile();
  }, [fullName]);

  useEffect(() => {
    try {
      const raw = localStorage.getItem(EXPENSE_STORAGE_KEY);
      const all = raw ? JSON.parse(raw) : {};
      const expenses = Object.values(all).flat();
      setExpenseSummary({
        total: expenses.reduce((sum, item) => sum + Number(item.amount || 0), 0),
        ielts: sumByCategory(expenses, (category) => category.includes("ielts") || category.includes("english")),
        application: sumByCategory(
          expenses,
          (category) => category.includes("application") || category.includes("visa") || category.includes("transcript")
        ),
      });
    } catch {
      setExpenseSummary({ total: 0, ielts: 0, application: 0 });
    }
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const token = localStorage.getItem("token");
    if (!token) {
      setStatus({ type: "error", message: "Please login again." });
      return;
    }

    setSaving(true);
    setStatus({ type: "", message: "" });
    try {
      const res = await fetch("http://localhost:5000/api/profile/personal", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(formData),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.details || data.message || "Save failed");
      }

      localStorage.setItem(
        "user",
        JSON.stringify({ ...user, full_name: formData.full_name || fullName })
      );
      setStatus({ type: "success", message: "Profile saved." });
      navigate("/profile/academic");
    } catch (err) {
      setStatus({ type: "error", message: err.message || "Could not save profile." });
    } finally {
      setSaving(false);
    }
  };

  return (
    <>
      <Navbar />
      <main className="profile-page">
        <section className="profile-hero">
          <div className="profile-hero__card">
            <h1>Complete your Profile</h1>
            <p>Finish setting up your EduVoyage account to get personalized recommendations.</p>
          </div>
        </section>

        <section className="profile-shell">
          <div className="profile-layout">
            <aside className="profile-steps">
              <div className="profile-step profile-step--active">
                <span className="step-dot">1</span>
                <div>
                  <h4>Personal Information</h4>
                  <p>Basic details about you</p>
                </div>
              </div>
              <div className="profile-step">
                <span className="step-dot">2</span>
                <div>
                  <h4>Academic Background</h4>
                  <p>Your education history</p>
                </div>
              </div>
              <div className="profile-step">
                <span className="step-dot">3</span>
                <div>
                  <h4>Study Preferences</h4>
                  <p>Where and what you want</p>
                </div>
              </div>
              <div className="profile-step">
                <span className="step-dot">4</span>
                <div>
                  <h4>Documents</h4>
                  <p>Upload required files</p>
                </div>
              </div>
              <div className="profile-step">
                <span className="step-dot">5</span>
                <div>
                  <h4>Review &amp; Submit</h4>
                  <p>Finalize your profile</p>
                </div>
              </div>
            </aside>

            <div className="profile-form">
              <div className="profile-form__title">Personal Information</div>
              <div className="profile-user">
                <div className="profile-avatar">{initials}</div>
                <div>
                  <h3>{fullName}</h3>
                  <p>{email}</p>
                </div>
              </div>

              <div className="profile-expense-summary">
                <div className="profile-expense-summary__card">
                  <span>Total tracked spend</span>
                  <strong>${expenseSummary.total.toLocaleString()}</strong>
                </div>
                <div className="profile-expense-summary__card">
                  <span>IELTS / English tests</span>
                  <strong>${expenseSummary.ielts.toLocaleString()}</strong>
                </div>
                <div className="profile-expense-summary__card">
                  <span>Application related</span>
                  <strong>${expenseSummary.application.toLocaleString()}</strong>
                </div>
              </div>

              <form className="profile-grid" onSubmit={handleSubmit}>
                <div className="profile-field">
                  <label htmlFor="firstName">Full Name</label>
                  <input
                    id="firstName"
                    name="full_name"
                    type="text"
                    placeholder="Your First Name"
                    value={formData.full_name}
                    onChange={handleChange}
                  />
                </div>
                <div className="profile-field">
                  <label htmlFor="dob">Date of birth</label>
                  <input
                    id="dob"
                    name="dob"
                    type="date"
                    value={formData.dob}
                    onChange={handleChange}
                  />
                </div>
                <div className="profile-field">
                  <label htmlFor="gender">Gender</label>
                  <select id="gender" name="gender" value={formData.gender} onChange={handleChange}>
                    <option value="" disabled>Choose</option>
                    <option>Male</option>
                    <option>Female</option>
                    <option>Other</option>
                  </select>
                </div>
                <div className="profile-field">
                  <label htmlFor="country">Country</label>
                  <input
                    id="country"
                    name="country"
                    type="text"
                    placeholder="Nepal"
                    value={formData.country}
                    onChange={handleChange}
                  />
                </div>
                <div className="profile-field">
                  <label htmlFor="nationality">Nationality</label>
                  <input
                    id="nationality"
                    name="nationality"
                    type="text"
                    placeholder="Nepali"
                    value={formData.nationality}
                    onChange={handleChange}
                  />
                </div>
                <div className="profile-field">
                  <label htmlFor="city">City</label>
                  <input
                    id="city"
                    name="city"
                    type="text"
                    placeholder="Kathmandu"
                    value={formData.city}
                    onChange={handleChange}
                  />
                </div>
                <div className="profile-actions">
                  <button type="submit" className="profile-next-btn" disabled={saving}>
                    {saving ? "Saving..." : "Next Education"}
                  </button>
                </div>
              </form>

              {status.message && (
                <p className={`profile-status profile-status--${status.type}`}>
                  {status.message}
                </p>
              )}
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
