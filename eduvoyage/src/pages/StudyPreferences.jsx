import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const COUNTRY_OPTIONS = [
  "United States",
  "United Kingdom",
  "Canada",
  "Australia",
  "New Zealand",
  "Germany",
  "Japan",
  "Singapore",
];

export default function StudyPreferences() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    degree_level: "",
    field_of_study: "",
    preferred_countries: "",
    annual_budget: "",
    preferred_intake: "",
  });
  const [status, setStatus] = useState({ type: "", message: "" });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) return;

    const loadPreferences = async () => {
      try {
        const res = await fetch("http://localhost:5000/api/profile/preferences", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data = await res.json();
        if (!data.preferences) return;
        setFormData({
          degree_level: data.preferences.degree_level || "",
          field_of_study: data.preferences.field_of_study || "",
          preferred_countries: data.preferences.preferred_countries || "",
          annual_budget: data.preferences.annual_budget || "",
          preferred_intake: data.preferences.preferred_intake || "",
        });
      } catch {
        setStatus({ type: "error", message: "Failed to load study preferences." });
      }
    };

    loadPreferences();
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
      const res = await fetch("http://localhost:5000/api/profile/preferences", {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(formData),
      });

      if (!res.ok) {
        throw new Error("Save failed");
      }

      setStatus({ type: "success", message: "Study preferences saved." });
      navigate("/profile/documents");
    } catch {
      setStatus({ type: "error", message: "Could not save study preferences." });
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
              <div className="profile-step">
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
              <div className="profile-step profile-step--active">
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
              <div className="profile-form__title">Study Preference</div>

              <form onSubmit={handleSubmit}>
                <div className="profile-grid profile-grid--academic">
                  <div className="profile-field">
                    <label htmlFor="degreeLevel">Desired Degree level</label>
                    <select
                      id="degreeLevel"
                      name="degree_level"
                      value={formData.degree_level}
                      onChange={handleChange}
                    >
                      <option value="" disabled>Select level</option>
                      <option>Diploma</option>
                      <option>Bachelor</option>
                      <option>Master</option>
                      <option>PhD</option>
                    </select>
                  </div>
                  <div className="profile-field">
                    <label htmlFor="fieldStudy">Desired field of study</label>
                    <input
                      id="fieldStudy"
                      name="field_of_study"
                      type="text"
                      placeholder="eg, computer science, business"
                      value={formData.field_of_study}
                      onChange={handleChange}
                    />
                  </div>
                  <div className="profile-field">
                    <label htmlFor="countries">Preferred Countries</label>
                    <select
                      id="countries"
                      name="preferred_countries"
                      value={formData.preferred_countries}
                      onChange={handleChange}
                    >
                      <option value="" disabled>Select preferred country</option>
                      {COUNTRY_OPTIONS.map((country) => (
                        <option key={country} value={country}>
                          {country}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div className="profile-field">
                    <label htmlFor="budget">Annual Budget</label>
                    <input
                      id="budget"
                      name="annual_budget"
                      type="text"
                      placeholder="USD"
                      value={formData.annual_budget}
                      onChange={handleChange}
                    />
                  </div>
                  <div className="profile-field profile-field--full">
                    <label htmlFor="intake">Preferred Intake</label>
                    <input
                      id="intake"
                      name="preferred_intake"
                      type="text"
                      placeholder="Spring 2026 / Fall 2026"
                      value={formData.preferred_intake}
                      onChange={handleChange}
                    />
                  </div>
                </div>

                <div className="profile-actions profile-actions--split">
                  <Link to="/profile/academic" className="profile-btn profile-btn--ghost">Back</Link>
                  <button type="submit" className="profile-btn profile-next-btn" disabled={saving}>
                    {saving ? "Saving..." : "Next Documents"}
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
