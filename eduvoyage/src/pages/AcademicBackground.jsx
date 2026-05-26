import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

export default function AcademicBackground() {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    highest_level: "",
    gpa: "",
    school_name: "",
    graduation_year: "",
    field_of_study: "",
    ielts_score: "",
    toefl_score: "",
    gre_score: "",
    gmat_score: "",
    sat_score: "",
  });
  const [status, setStatus] = useState({ type: "", message: "" });
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) return;

    const loadAcademic = async () => {
      try {
        const res = await fetch("http://localhost:5000/api/profile/academic", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data = await res.json();
        if (!data.academic) return;
        setFormData({
          highest_level: data.academic.highest_level || "",
          gpa: data.academic.gpa || "",
          school_name: data.academic.school_name || "",
          graduation_year: data.academic.graduation_year || "",
          field_of_study: data.academic.field_of_study || "",
          ielts_score: data.academic.ielts_score || "",
          toefl_score: data.academic.toefl_score || "",
          gre_score: data.academic.gre_score || "",
          gmat_score: data.academic.gmat_score || "",
          sat_score: data.academic.sat_score || "",
        });
      } catch {
        setStatus({ type: "error", message: "Failed to load academic data." });
      }
    };

    loadAcademic();
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
      const res = await fetch("http://localhost:5000/api/profile/academic", {
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

      setStatus({ type: "success", message: "Academic background saved." });
      navigate("/profile/preferences");
    } catch {
      setStatus({ type: "error", message: "Could not save academic data." });
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
              <div className="profile-step profile-step--active">
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
              <div className="profile-form__title">Academic Background</div>

              <form onSubmit={handleSubmit}>
                <div className="profile-grid profile-grid--academic">
                  <div className="profile-field">
                    <label htmlFor="level">Highest level Education</label>
                    <select
                      id="level"
                      name="highest_level"
                      value={formData.highest_level}
                      onChange={handleChange}
                    >
                      <option value="" disabled>Select level</option>
                      <option>High School</option>
                      <option>Bachelor</option>
                      <option>Master</option>
                      <option>PhD</option>
                    </select>
                  </div>
                  <div className="profile-field">
                    <label htmlFor="gpa">GPA or Percentage</label>
                    <input
                      id="gpa"
                      name="gpa"
                      type="text"
                      placeholder="eg. 3.5 or 85%"
                      value={formData.gpa}
                      onChange={handleChange}
                    />
                  </div>
                  <div className="profile-field">
                    <label htmlFor="school">School/College Name</label>
                    <input
                      id="school"
                      name="school_name"
                      type="text"
                      placeholder="Enter your institution name"
                      value={formData.school_name}
                      onChange={handleChange}
                    />
                  </div>
                  <div className="profile-field">
                    <label htmlFor="gradYear">Graduation Year</label>
                    <input
                      id="gradYear"
                      name="graduation_year"
                      type="text"
                      placeholder="2015"
                      value={formData.graduation_year}
                      onChange={handleChange}
                    />
                  </div>
                  <div className="profile-field profile-field--full">
                    <label htmlFor="field">Field of study</label>
                    <input
                      id="field"
                      name="field_of_study"
                      type="text"
                      placeholder="Nepali"
                      value={formData.field_of_study}
                      onChange={handleChange}
                    />
                  </div>
                </div>

                <div className="profile-subsection">
                  <h4>Test Scores</h4>
                  <p>Enter your standardized test scores (if available)</p>
                  <div className="profile-grid profile-grid--scores">
                    <div className="profile-field">
                      <label htmlFor="ielts">IELTS Score</label>
                      <input
                        id="ielts"
                        name="ielts_score"
                        type="text"
                        placeholder="0.0-9.0"
                        value={formData.ielts_score}
                        onChange={handleChange}
                      />
                    </div>
                    <div className="profile-field">
                      <label htmlFor="toefl">TOEFL Score</label>
                      <input
                        id="toefl"
                        name="toefl_score"
                        type="text"
                        placeholder="0-120"
                        value={formData.toefl_score}
                        onChange={handleChange}
                      />
                    </div>
                    <div className="profile-field">
                      <label htmlFor="sat">SAT Score</label>
                      <input
                        id="sat"
                        name="sat_score"
                        type="text"
                        placeholder="400-1600"
                        value={formData.sat_score}
                        onChange={handleChange}
                      />
                    </div>
                    <div className="profile-field">
                      <label htmlFor="gre">GRE Score</label>
                      <input
                        id="gre"
                        name="gre_score"
                        type="text"
                        placeholder="260-340"
                        value={formData.gre_score}
                        onChange={handleChange}
                      />
                    </div>
                    <div className="profile-field">
                      <label htmlFor="gmat">GMAT Score</label>
                      <input
                        id="gmat"
                        name="gmat_score"
                        type="text"
                        placeholder="200-800"
                        value={formData.gmat_score}
                        onChange={handleChange}
                      />
                    </div>
                  </div>
                </div>

                <div className="profile-actions profile-actions--split">
                  <Link to="/profile" className="profile-btn profile-btn--ghost">Back</Link>
                  <button type="submit" className="profile-btn profile-next-btn" disabled={saving}>
                    {saving ? "Saving..." : "Next Study pref"}
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
