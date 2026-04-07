import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

export default function ReviewSubmit() {
  const navigate = useNavigate();
  const [data, setData] = useState({
    personal: null,
    academic: null,
    preferences: null,
    documents: [],
  });
  const [status, setStatus] = useState({ type: "", message: "" });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      setStatus({ type: "error", message: "Please login again." });
      setLoading(false);
      return;
    }

    const loadAll = async () => {
      try {
        const headers = { Authorization: `Bearer ${token}` };
        const [personalRes, academicRes, prefRes, docsRes] = await Promise.all([
          fetch("http://localhost:5000/api/profile/personal", { headers }),
          fetch("http://localhost:5000/api/profile/academic", { headers }),
          fetch("http://localhost:5000/api/profile/preferences", { headers }),
          fetch("http://localhost:5000/api/profile/documents", { headers }),
        ]);

        const personal = personalRes.ok ? (await personalRes.json()).profile : null;
        const academic = academicRes.ok ? (await academicRes.json()).academic : null;
        const preferences = prefRes.ok ? (await prefRes.json()).preferences : null;
        const documents = docsRes.ok ? (await docsRes.json()).documents : [];

        setData({ personal, academic, preferences, documents });
      } catch {
        setStatus({ type: "error", message: "Failed to load profile summary." });
      } finally {
        setLoading(false);
      }
    };

    loadAll();
  }, []);

  const handleSubmit = () => {
    setStatus({ type: "success", message: "Profile submitted successfully." });
    setTimeout(() => navigate("/"), 800);
  };

  return (
    <>
      <Navbar />
      <main className="profile-page">
        <section className="profile-hero">
          <div className="profile-hero__card">
            <h1>Complete your Profile</h1>
            <p>Review everything before submitting your profile.</p>
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
              <div className="profile-step profile-step--active">
                <span className="step-dot">5</span>
                <div>
                  <h4>Review &amp; Submit</h4>
                  <p>Finalize your profile</p>
                </div>
              </div>
            </aside>

            <div className="profile-form">
              <div className="profile-form__title">Review &amp; Submit</div>

              {loading ? (
                <p className="profile-helper">Loading profile summary...</p>
              ) : (
                <div className="review-grid">
                  <div className="review-card">
                    <h4>Personal Information</h4>
                    <ul>
                      <li><strong>Name:</strong> {data.personal?.full_name || "-"}</li>
                      <li><strong>Email:</strong> {data.personal?.email || "-"}</li>
                      <li><strong>Date of birth:</strong> {data.personal?.dob || "-"}</li>
                      <li><strong>Gender:</strong> {data.personal?.gender || "-"}</li>
                      <li><strong>Country:</strong> {data.personal?.country || "-"}</li>
                      <li><strong>City:</strong> {data.personal?.city || "-"}</li>
                    </ul>
                  </div>

                  <div className="review-card">
                    <h4>Academic Background</h4>
                    <ul>
                      <li><strong>Level:</strong> {data.academic?.highest_level || "-"}</li>
                      <li><strong>GPA:</strong> {data.academic?.gpa || "-"}</li>
                      <li><strong>School:</strong> {data.academic?.school_name || "-"}</li>
                      <li><strong>Year:</strong> {data.academic?.graduation_year || "-"}</li>
                      <li><strong>Field:</strong> {data.academic?.field_of_study || "-"}</li>
                    </ul>
                  </div>

                  <div className="review-card">
                    <h4>Study Preferences</h4>
                    <ul>
                      <li><strong>Degree:</strong> {data.preferences?.degree_level || "-"}</li>
                      <li><strong>Field:</strong> {data.preferences?.field_of_study || "-"}</li>
                      <li><strong>Countries:</strong> {data.preferences?.preferred_countries || "-"}</li>
                      <li><strong>Budget:</strong> {data.preferences?.annual_budget || "-"}</li>
                      <li><strong>Intake:</strong> {data.preferences?.preferred_intake || "-"}</li>
                    </ul>
                  </div>

                  <div className="review-card">
                    <h4>Documents</h4>
                    <ul>
                      {data.documents.length === 0 && <li>No documents uploaded.</li>}
                      {data.documents.map((doc) => (
                        <li key={doc.id}>
                          {doc.file_name} <span className="review-muted">({doc.file_size})</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}

              <div className="profile-actions">
                <button type="button" className="profile-next-btn" onClick={handleSubmit}>
                  Submit Profile
                </button>
              </div>

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
