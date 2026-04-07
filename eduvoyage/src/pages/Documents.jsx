import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

export default function Documents() {
  const fileInputRef = useRef(null);
  const [files, setFiles] = useState([]);
  const [status, setStatus] = useState({ type: "", message: "" });

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) return;

    const loadDocuments = async () => {
      try {
        const res = await fetch("http://localhost:5000/api/profile/documents", {
          headers: { Authorization: `Bearer ${token}` },
        });
        if (!res.ok) return;
        const data = await res.json();
        setFiles(data.documents || []);
      } catch {
        setStatus({ type: "error", message: "Failed to load documents." });
      }
    };

    loadDocuments();
  }, []);

  const handleBrowse = () => {
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
      fileInputRef.current.click();
    }
  };

  const handleFileChange = async (e) => {
    const token = localStorage.getItem("token");
    if (!token) {
      setStatus({ type: "error", message: "Please login again." });
      return;
    }

    const selected = Array.from(e.target.files || []);
    if (selected.length === 0) return;

    try {
      const formData = new FormData();
      selected.forEach((file) => formData.append("documents", file));

      const res = await fetch("http://localhost:5000/api/profile/documents", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: formData,
      });

      if (!res.ok) {
        throw new Error("Save failed");
      }

      const data = await res.json();
      setFiles(data.documents || []);
      setStatus({ type: "success", message: "Documents saved." });
    } catch {
      setStatus({ type: "error", message: "Could not save documents." });
    }
  };

  const handleDelete = async (docId) => {
    const token = localStorage.getItem("token");
    if (!token) return;

    try {
      const res = await fetch(`http://localhost:5000/api/profile/documents/${docId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        throw new Error("Delete failed");
      }

      setFiles((prev) => prev.filter((doc) => doc.id !== docId));
    } catch {
      setStatus({ type: "error", message: "Could not delete document." });
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
              <div className="profile-step">
                <span className="step-dot">3</span>
                <div>
                  <h4>Study Preferences</h4>
                  <p>Where and what you want</p>
                </div>
              </div>
              <div className="profile-step profile-step--active">
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
              <div className="profile-form__title">Required Documents</div>
              <p className="profile-helper">Upload the necessary documents for your applications</p>

              <div className="upload-card">
                <div className="upload-icon">
                  <div className="upload-icon__sheet"></div>
                </div>
                <p className="upload-title">Drag &amp; Drop your files here</p>
                <p className="upload-subtitle">or click to browse files</p>
                <button type="button" className="profile-btn profile-next-btn" onClick={handleBrowse}>
                  Browse Files
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  hidden
                  onChange={handleFileChange}
                />
              </div>

              <div className="file-list">
                {files.map((file) => (
                  <div className="file-row" key={file.id}>
                    <div className="file-meta">
                      {file.mime_type && file.mime_type.startsWith("image/") ? (
                        <img
                          className="file-thumb"
                          src={`http://localhost:5000${file.file_url}`}
                          alt={file.file_name}
                        />
                      ) : (
                        <span className="file-icon"></span>
                      )}
                      <div>
                        <h5>{file.file_name}</h5>
                        <p>{file.file_size}</p>
                      </div>
                    </div>
                    <div className="file-actions">
                      <button
                        type="button"
                        className="file-btn"
                        onClick={() => {
                          if (file.file_url) {
                            window.open(`http://localhost:5000${file.file_url}`, "_blank");
                          }
                        }}
                      >
                        view
                      </button>
                      <button
                        type="button"
                        className="file-btn file-btn--danger"
                        onClick={() => handleDelete(file.id)}
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                ))}
              </div>

              <div className="profile-actions profile-actions--split">
                <Link to="/profile/preferences" className="profile-btn profile-btn--ghost">Back</Link>
                <Link to="/profile/review" className="profile-btn profile-next-btn">Next Submit</Link>
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
