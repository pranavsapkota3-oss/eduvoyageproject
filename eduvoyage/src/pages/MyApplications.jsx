import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const STATUS_ORDER = ["shortlisted", "applying", "submitted", "offer received", "accepted", "rejected", "stopped applying"];

function statusClass(status) {
  if (status === "accepted") return "tag tag--active";
  if (status === "rejected") return "tag tag--inactive";
  if (status === "offer received") return "tag tag--offer";
  if (status === "stopped applying") return "tag tag--stopped";
  return "tag";
}

export default function MyApplications() {
  const token = localStorage.getItem("token");
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [statusKind, setStatusKind] = useState("");
  const [applications, setApplications] = useState([]);
  const [actionLoadingId, setActionLoadingId] = useState(null);

  const loadApplications = async ({ silent = false } = {}) => {
    if (!token) {
      setStatus("Login first to view your applications.");
      setStatusKind("error");
      setLoading(false);
      return;
    }

    if (!silent) {
      setLoading(true);
    }

    try {
      const res = await fetch("http://localhost:5000/api/profile/applications", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();

      if (!res.ok) {
        setStatus(data.message || "Could not load applications.");
        setStatusKind("error");
        return;
      }

      setApplications(data.applications || []);
    } catch {
      setStatus("Could not load applications.");
      setStatusKind("error");
    } finally {
      if (!silent) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    loadApplications();
  }, [token]);

  const summary = useMemo(() => ({
    total: applications.length,
    active: applications.filter((item) => !["accepted", "rejected", "stopped applying"].includes(item.status)).length,
    offers: applications.filter((item) => item.status === "offer received").length,
    decisions: applications.filter((item) => ["accepted", "rejected", "stopped applying"].includes(item.status)).length,
  }), [applications]);

  const updateApplicationStatus = async (application, nextStatus) => {
    if (!nextStatus) return;

    try {
      setActionLoadingId(application.id);
      setStatus("");
      setStatusKind("");
      const res = await fetch(`http://localhost:5000/api/profile/applications/${application.id}/status`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ status: nextStatus }),
      });
      const data = await res.json();

      if (!res.ok) {
        setStatus(data.message || "Could not update application status.");
        setStatusKind("error");
        return;
      }

      await loadApplications({ silent: true });
      setStatus(`Application updated to ${nextStatus}.`);
      setStatusKind("success");
    } catch {
      setStatus("Could not update application status.");
      setStatusKind("error");
    } finally {
      setActionLoadingId(null);
    }
  };

  const getStudentActions = (currentStatus) => {
    switch (currentStatus) {
      case "shortlisted":
        return [
          { status: "applying", label: "Mark as applying" },
          { status: "stopped applying", label: "Stop applying" },
        ];
      case "applying":
        return [
          { status: "submitted", label: "Mark as submitted" },
          { status: "stopped applying", label: "Stop applying" },
        ];
      case "submitted":
        return [
          { status: "offer received", label: "Mark offer received" },
          { status: "accepted", label: "Mark as accepted" },
          { status: "rejected", label: "Mark as rejected" },
          { status: "stopped applying", label: "Stop applying" },
        ];
      case "offer received":
        return [
          { status: "accepted", label: "Mark as accepted" },
          { status: "rejected", label: "Mark as rejected" },
          { status: "stopped applying", label: "Stop applying" },
        ];
      default:
        return [];
    }
  };

  return (
    <>
      <Navbar />
      <main className="applications-page">
        <section className="applications-hero">
          <p className="applications-hero__eyebrow">Student pipeline</p>
          <h1>My Applications</h1>
          <p>Track which university you shortlisted, where you already applied, and what the latest decision status looks like.</p>
        </section>

        {status && <p className={`settings-state ${statusKind === "success" ? "settings-state--success" : "settings-state--error"}`}>{status}</p>}

        {!loading && (
          <>
            <section className="applications-summary">
              <article className="applications-summary__card">
                <span>Total applications</span>
                <strong>{summary.total}</strong>
              </article>
              <article className="applications-summary__card">
                <span>Still active</span>
                <strong>{summary.active}</strong>
              </article>
              <article className="applications-summary__card">
                <span>Offers received</span>
                <strong>{summary.offers}</strong>
              </article>
              <article className="applications-summary__card">
                <span>Final decisions</span>
                <strong>{summary.decisions}</strong>
              </article>
            </section>

            <section className="applications-list">
              {applications.length === 0 && (
                <article className="applications-empty">
                  <h2>No applications yet</h2>
                  <p>Start from any university detail page, click <strong>Apply Now</strong>, and the university will appear here as part of your application workflow.</p>
                  <Link to="/universities" className="profile-btn">Browse universities</Link>
                </article>
              )}

              {applications.map((application) => {
                const currentStatus = application.status || "shortlisted";
                const currentIndex = Math.max(0, STATUS_ORDER.indexOf(currentStatus));
                const studentActions = getStudentActions(currentStatus);
                return (
                  <article key={application.id} className="applications-card">
                    <div className="applications-card__head">
                      <div>
                        <span className="applications-card__eyebrow">Application record</span>
                        <h2>{application.university_name}</h2>
                        <p>{application.university_city || "-"}{application.university_city && application.university_country ? ", " : ""}{application.university_country || ""}</p>
                      </div>
                      <span className={statusClass(currentStatus)}>
                        {currentStatus}
                      </span>
                    </div>

                    <div className="applications-timeline">
                      {STATUS_ORDER.map((step, index) => (
                        <div key={step} className={`applications-timeline__step ${index <= currentIndex ? "applications-timeline__step--done" : ""}`}>
                          <span />
                          <strong>{step}</strong>
                        </div>
                      ))}
                    </div>

                    <div className="applications-meta">
                      <div>
                        <span>Started</span>
                        <strong>{application.created_at?.slice?.(0, 10) || "-"}</strong>
                      </div>
                      <div>
                        <span>Last updated</span>
                        <strong>{application.updated_at?.slice?.(0, 10) || "-"}</strong>
                      </div>
                      <div>
                        <span>Submitted</span>
                        <strong>{application.submitted_at?.slice?.(0, 10) || "Not yet"}</strong>
                      </div>
                    </div>

                    {application.notes && (
                      <div className="applications-note">
                        <span>Follow-up note</span>
                        <p>{application.notes}</p>
                      </div>
                    )}

                    {studentActions.length > 0 && (
                      <div className="applications-next-step">
                        <div>
                          <span>Next step</span>
                          <p>
                            {currentStatus === "shortlisted"
                              ? "You shortlisted this university. Start the application or stop the process if you changed your mind."
                              : currentStatus === "applying"
                                ? "Mark it as submitted once you finish the university application and send it."
                                : currentStatus === "submitted"
                                  ? "Record the next outcome after the university responds or stop the process if you are no longer continuing."
                                  : "Choose the final result after receiving the university outcome."}
                          </p>
                        </div>
                        <div className="applications-next-step__actions">
                          {studentActions.map((action) => (
                            <button
                              key={action.status}
                              type="button"
                              className={`profile-btn ${action.status === "stopped applying" || action.status === "rejected" ? "profile-btn--ghost" : ""}`}
                              disabled={actionLoadingId === application.id}
                              onClick={() => updateApplicationStatus(application, action.status)}
                            >
                              {actionLoadingId === application.id ? "Saving..." : action.label}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="applications-actions">
                      <Link to={`/universities/${application.university_id}`} className="profile-btn profile-btn--ghost">View university</Link>
                      <Link to={`/expense-tracker?university=${application.university_id}&source=application`} className="profile-btn">Continue planning</Link>
                    </div>
                  </article>
                );
              })}
            </section>
          </>
        )}
      </main>
      <Footer />
    </>
  );
}
