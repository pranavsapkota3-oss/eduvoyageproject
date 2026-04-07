import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const DOC_REVIEW_STORAGE_KEY = "admin_document_review_state_v1";
const APP_STATUS_STORAGE_KEY = "admin_application_status_state_v1";
const ITEMS_PER_PAGE = 8;

const navItems = [
  { key: "overview", label: "Overview" },
  { key: "users", label: "Users" },
  { key: "universities", label: "Universities" },
  { key: "documents", label: "Documents" },
  { key: "applications", label: "Applications" },
  { key: "counseling", label: "Counseling Requests" },
];

function paginate(items, page, perPage = ITEMS_PER_PAGE) {
  const start = (page - 1) * perPage;
  return items.slice(start, start + perPage);
}

function readStoredMap(key) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function getApplicationLabel(application) {
  return (
    application.university_name ||
    application.university ||
    application.school_name ||
    application.program_name ||
    application.course_name ||
    `Application #${application.id || "-"}`
  );
}

function getApplicantLabel(application) {
  return (
    application.full_name ||
    application.student_name ||
    application.applicant_name ||
    application.email ||
    `User ${application.user_id || "-"}`
  );
}

function getApplicationDate(application) {
  return application.created_at?.slice?.(0, 10) || application.updated_at?.slice?.(0, 10) || "-";
}

export default function AgentDashboard() {
  const token = localStorage.getItem("token");
  const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
  const canManageUsers = currentUser.role === "admin";

  const [activeSection, setActiveSection] = useState("overview");
  const [loading, setLoading] = useState(true);
  const [status, setStatus] = useState("");
  const [summary, setSummary] = useState({
    total_students: 0,
    active_agents: 0,
    pending_document_reviews: 0,
    applications_submitted: 0,
  });
  const [users, setUsers] = useState([]);
  const [universities, setUniversities] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [applications, setApplications] = useState([]);
  const [counselingRequests, setCounselingRequests] = useState([]);
  const [docReviewState, setDocReviewState] = useState(() => readStoredMap(DOC_REVIEW_STORAGE_KEY));
  const [applicationStatusState, setApplicationStatusState] = useState(() => readStoredMap(APP_STATUS_STORAGE_KEY));

  const [userSearch, setUserSearch] = useState("");
  const [userRoleFilter, setUserRoleFilter] = useState("");
  const [userStatusFilter, setUserStatusFilter] = useState("");
  const [userPage, setUserPage] = useState(1);

  const [uniSearch, setUniSearch] = useState("");
  const [uniCountryFilter, setUniCountryFilter] = useState("");
  const [uniWorkflowFilter, setUniWorkflowFilter] = useState("all");
  const [uniPage, setUniPage] = useState(1);

  const [docSearch, setDocSearch] = useState("");
  const [docPage, setDocPage] = useState(1);

  const [applicationSearch, setApplicationSearch] = useState("");
  const [applicationFilter, setApplicationFilter] = useState("");
  const [applicationPage, setApplicationPage] = useState(1);

  const [editingUniId, setEditingUniId] = useState(null);
  const [uniName, setUniName] = useState("");
  const [uniCountry, setUniCountry] = useState("");
  const [uniCity, setUniCity] = useState("");
  const [uniRanking, setUniRanking] = useState("");
  const [uniWebsite, setUniWebsite] = useState("");
  const [uniOverview, setUniOverview] = useState("");
  const [uniCourses, setUniCourses] = useState("");
  const [uniFees, setUniFees] = useState("");
  const [uniFacilities, setUniFacilities] = useState("");
  const [uniScholarships, setUniScholarships] = useState("");
  const [uniAdmissions, setUniAdmissions] = useState("");
  const [uniLocation, setUniLocation] = useState("");
  const [uniContact, setUniContact] = useState("");
  const [uniImage, setUniImage] = useState("");

  const resetUniversityForm = () => {
    setUniName("");
    setUniCountry("");
    setUniCity("");
    setUniRanking("");
    setUniWebsite("");
    setUniOverview("");
    setUniCourses("");
    setUniFees("");
    setUniFacilities("");
    setUniScholarships("");
    setUniAdmissions("");
    setUniLocation("");
    setUniContact("");
    setUniImage("");
    setEditingUniId(null);
  };

  const loadSummary = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/admin/summary", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setSummary(data);
    } catch {}
  };

  const loadUsers = async () => {
    if (!canManageUsers) return;
    try {
      const res = await fetch("http://localhost:5000/api/admin/users", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setUsers(data.users || []);
      else setStatus(data.message || "Failed to load users.");
    } catch {
      setStatus("Failed to load users.");
    }
  };

  const loadUniversities = async () => {
    try {
      const params = new URLSearchParams({ page: "1", limit: "200" });
      const res = await fetch(`http://localhost:5000/api/universities?${params.toString()}`);
      const data = await res.json();
      if (res.ok) setUniversities(data.universities || []);
    } catch {
      setUniversities([]);
    }
  };

  const loadDocuments = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/admin/documents", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setDocuments(data.documents || []);
    } catch {
      setDocuments([]);
    }
  };

  const loadApplications = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/admin/applications", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setApplications(data.applications || []);
    } catch {
      setApplications([]);
    }
  };

  const loadCounselingRequests = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/admin/counseling-requests", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setCounselingRequests(data.requests || []);
    } catch {
      setCounselingRequests([]);
    }
  };

  useEffect(() => {
    const init = async () => {
      if (!token) {
        setStatus("Please login with an admin or agent account.");
        setLoading(false);
        return;
      }
      setLoading(true);
      await Promise.all([
        loadSummary(),
        loadUsers(),
        loadUniversities(),
        loadDocuments(),
        loadApplications(),
        loadCounselingRequests(),
      ]);
      setLoading(false);
    };
    init();
  }, []);

  useEffect(() => {
    localStorage.setItem(DOC_REVIEW_STORAGE_KEY, JSON.stringify(docReviewState));
  }, [docReviewState]);

  useEffect(() => {
    localStorage.setItem(APP_STATUS_STORAGE_KEY, JSON.stringify(applicationStatusState));
  }, [applicationStatusState]);

  const existingOptions = useMemo(() => {
    const unique = (key) => [...new Set(universities.map((u) => u[key]).filter(Boolean))].slice(0, 120);
    return {
      names: unique("name"),
      countries: unique("country"),
      cities: unique("city"),
      websites: unique("website"),
      locations: unique("location"),
      contacts: unique("contact"),
      images: unique("image_url"),
    };
  }, [universities]);

  const workflowIssues = useMemo(() => {
    const missingImage = universities.filter((uni) => !uni.image_url).length;
    const missingFees = universities.filter((uni) => !uni.fees).length;
    const missingContent = universities.filter((uni) => !uni.overview || !uni.courses).length;
    return [
      { title: "University content cleanup", subtitle: `${missingContent} profiles need stronger academic content`, target: "universities", action: "Open universities" },
      { title: "Missing tuition data", subtitle: `${missingFees} universities still need fees`, target: "universities", action: "Fix tuition data" },
      { title: "Document review queue", subtitle: `${documents.length} uploaded documents are waiting`, target: "documents", action: "Open documents" },
      { title: "Application queue", subtitle: `${applications.length} applications are in the pipeline`, target: "applications", action: "Open applications" },
      { title: "Image coverage", subtitle: `${missingImage} universities need a hero image`, target: "universities", action: "Update images" },
    ];
  }, [applications.length, documents.length, universities]);

  const filteredUsers = useMemo(() => users.filter((user) => {
    const matchesSearch = !userSearch || `${user.full_name} ${user.email}`.toLowerCase().includes(userSearch.toLowerCase());
    const matchesRole = !userRoleFilter || user.role === userRoleFilter;
    const matchesStatus = !userStatusFilter || String(user.is_active) === userStatusFilter;
    return matchesSearch && matchesRole && matchesStatus;
  }), [userRoleFilter, userSearch, userStatusFilter, users]);

  const filteredUniversities = useMemo(() => universities.filter((uni) => {
    const matchesSearch = !uniSearch || `${uni.name} ${uni.country} ${uni.city}`.toLowerCase().includes(uniSearch.toLowerCase());
    const matchesCountry = !uniCountryFilter || uni.country === uniCountryFilter;
    if (uniWorkflowFilter === "needs-content") return matchesSearch && matchesCountry && (!uni.overview || !uni.courses);
    if (uniWorkflowFilter === "needs-fees") return matchesSearch && matchesCountry && !uni.fees;
    if (uniWorkflowFilter === "needs-image") return matchesSearch && matchesCountry && !uni.image_url;
    return matchesSearch && matchesCountry;
  }), [uniCountryFilter, uniSearch, uniWorkflowFilter, universities]);

  const filteredDocuments = useMemo(() => documents.filter((doc) => {
    const reviewLabel = docReviewState[doc.id]?.status || "Pending";
    return !docSearch || `${doc.full_name} ${doc.email} ${doc.file_name} ${reviewLabel}`.toLowerCase().includes(docSearch.toLowerCase());
  }), [docReviewState, docSearch, documents]);

  const filteredApplications = useMemo(() => applications.filter((application) => {
    const localStatus = applicationStatusState[application.id] || application.status || "submitted";
    const haystack = `${getApplicantLabel(application)} ${getApplicationLabel(application)} ${localStatus}`.toLowerCase();
    const matchesSearch = !applicationSearch || haystack.includes(applicationSearch.toLowerCase());
    const matchesStatus = !applicationFilter || localStatus === applicationFilter;
    return matchesSearch && matchesStatus;
  }), [applicationFilter, applicationSearch, applicationStatusState, applications]);

  const suggestedCounseling = useMemo(() => {
    if (counselingRequests.length) return counselingRequests;
    return users.filter((user) => user.role === "student").slice(0, 5).map((user) => ({
      id: `suggested-${user.id}`,
      full_name: user.full_name,
      email: user.email,
      topic: "Profile review and university shortlist",
      priority: user.is_active ? "Normal priority" : "Follow up",
      created_at: user.created_at,
    }));
  }, [counselingRequests, users]);

  const pagedUsers = paginate(filteredUsers, userPage);
  const pagedUniversities = paginate(filteredUniversities, uniPage);
  const pagedDocuments = paginate(filteredDocuments, docPage);
  const pagedApplications = paginate(filteredApplications, applicationPage);

  const setDocumentReview = (docId, nextStatus) => {
    setDocReviewState((prev) => ({ ...prev, [docId]: { status: nextStatus } }));
    setStatus(`Document marked as ${nextStatus.toLowerCase()}.`);
  };

  const setApplicationStatus = (applicationId, nextStatus) => {
    setApplicationStatusState((prev) => ({ ...prev, [applicationId]: nextStatus }));
    setStatus(`Application moved to ${nextStatus}.`);
  };

  const updateRole = async (id, nextRole) => {
    try {
      const res = await fetch(`http://localhost:5000/api/admin/users/${id}/role`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ role: nextRole }),
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to update role.");
      setUsers((prev) => prev.map((user) => (user.id === id ? { ...user, role: nextRole } : user)));
      setStatus("User role updated.");
      loadSummary();
    } catch {
      setStatus("Failed to update role.");
    }
  };

  const updateUserStatus = async (id, isActive) => {
    try {
      const res = await fetch(`http://localhost:5000/api/admin/users/${id}/status`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ is_active: isActive }),
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to update user status.");
      setUsers((prev) => prev.map((user) => (user.id === id ? { ...user, is_active: isActive } : user)));
      setStatus("User status updated.");
    } catch {
      setStatus("Failed to update user status.");
    }
  };

  const deleteUser = async (id) => {
    if (!window.confirm("Delete this user?")) return;
    try {
      const res = await fetch(`http://localhost:5000/api/admin/users/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to delete user.");
      setUsers((prev) => prev.filter((user) => user.id !== id));
      setStatus("User deleted.");
      loadSummary();
    } catch {
      setStatus("Failed to delete user.");
    }
  };

  const handleEditUniversity = (uni) => {
    setEditingUniId(uni.id);
    setUniName(uni.name || "");
    setUniCountry(uni.country || "");
    setUniCity(uni.city || "");
    setUniRanking(uni.ranking || "");
    setUniWebsite(uni.website || "");
    setUniOverview(uni.overview || "");
    setUniCourses(uni.courses || "");
    setUniFees(uni.fees || "");
    setUniFacilities(uni.facilities || "");
    setUniScholarships(uni.scholarships || "");
    setUniAdmissions(uni.admissions || "");
    setUniLocation(uni.location || "");
    setUniContact(uni.contact || "");
    setUniImage(uni.image_url || "");
    setStatus("Editing university. Save changes to update the public pages.");
    setActiveSection("universities");
  };

  const handleAddUniversity = async (event) => {
    event.preventDefault();
    if (!uniName || !uniCountry) return setStatus("University name and country are required.");
    try {
      const endpoint = editingUniId
        ? `http://localhost:5000/api/agent/universities/${editingUniId}`
        : "http://localhost:5000/api/agent/universities";
      const method = editingUniId ? "PATCH" : "POST";
      const res = await fetch(endpoint, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: uniName,
          country: uniCountry,
          city: uniCity,
          ranking: uniRanking ? Number(uniRanking) : null,
          website: uniWebsite,
          overview: uniOverview,
          courses: uniCourses,
          fees: uniFees,
          facilities: uniFacilities,
          scholarships: uniScholarships,
          admissions: uniAdmissions,
          location: uniLocation,
          contact: uniContact,
          image_url: uniImage,
        }),
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to save university.");
      setStatus(editingUniId ? "University updated." : "University added.");
      resetUniversityForm();
      loadUniversities();
    } catch {
      setStatus("Failed to save university.");
    }
  };

  const handleDeleteUniversity = async (id) => {
    if (!window.confirm("Delete this university?")) return;
    try {
      const res = await fetch(`http://localhost:5000/api/agent/universities/${id}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to delete university.");
      setStatus("University deleted.");
      loadUniversities();
      loadSummary();
    } catch {
      setStatus("Failed to delete university.");
    }
  };

  if (!currentUser.role || (currentUser.role !== "admin" && currentUser.role !== "agent")) {
    return (
      <>
        <Navbar />
        <main className="admin-page">
          <div className="admin-card">
            <h1>Admin or Agent Access Only</h1>
            <p>Please log in with an admin or agent account to continue.</p>
          </div>
        </main>
        <Footer />
      </>
    );
  }

  return (
    <>
      <div className="admin-layout admin-layout--dashboard">
        <aside className="admin-sidebar admin-sidebar--dashboard">
          <div className="admin-brand">
            <div className="admin-logo">EduVoyage</div>
            <span>{canManageUsers ? "Management workspace" : "Agent operations"}</span>
          </div>

          <nav className="admin-nav admin-nav--dashboard">
            {navItems.filter((item) => canManageUsers || item.key !== "users").map((item) => (
              <button
                key={item.key}
                type="button"
                className={`admin-nav__item ${activeSection === item.key ? "admin-nav__item--active" : ""}`}
                onClick={() => setActiveSection(item.key)}
              >
                {item.label}
              </button>
            ))}
          </nav>

          <div className="admin-sidebar__footer">
            <strong>Current role</strong>
            <span>{currentUser.role}</span>
            <Link to="/" className="admin-signout">Back to site</Link>
          </div>
        </aside>

        <div className="admin-main admin-main--dashboard">
          <header className="admin-topbar admin-topbar--dashboard">
            <div>
              <p className="admin-kicker">Management panel</p>
              <h1>{canManageUsers ? "Admin Control Center" : "Agent Workflow Desk"}</h1>
            </div>
            {status && <p className="admin-status admin-status--inline">{status}</p>}
          </header>

          <section className="admin-summary-grid">
            <article className="admin-summary-card">
              <span>Total students</span>
              <strong>{summary.total_students}</strong>
              <p>Registered students currently in the system.</p>
            </article>
            <article className="admin-summary-card">
              <span>Active agents</span>
              <strong>{summary.active_agents}</strong>
              <p>Agents with active accounts and dashboard access.</p>
            </article>
            <article className="admin-summary-card">
              <span>Pending document reviews</span>
              <strong>{summary.pending_document_reviews}</strong>
              <p>Uploaded files currently waiting for review.</p>
            </article>
            <article className="admin-summary-card">
              <span>Applications submitted</span>
              <strong>{summary.applications_submitted}</strong>
              <p>Application rows currently stored in the database.</p>
            </article>
          </section>

          {!loading && activeSection === "overview" && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Workflow</p>
                    <h2>Today’s management priorities</h2>
                  </div>
                </div>
                <div className="admin-workflow-grid">
                  {workflowIssues.map((item) => (
                    <button key={item.title} type="button" className="admin-workflow-card" onClick={() => setActiveSection(item.target)}>
                      <span>{item.title}</span>
                      <strong>{item.subtitle}</strong>
                      <em>{item.action}</em>
                    </button>
                  ))}
                </div>
              </article>

              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Operations snapshot</p>
                    <h2>What needs attention next</h2>
                  </div>
                </div>
                <div className="admin-overview-grid">
                  <div className="admin-overview-card"><h3>University coverage</h3><p>{universities.length} universities are currently published across the public catalogue.</p></div>
                  <div className="admin-overview-card"><h3>Document queue</h3><p>{documents.length ? `${documents.length} files are waiting for review.` : "No new uploads in the review queue."}</p></div>
                  <div className="admin-overview-card"><h3>Application pipeline</h3><p>{applications.length ? `${applications.length} application rows are available for follow-up.` : "No application records are currently available."}</p></div>
                  <div className="admin-overview-card"><h3>Counseling support</h3><p>{suggestedCounseling.length ? `${suggestedCounseling.length} student conversations need attention.` : "No counseling requests are waiting right now."}</p></div>
                </div>
              </article>
            </section>
          )}

          {!loading && activeSection === "users" && canManageUsers && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">User management</p>
                    <h2>Users</h2>
                  </div>
                  <div className="admin-toolbar">
                    <input type="text" placeholder="Search name or email" value={userSearch} onChange={(e) => { setUserSearch(e.target.value); setUserPage(1); }} />
                    <select value={userRoleFilter} onChange={(e) => { setUserRoleFilter(e.target.value); setUserPage(1); }}>
                      <option value="">All roles</option><option value="student">Student</option><option value="agent">Agent</option><option value="admin">Admin</option>
                    </select>
                    <select value={userStatusFilter} onChange={(e) => { setUserStatusFilter(e.target.value); setUserPage(1); }}>
                      <option value="">All status</option><option value="1">Active</option><option value="0">Inactive</option>
                    </select>
                  </div>
                </div>
                <div className="admin-data-table">
                  <table>
                    <thead><tr><th>Name</th><th>Email</th><th>Joined</th><th>Role</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody>
                      {pagedUsers.length === 0 && <tr><td colSpan="6">No users match the current filters.</td></tr>}
                      {pagedUsers.map((user) => (
                        <tr key={user.id}>
                          <td>{user.full_name}</td>
                          <td>{user.email}</td>
                          <td>{user.created_at?.slice?.(0, 10) || "-"}</td>
                          <td>
                            <select value={user.role} onChange={(e) => updateRole(user.id, e.target.value)}>
                              <option value="student">Student</option><option value="agent">Agent</option><option value="admin">Admin</option>
                            </select>
                          </td>
                          <td><span className={user.is_active ? "tag tag--active" : "tag tag--inactive"}>{user.is_active ? "Active" : "Inactive"}</span></td>
                          <td className="admin-actions">
                            <button type="button" className="agent-btn agent-btn--ghost" onClick={() => updateUserStatus(user.id, !user.is_active)}>{user.is_active ? "Deactivate" : "Activate"}</button>
                            <button type="button" className="agent-btn agent-btn--danger" onClick={() => deleteUser(user.id)}>Delete</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="admin-pagination">
                  <button type="button" disabled={userPage === 1} onClick={() => setUserPage((page) => Math.max(1, page - 1))}>Prev</button>
                  <span>Page {userPage}</span>
                  <button type="button" disabled={userPage * ITEMS_PER_PAGE >= filteredUsers.length} onClick={() => setUserPage((page) => page + 1)}>Next</button>
                </div>
              </article>
            </section>
          )}

          {!loading && activeSection === "universities" && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Publishing workflow</p>
                    <h2>Universities</h2>
                  </div>
                  <div className="admin-toolbar">
                    <input type="text" placeholder="Search by name, city or country" value={uniSearch} onChange={(e) => { setUniSearch(e.target.value); setUniPage(1); }} />
                    <select value={uniCountryFilter} onChange={(e) => { setUniCountryFilter(e.target.value); setUniPage(1); }}>
                      <option value="">All countries</option>
                      {[...new Set(universities.map((uni) => uni.country).filter(Boolean))].sort().map((country) => <option key={country} value={country}>{country}</option>)}
                    </select>
                    <select value={uniWorkflowFilter} onChange={(e) => { setUniWorkflowFilter(e.target.value); setUniPage(1); }}>
                      <option value="all">All records</option>
                      <option value="needs-content">Needs overview/courses</option>
                      <option value="needs-fees">Needs fees</option>
                      <option value="needs-image">Needs image</option>
                    </select>
                  </div>
                </div>
                <div className="admin-university-shell">
                  <form className="admin-form admin-form--dashboard" onSubmit={handleAddUniversity}>
                    <div className="admin-form__section-title">University profile editor</div>
                    <input type="text" placeholder="University name" value={uniName} onChange={(e) => setUniName(e.target.value)} list="uni-name-list" />
                    <input type="text" placeholder="Country" value={uniCountry} onChange={(e) => setUniCountry(e.target.value)} list="uni-country-list" />
                    <input type="text" placeholder="City" value={uniCity} onChange={(e) => setUniCity(e.target.value)} list="uni-city-list" />
                    <input type="number" placeholder="Ranking" value={uniRanking} onChange={(e) => setUniRanking(e.target.value)} />
                    <input type="text" placeholder="Website" value={uniWebsite} onChange={(e) => setUniWebsite(e.target.value)} list="uni-website-list" />
                    <input type="text" placeholder="Location" value={uniLocation} onChange={(e) => setUniLocation(e.target.value)} list="uni-location-list" />
                    <input type="text" placeholder="Contact" value={uniContact} onChange={(e) => setUniContact(e.target.value)} list="uni-contact-list" />
                    <input type="text" placeholder="Image URL" value={uniImage} onChange={(e) => setUniImage(e.target.value)} list="uni-image-list" />
                    <textarea placeholder="Overview" value={uniOverview} onChange={(e) => setUniOverview(e.target.value)} />
                    <textarea placeholder="Courses" value={uniCourses} onChange={(e) => setUniCourses(e.target.value)} />
                    <textarea placeholder="Fees" value={uniFees} onChange={(e) => setUniFees(e.target.value)} />
                    <textarea placeholder="Facilities" value={uniFacilities} onChange={(e) => setUniFacilities(e.target.value)} />
                    <textarea placeholder="Scholarships" value={uniScholarships} onChange={(e) => setUniScholarships(e.target.value)} />
                    <textarea placeholder="Admissions" value={uniAdmissions} onChange={(e) => setUniAdmissions(e.target.value)} />
                    <div className="admin-form__actions">
                      <button type="submit">{editingUniId ? "Save changes" : "Add university"}</button>
                      {editingUniId && <button type="button" className="admin-form__cancel-btn" onClick={resetUniversityForm}>Cancel edit</button>}
                    </div>

                    <datalist id="uni-name-list">{existingOptions.names.map((item) => <option key={item} value={item} />)}</datalist>
                    <datalist id="uni-country-list">{existingOptions.countries.map((item) => <option key={item} value={item} />)}</datalist>
                    <datalist id="uni-city-list">{existingOptions.cities.map((item) => <option key={item} value={item} />)}</datalist>
                    <datalist id="uni-website-list">{existingOptions.websites.map((item) => <option key={item} value={item} />)}</datalist>
                    <datalist id="uni-location-list">{existingOptions.locations.map((item) => <option key={item} value={item} />)}</datalist>
                    <datalist id="uni-contact-list">{existingOptions.contacts.map((item) => <option key={item} value={item} />)}</datalist>
                    <datalist id="uni-image-list">{existingOptions.images.map((item) => <option key={item} value={item} />)}</datalist>
                  </form>

                  <div className="admin-data-table">
                    <table>
                      <thead><tr><th>Name</th><th>Country</th><th>Rank</th><th>Workflow</th><th>Actions</th></tr></thead>
                      <tbody>
                        {pagedUniversities.length === 0 && <tr><td colSpan="5">No universities match the current workflow filter.</td></tr>}
                        {pagedUniversities.map((uni) => {
                          const issueTags = [!uni.overview || !uni.courses ? "Content" : null, !uni.fees ? "Fees" : null, !uni.image_url ? "Image" : null].filter(Boolean);
                          return (
                            <tr key={uni.id}>
                              <td>{uni.name}</td>
                              <td>{uni.country}</td>
                              <td>{uni.ranking || "-"}</td>
                              <td><div className="admin-chip-row">{issueTags.length ? issueTags.map((tag) => <span key={tag} className="admin-chip">{tag}</span>) : <span className="tag tag--active">Ready</span>}</div></td>
                              <td className="admin-actions">
                                <button type="button" className="agent-btn agent-btn--ghost" onClick={() => handleEditUniversity(uni)}>Edit</button>
                                <Link to={`/universities/${uni.id}`} className="agent-btn agent-btn--ghost">View</Link>
                                {canManageUsers && <button type="button" className="agent-btn agent-btn--danger" onClick={() => handleDeleteUniversity(uni.id)}>Delete</button>}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="admin-pagination">
                  <button type="button" disabled={uniPage === 1} onClick={() => setUniPage((page) => Math.max(1, page - 1))}>Prev</button>
                  <span>Page {uniPage}</span>
                  <button type="button" disabled={uniPage * ITEMS_PER_PAGE >= filteredUniversities.length} onClick={() => setUniPage((page) => page + 1)}>Next</button>
                </div>
              </article>
            </section>
          )}

          {!loading && activeSection === "documents" && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Review queue</p>
                    <h2>Documents</h2>
                  </div>
                  <div className="admin-toolbar">
                    <input type="text" placeholder="Search student, email, or file name" value={docSearch} onChange={(e) => { setDocSearch(e.target.value); setDocPage(1); }} />
                  </div>
                </div>
                <div className="admin-data-table">
                  <table>
                    <thead><tr><th>Student</th><th>Document</th><th>Uploaded</th><th>Review status</th><th>Actions</th></tr></thead>
                    <tbody>
                      {pagedDocuments.length === 0 && <tr><td colSpan="5">No documents found in the current queue.</td></tr>}
                      {pagedDocuments.map((doc) => {
                        const reviewStatus = docReviewState[doc.id]?.status || "Pending";
                        return (
                          <tr key={doc.id}>
                            <td><strong>{doc.full_name}</strong><div>{doc.email}</div></td>
                            <td><strong>{doc.file_name}</strong><div>{doc.file_size || "-"}</div></td>
                            <td>{doc.created_at?.slice?.(0, 10) || "-"}</td>
                            <td><span className={`tag ${reviewStatus === "Approved" ? "tag--active" : reviewStatus === "Rejected" ? "tag--inactive" : ""}`}>{reviewStatus}</span></td>
                            <td className="admin-actions">
                              {doc.file_url && <a className="agent-btn agent-btn--ghost" href={`http://localhost:5000${doc.file_url}`} target="_blank" rel="noreferrer">Open</a>}
                              <button type="button" className="agent-btn agent-btn--ghost" onClick={() => setDocumentReview(doc.id, "Approved")}>Approve</button>
                              <button type="button" className="agent-btn agent-btn--danger" onClick={() => setDocumentReview(doc.id, "Rejected")}>Reject</button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="admin-pagination">
                  <button type="button" disabled={docPage === 1} onClick={() => setDocPage((page) => Math.max(1, page - 1))}>Prev</button>
                  <span>Page {docPage}</span>
                  <button type="button" disabled={docPage * ITEMS_PER_PAGE >= filteredDocuments.length} onClick={() => setDocPage((page) => page + 1)}>Next</button>
                </div>
              </article>
            </section>
          )}

          {!loading && activeSection === "applications" && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Pipeline</p>
                    <h2>Applications</h2>
                  </div>
                  <div className="admin-toolbar">
                    <input type="text" placeholder="Search applicant or university" value={applicationSearch} onChange={(e) => { setApplicationSearch(e.target.value); setApplicationPage(1); }} />
                    <select value={applicationFilter} onChange={(e) => { setApplicationFilter(e.target.value); setApplicationPage(1); }}>
                      <option value="">All statuses</option>
                      <option value="shortlisted">Shortlisted</option>
                      <option value="applying">Applying</option>
                      <option value="submitted">Submitted</option>
                      <option value="offer received">Offer received</option>
                      <option value="accepted">Accepted</option>
                      <option value="rejected">Rejected</option>
                    </select>
                  </div>
                </div>
                <div className="admin-data-table">
                  <table>
                    <thead><tr><th>Applicant</th><th>University</th><th>Date</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody>
                      {pagedApplications.length === 0 && <tr><td colSpan="5">No applications are currently available.</td></tr>}
                      {pagedApplications.map((application) => {
                        const currentStatus = applicationStatusState[application.id] || application.status || "submitted";
                        return (
                          <tr key={application.id || `${getApplicantLabel(application)}-${getApplicationLabel(application)}`}>
                            <td>{getApplicantLabel(application)}</td>
                            <td>{getApplicationLabel(application)}</td>
                            <td>{getApplicationDate(application)}</td>
                            <td><span className="tag tag--active">{currentStatus}</span></td>
                            <td className="admin-actions admin-actions--wrap">
                              {["shortlisted", "applying", "submitted", "offer received", "accepted", "rejected"].map((nextStatus) => (
                                <button key={nextStatus} type="button" className={`agent-btn ${nextStatus === "rejected" ? "agent-btn--danger" : "agent-btn--ghost"}`} onClick={() => setApplicationStatus(application.id, nextStatus)}>
                                  {nextStatus}
                                </button>
                              ))}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="admin-pagination">
                  <button type="button" disabled={applicationPage === 1} onClick={() => setApplicationPage((page) => Math.max(1, page - 1))}>Prev</button>
                  <span>Page {applicationPage}</span>
                  <button type="button" disabled={applicationPage * ITEMS_PER_PAGE >= filteredApplications.length} onClick={() => setApplicationPage((page) => page + 1)}>Next</button>
                </div>
              </article>
            </section>
          )}

          {!loading && activeSection === "counseling" && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Student support</p>
                    <h2>Counseling requests</h2>
                  </div>
                </div>
                <div className="admin-request-grid">
                  {suggestedCounseling.length === 0 && (
                    <div className="admin-empty-state">
                      <h3>No counseling requests yet</h3>
                      <p>Add a student-facing counseling request flow later and this section will populate automatically.</p>
                    </div>
                  )}
                  {suggestedCounseling.map((request) => (
                    <article key={request.id} className="admin-request-card">
                      <span>{request.priority || "Normal priority"}</span>
                      <h3>{request.full_name || request.student_name || "Student request"}</h3>
                      <p>{request.topic || request.message || "Student is waiting for counseling support."}</p>
                      <strong>{request.email || request.contact_email || "No email provided"}</strong>
                    </article>
                  ))}
                </div>
              </article>
            </section>
          )}
        </div>
      </div>
      <Footer />
    </>
  );
}
