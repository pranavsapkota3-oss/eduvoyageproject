import { useEffect, useMemo, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const ITEMS_PER_PAGE = 8;

const navItems = [
  { key: "overview", label: "Overview" },
  { key: "users", label: "Users" },
  { key: "universities", label: "Universities" },
  { key: "applications", label: "Applications" },
  { key: "documents", label: "Documents" },
  { key: "counseling", label: "Counseling Requests" },
];

const COUNTRY_OPTIONS = [
  "United States",
  "United Kingdom",
  "Canada",
  "Australia",
  "New Zealand",
  "Germany",
  "Japan",
  "Singapore",
  "Nepal",
  "India",
];

function paginate(items, page, perPage = ITEMS_PER_PAGE) {
  const start = (page - 1) * perPage;
  return items.slice(start, start + perPage);
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

function parseChangedFields(value) {
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export default function AgentDashboard() {
  const location = useLocation();
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
  const [applications, setApplications] = useState([]);
  const [documents, setDocuments] = useState([]);
  const [counselingRequests, setCounselingRequests] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [documentCommentDrafts, setDocumentCommentDrafts] = useState({});
  const [applicationNoteDrafts, setApplicationNoteDrafts] = useState({});
  const [counselingPriorityDrafts, setCounselingPriorityDrafts] = useState({});

  const [userSearch, setUserSearch] = useState("");
  const [userRoleFilter, setUserRoleFilter] = useState("");
  const [userStatusFilter, setUserStatusFilter] = useState("");
  const [userPage, setUserPage] = useState(1);

  const [uniSearch, setUniSearch] = useState("");
  const [uniCountryFilter, setUniCountryFilter] = useState("");
  const [uniWorkflowFilter, setUniWorkflowFilter] = useState("all");
  const [uniPage, setUniPage] = useState(1);

  const [docSearch, setDocSearch] = useState("");
  const [docReviewFilter, setDocReviewFilter] = useState("");
  const [docPage, setDocPage] = useState(1);

  const [applicationSearch, setApplicationSearch] = useState("");
  const [applicationStatusFilter, setApplicationStatusFilter] = useState("");
  const [applicationPage, setApplicationPage] = useState(1);

  const [counselingSearch, setCounselingSearch] = useState("");
  const [counselingFilter, setCounselingFilter] = useState("");
  const [counselingPage, setCounselingPage] = useState(1);

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
  const [uniMinIelts, setUniMinIelts] = useState("");
  const [uniMinSat, setUniMinSat] = useState("");
  const [uniScholarshipName, setUniScholarshipName] = useState("");
  const [uniScholarshipAmount, setUniScholarshipAmount] = useState("");
  const [uniScholarshipType, setUniScholarshipType] = useState("fixed_amount");
  const [uniScholarshipEligibilityNote, setUniScholarshipEligibilityNote] = useState("");

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
    setUniMinIelts("");
    setUniMinSat("");
    setUniScholarshipName("");
    setUniScholarshipAmount("");
    setUniScholarshipType("fixed_amount");
    setUniScholarshipEligibilityNote("");
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
      if (res.ok) {
        setDocuments(data.documents || []);
        setDocumentCommentDrafts((prev) => {
          const next = { ...prev };
          (data.documents || []).forEach((doc) => {
            next[doc.id] = prev[doc.id] ?? doc.review_comment ?? "";
          });
          return next;
        });
      }
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
      if (res.ok) {
        setApplications(data.applications || []);
        setApplicationNoteDrafts((prev) => {
          const next = { ...prev };
          (data.applications || []).forEach((application) => {
            next[application.id] = prev[application.id] ?? application.notes ?? "";
          });
          return next;
        });
      }
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
      if (res.ok) {
        setCounselingRequests(data.requests || []);
        setCounselingPriorityDrafts((prev) => {
          const next = { ...prev };
          (data.requests || []).forEach((request) => {
            next[request.id] = prev[request.id] ?? request.priority ?? "normal";
          });
          return next;
        });
      }
    } catch {
      setCounselingRequests([]);
    }
  };

  const loadAuditLogs = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/agent/university-audit?limit=24", {
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (res.ok) setAuditLogs(data.logs || []);
    } catch {
      setAuditLogs([]);
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
        loadApplications(),
        loadDocuments(),
        loadCounselingRequests(),
        loadAuditLogs(),
      ]);
      setLoading(false);
    };
    init();
  }, []);

  useEffect(() => {
    if (!location.state?.adminStatus) return;
    setStatus(location.state.adminStatus);
    if (location.state.adminSection) {
      setActiveSection(location.state.adminSection);
    }
    window.history.replaceState({}, document.title);
  }, [location.state]);

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
    const activeApplications = applications.filter((application) => !["accepted", "rejected", "stopped applying"].includes(application.status || "")).length;
    return [
      { title: "University content cleanup", subtitle: `${missingContent} profiles need stronger academic content`, target: "universities", action: "Open universities" },
      { title: "Missing tuition data", subtitle: `${missingFees} universities still need fees`, target: "universities", action: "Fix tuition data" },
      { title: "Applications pipeline", subtitle: `${activeApplications} applications still need review or follow-up`, target: "applications", action: "Open applications" },
      { title: "Document review queue", subtitle: `${documents.filter((doc) => (doc.review_status || "pending") === "pending").length} uploaded documents are waiting`, target: "documents", action: "Open documents" },
      { title: "Counseling queue", subtitle: `${counselingRequests.length} requests are waiting for follow-up`, target: "counseling", action: "Open counseling" },
      { title: "Image coverage", subtitle: `${missingImage} universities need a hero image`, target: "universities", action: "Update images" },
    ];
  }, [applications, counselingRequests.length, documents, universities]);

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
    const reviewLabel = doc.review_status || "pending";
    const matchesSearch = !docSearch || `${doc.full_name} ${doc.email} ${doc.file_name} ${reviewLabel}`.toLowerCase().includes(docSearch.toLowerCase());
    const matchesReview = !docReviewFilter || reviewLabel === docReviewFilter;
    return matchesSearch && matchesReview;
  }), [docReviewFilter, docSearch, documents]);

  const filteredApplications = useMemo(() => applications.filter((application) => {
    const currentStatus = application.status || "shortlisted";
    const haystack = `${getApplicationLabel(application)} ${getApplicantLabel(application)} ${application.email || ""} ${currentStatus}`.toLowerCase();
    const matchesSearch = !applicationSearch || haystack.includes(applicationSearch.toLowerCase());
    const matchesStatus = !applicationStatusFilter || currentStatus === applicationStatusFilter;
    return matchesSearch && matchesStatus;
  }), [applicationSearch, applicationStatusFilter, applications]);

  const filteredCounselingRequests = useMemo(() => counselingRequests.filter((request) => {
    const localStatus = request.status || "pending";
    const haystack = `${request.full_name || ""} ${request.email || ""} ${request.topic || ""} ${localStatus}`.toLowerCase();
    const matchesSearch = !counselingSearch || haystack.includes(counselingSearch.toLowerCase());
    const matchesStatus = !counselingFilter || localStatus === counselingFilter;
    return matchesSearch && matchesStatus;
  }), [counselingFilter, counselingRequests, counselingSearch]);

  const pagedUsers = paginate(filteredUsers, userPage);
  const pagedUniversities = paginate(filteredUniversities, uniPage);
  const pagedDocuments = paginate(filteredDocuments, docPage);
  const pagedApplications = paginate(filteredApplications, applicationPage);
  const pagedCounselingRequests = paginate(filteredCounselingRequests, counselingPage);

  const setDocumentReview = async (docId, nextStatus) => {
    try {
      const comment = documentCommentDrafts[docId] || "";
      const res = await fetch(`http://localhost:5000/api/admin/documents/${docId}/review`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ status: nextStatus.toLowerCase(), comment }),
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to update document review.");
      setDocuments((prev) => prev.map((doc) => (doc.id === docId ? data.document : doc)));
      setDocumentCommentDrafts((prev) => ({
        ...prev,
        [docId]: data.document?.review_comment ?? comment,
      }));
      setStatus(`Document marked as ${nextStatus.toLowerCase()}.`);
      loadSummary();
    } catch {
      setStatus("Failed to update document review.");
    }
  };

  const updateCounselingRequest = async (requestId, nextStatus, nextPriority) => {
    try {
      const res = await fetch(`http://localhost:5000/api/admin/counseling-requests/${requestId}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ status: nextStatus, priority: nextPriority }),
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to update counseling request.");
      setCounselingRequests((prev) => prev.map((request) => (request.id === requestId ? data.request : request)));
      setCounselingPriorityDrafts((prev) => ({
        ...prev,
        [requestId]: data.request?.priority || nextPriority,
      }));
      setStatus("Counseling request updated.");
      loadSummary();
    } catch {
      setStatus("Failed to update counseling request.");
    }
  };

  const updateApplicationStatus = async (applicationId, nextStatus) => {
    try {
      const notes = applicationNoteDrafts[applicationId] || "";
      const res = await fetch(`http://localhost:5000/api/admin/applications/${applicationId}/status`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ status: nextStatus, notes }),
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to update application.");
      setApplications((prev) => prev.map((application) => (application.id === applicationId ? data.application : application)));
      setApplicationNoteDrafts((prev) => ({
        ...prev,
        [applicationId]: data.application?.notes ?? notes,
      }));
      setStatus("Application workflow updated.");
      loadSummary();
    } catch {
      setStatus("Failed to update application.");
    }
  };

  const openAdminDocument = async (downloadUrl, fileName = "document") => {
    try {
      const res = await fetch(`http://localhost:5000${downloadUrl}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        setStatus(data.message || "Could not open document.");
        return;
      }

      const blob = await res.blob();
      const objectUrl = window.URL.createObjectURL(blob);
      window.open(objectUrl, "_blank", "noopener,noreferrer");
      window.setTimeout(() => window.URL.revokeObjectURL(objectUrl), 60000);
    } catch {
      setStatus(`Could not open ${fileName}.`);
    }
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
    setUniMinIelts(uni.min_ielts_score || "");
    setUniMinSat(uni.min_sat_score || "");
    setUniScholarshipName(uni.scholarship_name || "");
    setUniScholarshipAmount(uni.scholarship_amount || "");
    setUniScholarshipType(uni.scholarship_type || "fixed_amount");
    setUniScholarshipEligibilityNote(uni.scholarship_eligibility_note || "");
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
          min_ielts_score: uniMinIelts,
          min_sat_score: uniMinSat,
          scholarship_name: uniScholarshipName,
          scholarship_amount: uniScholarshipAmount,
          scholarship_type: uniScholarshipType,
          scholarship_eligibility_note: uniScholarshipEligibilityNote,
        }),
      });
      const data = await res.json();
      if (!res.ok) return setStatus(data.message || "Failed to save university.");
      setStatus(editingUniId ? "University updated." : "University added.");
      resetUniversityForm();
      loadUniversities();
      loadAuditLogs();
      loadSummary();
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
      loadAuditLogs();
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
                <span className="admin-nav__label">{item.label}</span>
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

          {loading && (
            <section className="admin-shell">
              <article className="app-state-card app-state-card--loading">
                <div className="app-skeleton app-skeleton--title" />
                <div className="app-skeleton app-skeleton--line" />
                <div className="app-skeleton app-skeleton--line short" />
                <div className="admin-summary-grid">
                  {[1, 2, 3, 4].map((item) => (
                    <div key={item} className="app-skeleton app-skeleton--block" />
                  ))}
                </div>
              </article>
            </section>
          )}

          {!loading && (
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
                <span>Applications</span>
                <strong>{summary.applications_submitted}</strong>
                <p>Student application records currently tracked in the pipeline.</p>
              </article>
            </section>
          )}

          {!loading && activeSection === "overview" && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Workflow</p>
                    <h2>Today's management priorities</h2>
                    <p className="admin-panel__hint">Use these shortcuts to move directly into the queue that needs attention first.</p>
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
                  <div className="admin-overview-card"><h3>Document queue</h3><p>{documents.length ? `${documents.filter((doc) => (doc.review_status || "pending") === "pending").length} files are waiting for review.` : "No new uploads in the review queue."}</p></div>
                  <div className="admin-overview-card"><h3>Counseling queue</h3><p>{counselingRequests.length ? `${counselingRequests.length} student requests are waiting for follow-up.` : "No counseling requests are waiting right now."}</p></div>
                  <div className="admin-overview-card"><h3>Application pipeline</h3><p>{applications.length ? `${applications.filter((application) => !["accepted", "rejected", "stopped applying"].includes(application.status || "")).length} applications still need action or follow-up.` : "No student applications are being tracked yet."}</p></div>
                  <div className="admin-overview-card"><h3>Editing activity</h3><p>{auditLogs.length ? `${auditLogs.length} recent university changes were recorded.` : "No recent university edits have been recorded."}</p></div>
                </div>
              </article>
            </section>
          )}

          {!loading && activeSection === "applications" && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Application workflow</p>
                    <h2>Applications</h2>
                    <p className="admin-panel__hint">Review new university applications, move them through the pipeline, and leave follow-up notes for the student journey.</p>
                  </div>
                  <div className="admin-toolbar">
                    <div className="admin-toolbar__group">
                      <input type="text" placeholder="Search student or university" value={applicationSearch} onChange={(e) => { setApplicationSearch(e.target.value); setApplicationPage(1); }} />
                      <select value={applicationStatusFilter} onChange={(e) => { setApplicationStatusFilter(e.target.value); setApplicationPage(1); }}>
                        <option value="">All statuses</option>
                        <option value="shortlisted">Shortlisted</option>
                        <option value="applying">Applying</option>
                        <option value="submitted">Submitted</option>
                        <option value="offer received">Offer received</option>
                        <option value="accepted">Accepted</option>
                        <option value="rejected">Rejected</option>
                        <option value="stopped applying">Stopped applying</option>
                      </select>
                    </div>
                    <div className="admin-toolbar__meta">{filteredApplications.length} applications</div>
                  </div>
                </div>

                <div className="admin-overview-grid admin-overview-grid--applications">
                  <div className="admin-overview-card"><h3>Needs review</h3><p>{applications.filter((application) => ["shortlisted", "applying"].includes(application.status || "")).length} applications are still early in the pipeline.</p></div>
                  <div className="admin-overview-card"><h3>Submitted</h3><p>{applications.filter((application) => (application.status || "") === "submitted").length} applications have been sent and are waiting for a result.</p></div>
                  <div className="admin-overview-card"><h3>Offers</h3><p>{applications.filter((application) => (application.status || "") === "offer received").length} students currently have an offer to review.</p></div>
                  <div className="admin-overview-card"><h3>Decisions</h3><p>{applications.filter((application) => ["accepted", "rejected", "stopped applying"].includes(application.status || "")).length} applications already reached a final outcome.</p></div>
                </div>

                <div className="admin-data-table">
                  <table>
                    <thead><tr><th>Student</th><th>University</th><th>Started</th><th>Status</th><th>Follow-up</th><th>Actions</th></tr></thead>
                    <tbody>
                      {pagedApplications.length === 0 && <tr><td colSpan="6">No applications match the current filters.</td></tr>}
                      {pagedApplications.map((application) => (
                        <tr key={application.id}>
                          <td>
                            <strong>{getApplicantLabel(application)}</strong>
                            <div>{application.email || "-"}</div>
                          </td>
                          <td>
                            <strong>{getApplicationLabel(application)}</strong>
                            <div className="admin-table-note">{application.university_city || "-"}{application.university_city && application.university_country ? ", " : ""}{application.university_country || ""}</div>
                          </td>
                          <td>{getApplicationDate(application)}</td>
                          <td>
                            <span className={`tag ${application.status === "accepted" ? "tag--active" : application.status === "rejected" ? "tag--inactive" : application.status === "offer received" ? "tag--offer" : application.status === "stopped applying" ? "tag--stopped" : ""}`}>
                              {application.status || "shortlisted"}
                            </span>
                            {application.submitted_at && <div className="admin-table-note">Submitted {application.submitted_at.slice(0, 10)}</div>}
                            <div className="admin-table-note">Source: {application.source || "student_portal"}</div>
                          </td>
                          <td>
                            <textarea
                              className="admin-inline-textarea"
                              placeholder="Add next-step note"
                              value={applicationNoteDrafts[application.id] ?? application.notes ?? ""}
                              onChange={(e) => setApplicationNoteDrafts((prev) => ({ ...prev, [application.id]: e.target.value }))}
                            />
                          </td>
                          <td className="admin-actions admin-actions--stack">
                            <button type="button" className="agent-btn agent-btn--ghost" onClick={() => updateApplicationStatus(application.id, "shortlisted")}>Shortlist</button>
                            <button type="button" className="agent-btn agent-btn--ghost" onClick={() => updateApplicationStatus(application.id, "applying")}>Applying</button>
                            <button type="button" className="agent-btn agent-btn--ghost" onClick={() => updateApplicationStatus(application.id, "submitted")}>Submitted</button>
                            <button type="button" className="agent-btn agent-btn--ghost" onClick={() => updateApplicationStatus(application.id, "offer received")}>Offer</button>
                            <button type="button" className="agent-btn" onClick={() => updateApplicationStatus(application.id, "accepted")}>Accept</button>
                            <button type="button" className="agent-btn agent-btn--danger" onClick={() => updateApplicationStatus(application.id, "rejected")}>Reject</button>
                            <button type="button" className="agent-btn agent-btn--ghost" onClick={() => updateApplicationStatus(application.id, "stopped applying")}>Stopped</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {!filteredApplications.length && (
                  <div className="admin-empty-state">
                    <h3>No applications yet</h3>
                    <p>Once students click Apply Now from a university page, the application pipeline will appear here for review and follow-up.</p>
                  </div>
                )}

                <div className="admin-pagination">
                  <button type="button" disabled={applicationPage === 1} onClick={() => setApplicationPage((page) => Math.max(1, page - 1))}>Prev</button>
                  <span>Page {applicationPage}</span>
                  <button type="button" disabled={applicationPage * ITEMS_PER_PAGE >= filteredApplications.length} onClick={() => setApplicationPage((page) => page + 1)}>Next</button>
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
                    <div className="admin-toolbar__group">
                      <input type="text" placeholder="Search name or email" value={userSearch} onChange={(e) => { setUserSearch(e.target.value); setUserPage(1); }} />
                      <select value={userRoleFilter} onChange={(e) => { setUserRoleFilter(e.target.value); setUserPage(1); }}>
                        <option value="">All roles</option><option value="student">Student</option><option value="agent">Agent</option><option value="admin">Admin</option>
                      </select>
                      <select value={userStatusFilter} onChange={(e) => { setUserStatusFilter(e.target.value); setUserPage(1); }}>
                        <option value="">All status</option><option value="1">Active</option><option value="0">Inactive</option>
                      </select>
                    </div>
                    <div className="admin-toolbar__meta">{filteredUsers.length} users</div>
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
                    <p className="admin-panel__hint">Keep the dashboard focused on search and review, then open the dedicated editor only when you need to publish or update a university profile.</p>
                  </div>
                  <div className="admin-toolbar">
                    <div className="admin-toolbar__group">
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
                    <div className="admin-toolbar__meta">{filteredUniversities.length} universities</div>
                  </div>
                </div>
                <div className="admin-university-shell">
                  <aside className="admin-editor-launcher">
                    <div className="admin-editor-launcher__card">
                      <span className="admin-panel__eyebrow">University editor</span>
                      <h3>Open a focused publishing page</h3>
                      <p>
                        The full university form now lives in a dedicated editor page so this dashboard can stay clean for filtering, tracking, and action queues.
                      </p>
                      <div className="admin-editor-launcher__actions">
                        <Link to="/agent/universities/new" className="agent-btn admin-editor-launcher__primary">
                          Add new university
                        </Link>
                      </div>
                    </div>
                    <div className="admin-editor-launcher__tips">
                      <strong>Why this is better</strong>
                      <ul>
                        <li>Less clutter on the dashboard</li>
                        <li>Clearer search and workflow review</li>
                        <li>Dedicated page for long-form content editing</li>
                      </ul>
                    </div>
                  </aside>
                  <div className="admin-university-content">
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
                                  <Link to={`/agent/universities/${uni.id}/edit`} className="agent-btn agent-btn--ghost">Edit</Link>
                                  <Link to={`/universities/${uni.id}`} className="agent-btn agent-btn--ghost">View</Link>
                                  {canManageUsers && <button type="button" className="agent-btn agent-btn--danger" onClick={() => handleDeleteUniversity(uni.id)}>Delete</button>}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>

                    <aside className="admin-activity-panel">
                      <div className="admin-activity-panel__header">
                        <span className="admin-panel__eyebrow">Edit tracking</span>
                        <h3>Recent university changes</h3>
                      </div>
                      <div className="admin-activity-list">
                        {auditLogs.length === 0 && <p className="admin-panel__hint">No university edits have been recorded yet.</p>}
                        {auditLogs.map((log) => (
                          <article key={log.id} className="admin-activity-item">
                            <strong>{log.university_name}</strong>
                            <span>{log.action} by {log.editor_name}</span>
                            <p>{parseChangedFields(log.changed_fields).slice(0, 4).join(", ") || "Structure change"}</p>
                            <em>{log.created_at?.slice?.(0, 16)?.replace("T", " ") || "-"}</em>
                          </article>
                        ))}
                      </div>
                    </aside>
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
                    <p className="admin-panel__hint">Review uploaded files and keep the student documentation pipeline moving.</p>
                  </div>
                  <div className="admin-toolbar">
                    <div className="admin-toolbar__group">
                      <input type="text" placeholder="Search student, email, or file name" value={docSearch} onChange={(e) => { setDocSearch(e.target.value); setDocPage(1); }} />
                      <select value={docReviewFilter} onChange={(e) => { setDocReviewFilter(e.target.value); setDocPage(1); }}>
                        <option value="">All reviews</option>
                        <option value="pending">Pending</option>
                        <option value="approved">Approved</option>
                        <option value="rejected">Rejected</option>
                      </select>
                    </div>
                    <div className="admin-toolbar__meta">{filteredDocuments.length} documents</div>
                  </div>
                </div>
                <div className="admin-data-table">
                  <table>
                    <thead><tr><th>Student</th><th>Document</th><th>Uploaded</th><th>Review status</th><th>Actions</th></tr></thead>
                    <tbody>
                      {pagedDocuments.length === 0 && <tr><td colSpan="5">No documents found in the current queue.</td></tr>}
                      {pagedDocuments.map((doc) => {
                        const reviewStatus = (doc.review_status || "pending").toLowerCase();
                        return (
                          <tr key={doc.id}>
                            <td><strong>{doc.full_name}</strong><div>{doc.email}</div></td>
                            <td><strong>{doc.file_name}</strong><div>{doc.file_size || "-"}</div></td>
                            <td>{doc.created_at?.slice?.(0, 10) || "-"}</td>
                            <td>
                              <span className={`tag ${reviewStatus === "approved" ? "tag--active" : reviewStatus === "rejected" ? "tag--inactive" : ""}`}>
                                {reviewStatus}
                              </span>
                              {doc.reviewer_name && <div className="admin-table-note">By {doc.reviewer_name}</div>}
                              {doc.review_comment && <div className="admin-table-note">{doc.review_comment}</div>}
                            </td>
                            <td className="admin-actions admin-actions--stack">
                              {doc.download_url && (
                                <button
                                  type="button"
                                  className="agent-btn agent-btn--ghost"
                                  onClick={() => openAdminDocument(doc.download_url, doc.file_name)}
                                >
                                  Open
                                </button>
                              )}
                              <textarea
                                className="admin-inline-textarea"
                                placeholder="Add review comment"
                                value={documentCommentDrafts[doc.id] ?? doc.review_comment ?? ""}
                                onChange={(e) => setDocumentCommentDrafts((prev) => ({ ...prev, [doc.id]: e.target.value }))}
                              />
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

          {!loading && activeSection === "counseling" && (
            <section className="admin-shell">
              <article className="admin-panel admin-panel--wide">
                <div className="admin-panel__header">
                  <div>
                    <p className="admin-panel__eyebrow">Student support</p>
                    <h2>Counseling requests</h2>
                    <p className="admin-panel__hint">Students submit these from Services. Use this queue to follow up on advising and planning requests.</p>
                  </div>
                  <div className="admin-toolbar">
                    <div className="admin-toolbar__group">
                      <input type="text" placeholder="Search student or topic" value={counselingSearch} onChange={(e) => { setCounselingSearch(e.target.value); setCounselingPage(1); }} />
                      <select value={counselingFilter} onChange={(e) => { setCounselingFilter(e.target.value); setCounselingPage(1); }}>
                        <option value="">All statuses</option>
                        <option value="pending">Pending</option>
                        <option value="in progress">In progress</option>
                        <option value="resolved">Resolved</option>
                      </select>
                    </div>
                    <div className="admin-toolbar__meta">{filteredCounselingRequests.length} requests</div>
                  </div>
                </div>
                <div className="admin-data-table">
                  <table>
                    <thead><tr><th>Student</th><th>Topic</th><th>Date</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody>
                      {pagedCounselingRequests.length === 0 && <tr><td colSpan="5">No counseling requests match the current filters.</td></tr>}
                      {pagedCounselingRequests.map((request) => {
                        const currentStatus = request.status || "pending";
                        const statusClass = currentStatus === "resolved"
                          ? "tag tag--active"
                          : currentStatus === "pending"
                            ? "tag tag--inactive"
                            : "tag";
                        return (
                          <tr key={request.id}>
                            <td>
                              <strong>{request.full_name || "Student request"}</strong>
                              <div>{request.email || ""}</div>
                            </td>
                            <td>
                              <strong>{request.topic || "-"}</strong>
                              <div className="admin-table-note">{request.preferred_country || "Country not specified"}</div>
                              <div className="admin-table-note">{request.message || "No details provided."}</div>
                            </td>
                            <td>{request.created_at?.slice?.(0, 10) || "-"}</td>
                            <td>
                              <span className={statusClass}>{currentStatus}</span>
                              <div className="admin-table-note">Priority: {request.priority || "normal"}</div>
                            </td>
                            <td className="admin-actions admin-actions--wrap">
                              <select
                                value={counselingPriorityDrafts[request.id] || request.priority || "normal"}
                                onChange={(event) => setCounselingPriorityDrafts((prev) => ({
                                  ...prev,
                                  [request.id]: event.target.value,
                                }))}
                              >
                                <option value="low">Low</option>
                                <option value="normal">Normal</option>
                                <option value="high">High</option>
                              </select>
                              {["pending", "in progress", "resolved"].map((nextStatus) => (
                                <button
                                  key={nextStatus}
                                  type="button"
                                  className="agent-btn agent-btn--ghost"
                                  onClick={() =>
                                    updateCounselingRequest(
                                      request.id,
                                      nextStatus,
                                      counselingPriorityDrafts[request.id] || request.priority || "normal"
                                    )
                                  }
                                >
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
                {!filteredCounselingRequests.length && (
                  <div className="admin-empty-state">
                    <h3>No counseling requests yet</h3>
                    <p>Students can submit a counseling request from the Services page and it will appear here.</p>
                  </div>
                )}
                <div className="admin-pagination">
                  <button type="button" disabled={counselingPage === 1} onClick={() => setCounselingPage((page) => Math.max(1, page - 1))}>Prev</button>
                  <span>Page {counselingPage}</span>
                  <button type="button" disabled={counselingPage * ITEMS_PER_PAGE >= filteredCounselingRequests.length} onClick={() => setCounselingPage((page) => page + 1)}>Next</button>
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
