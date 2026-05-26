import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

const API_URL = "http://localhost:5000";

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

const INITIAL_FORM = {
  name: "",
  country: "",
  city: "",
  ranking: "",
  website: "",
  image_url: "",
  location: "",
  contact: "",
  scholarship_name: "",
  scholarship_amount: "",
  scholarship_type: "fixed_amount",
  min_ielts_score: "",
  min_sat_score: "",
  scholarship_eligibility_note: "",
  overview: "",
  courses: "",
  fees: "",
  facilities: "",
  scholarships: "",
  admissions: "",
};

function mapUniversityToForm(university) {
  return {
    name: university?.name || "",
    country: university?.country || "",
    city: university?.city || "",
    ranking: university?.ranking || "",
    website: university?.website || "",
    image_url: university?.image_url || "",
    location: university?.location || "",
    contact: university?.contact || "",
    scholarship_name: university?.scholarship_name || "",
    scholarship_amount: university?.scholarship_amount || "",
    scholarship_type: university?.scholarship_type || "fixed_amount",
    min_ielts_score: university?.min_ielts_score || "",
    min_sat_score: university?.min_sat_score || "",
    scholarship_eligibility_note: university?.scholarship_eligibility_note || "",
    overview: university?.overview || "",
    courses: university?.courses || "",
    fees: university?.fees || "",
    facilities: university?.facilities || "",
    scholarships: university?.scholarships || "",
    admissions: university?.admissions || "",
  };
}

export default function AgentUniversityEditor() {
  const token = localStorage.getItem("token");
  const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
  const { id } = useParams();
  const navigate = useNavigate();
  const isEditing = Boolean(id);

  const [loading, setLoading] = useState(isEditing);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState("");
  const [universities, setUniversities] = useState([]);
  const [form, setForm] = useState(INITIAL_FORM);

  useEffect(() => {
    if (!token || !currentUser.role || (currentUser.role !== "admin" && currentUser.role !== "agent")) {
      navigate("/login");
      return;
    }
  }, [currentUser.role, navigate, token]);

  useEffect(() => {
    const loadContext = async () => {
      try {
        const listRes = await fetch(`${API_URL}/api/universities?page=1&limit=200`);
        const listData = await listRes.json();
        if (listRes.ok) {
          setUniversities(listData.universities || []);
        }
      } catch {
        setUniversities([]);
      }

      if (!isEditing) {
        setLoading(false);
        return;
      }

      try {
        const res = await fetch(`${API_URL}/api/universities/${id}`);
        const data = await res.json();
        if (!res.ok) {
          setStatus(data.message || "Failed to load university details.");
          return;
        }
        setForm(mapUniversityToForm(data.university));
      } catch {
        setStatus("Failed to load university details.");
      } finally {
        setLoading(false);
      }
    };

    loadContext();
  }, [id, isEditing]);

  const existingOptions = useMemo(() => {
    const unique = (key) => [...new Set(universities.map((u) => u[key]).filter(Boolean))].slice(0, 120);
    return {
      names: unique("name"),
      cities: unique("city"),
      websites: unique("website"),
      locations: unique("location"),
      contacts: unique("contact"),
      images: unique("image_url"),
    };
  }, [universities]);

  const updateField = (key, value) => {
    setForm((prev) => ({ ...prev, [key]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!form.name || !form.country) {
      setStatus("University name and country are required.");
      return;
    }

    try {
      setSaving(true);
      const endpoint = isEditing
        ? `${API_URL}/api/agent/universities/${id}`
        : `${API_URL}/api/agent/universities`;
      const method = isEditing ? "PATCH" : "POST";
      const res = await fetch(endpoint, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          ...form,
          ranking: form.ranking ? Number(form.ranking) : null,
          scholarship_amount: form.scholarship_amount === "" ? null : form.scholarship_amount,
          min_ielts_score: form.min_ielts_score === "" ? null : form.min_ielts_score,
          min_sat_score: form.min_sat_score === "" ? null : form.min_sat_score,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus(data.message || "Failed to save university.");
        return;
      }
      navigate("/agent", {
        state: {
          adminStatus: isEditing ? "University updated." : "University added.",
          adminSection: "universities",
        },
      });
    } catch {
      setStatus("Failed to save university.");
    } finally {
      setSaving(false);
    }
  };

  if (!currentUser.role || (currentUser.role !== "admin" && currentUser.role !== "agent")) {
    return null;
  }

  return (
    <main className="admin-editor-page">
      <section className="admin-editor-shell">
        <header className="admin-editor-hero">
          <div>
            <p className="admin-panel__eyebrow">Publishing workflow</p>
            <h1>{isEditing ? "Edit University Profile" : "Add University Profile"}</h1>
            <p className="admin-editor-hero__copy">
              Keep the public university page clean by editing content, scholarship rules, and page media in a focused workspace.
            </p>
          </div>
          <div className="admin-editor-hero__actions">
            <Link to="/agent" className="agent-btn agent-btn--ghost admin-editor-link">
              Back to dashboard
            </Link>
            <Link to="/agent" className="agent-btn agent-btn--ghost admin-editor-link">
              View list
            </Link>
          </div>
        </header>

        {status && <p className="admin-status">{status}</p>}

        {loading ? (
          <article className="admin-panel admin-panel--wide">
            <p className="admin-panel__hint">Loading university editor...</p>
          </article>
        ) : (
          <form className="admin-form admin-form--dashboard admin-editor-form" onSubmit={handleSubmit}>
            <div className="admin-form__section-title">University profile editor</div>

            <div className="admin-form__section">
              <div className="admin-form__subhead">
                <strong>Basic information</strong>
                <p>Core public details used across the directory and detail page.</p>
              </div>
              <div className="admin-form__grid admin-form__grid--two">
                <input type="text" placeholder="University name" value={form.name} onChange={(e) => updateField("name", e.target.value)} list="uni-name-list" />
                <select value={form.country} onChange={(e) => updateField("country", e.target.value)}>
                  <option value="" disabled>Select country</option>
                  {COUNTRY_OPTIONS.map((country) => (
                    <option key={country} value={country}>
                      {country}
                    </option>
                  ))}
                </select>
                <input type="text" placeholder="City" value={form.city} onChange={(e) => updateField("city", e.target.value)} list="uni-city-list" />
                <input type="number" placeholder="Ranking" value={form.ranking} onChange={(e) => updateField("ranking", e.target.value)} />
              </div>
            </div>

            <div className="admin-form__section">
              <div className="admin-form__subhead">
                <strong>Contact and page media</strong>
                <p>Links and supporting details used in the sidebar and hero area.</p>
              </div>
              <div className="admin-form__grid admin-form__grid--two">
                <input type="text" placeholder="Website" value={form.website} onChange={(e) => updateField("website", e.target.value)} list="uni-website-list" />
                <input type="text" placeholder="Image URL" value={form.image_url} onChange={(e) => updateField("image_url", e.target.value)} list="uni-image-list" />
                <input type="text" placeholder="Location" value={form.location} onChange={(e) => updateField("location", e.target.value)} list="uni-location-list" />
                <input type="text" placeholder="Contact" value={form.contact} onChange={(e) => updateField("contact", e.target.value)} list="uni-contact-list" />
              </div>
            </div>

            <div className="admin-form__section">
              <div className="admin-form__subhead">
                <strong>Scholarship settings</strong>
                <p>Define what the student sees on scholarship pages and the matching rules used by the system.</p>
              </div>
              <div className="admin-form__grid admin-form__grid--two">
                <input type="text" placeholder="Scholarship name" value={form.scholarship_name} onChange={(e) => updateField("scholarship_name", e.target.value)} />
                <input type="number" min="0" step="0.01" placeholder="Scholarship amount" value={form.scholarship_amount} onChange={(e) => updateField("scholarship_amount", e.target.value)} />
                <select value={form.scholarship_type} onChange={(e) => updateField("scholarship_type", e.target.value)}>
                  <option value="fixed_amount">Fixed amount</option>
                  <option value="percentage_waiver">Percentage waiver</option>
                  <option value="full_tuition">Full tuition</option>
                </select>
                <input type="number" step="0.5" min="0" max="9" placeholder="Minimum IELTS for scholarship" value={form.min_ielts_score} onChange={(e) => updateField("min_ielts_score", e.target.value)} />
                <input type="number" min="400" max="1600" placeholder="Minimum SAT for scholarship" value={form.min_sat_score} onChange={(e) => updateField("min_sat_score", e.target.value)} />
                <textarea
                  className="admin-form__field admin-form__field--wide"
                  placeholder="Scholarship eligibility note (optional)"
                  value={form.scholarship_eligibility_note}
                  onChange={(e) => updateField("scholarship_eligibility_note", e.target.value)}
                />
              </div>
            </div>

            <div className="admin-form__section">
              <div className="admin-form__subhead">
                <strong>Content sections</strong>
                <p>These fields drive the public university detail page content.</p>
              </div>
              <div className="admin-form__grid admin-form__grid--stack">
                <textarea placeholder="Overview" value={form.overview} onChange={(e) => updateField("overview", e.target.value)} />
                <textarea placeholder="Courses" value={form.courses} onChange={(e) => updateField("courses", e.target.value)} />
                <textarea placeholder="Fees" value={form.fees} onChange={(e) => updateField("fees", e.target.value)} />
                <textarea placeholder="Facilities" value={form.facilities} onChange={(e) => updateField("facilities", e.target.value)} />
                <textarea placeholder="Scholarships" value={form.scholarships} onChange={(e) => updateField("scholarships", e.target.value)} />
                <textarea placeholder="Admissions" value={form.admissions} onChange={(e) => updateField("admissions", e.target.value)} />
              </div>
            </div>

            <div className="admin-form__actions">
              <button type="submit" disabled={saving}>{saving ? "Saving..." : isEditing ? "Save changes" : "Add university"}</button>
              <button type="button" className="admin-form__cancel-btn" onClick={() => navigate("/agent")}>Cancel</button>
            </div>

            <datalist id="uni-name-list">{existingOptions.names.map((item) => <option key={item} value={item} />)}</datalist>
            <datalist id="uni-city-list">{existingOptions.cities.map((item) => <option key={item} value={item} />)}</datalist>
            <datalist id="uni-website-list">{existingOptions.websites.map((item) => <option key={item} value={item} />)}</datalist>
            <datalist id="uni-location-list">{existingOptions.locations.map((item) => <option key={item} value={item} />)}</datalist>
            <datalist id="uni-contact-list">{existingOptions.contacts.map((item) => <option key={item} value={item} />)}</datalist>
            <datalist id="uni-image-list">{existingOptions.images.map((item) => <option key={item} value={item} />)}</datalist>
          </form>
        )}
      </section>
    </main>
  );
}
