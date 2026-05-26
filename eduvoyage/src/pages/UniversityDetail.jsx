import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { getUniversityApplyUrl, getUniversityWebsiteUrl } from "../utils/universityLinks";

const APPLICATION_STORAGE_KEY = "university_application_flow_v1";
const detailSections = [
  { key: "overview", label: "Overview" },
  { key: "courses", label: "Courses" },
  { key: "tuitionLiving", label: "Tuition & Living Cost" },
  { key: "scholarships", label: "Scholarships" },
  { key: "admissions", label: "Admissions Requirements" },
  { key: "deadlines", label: "Deadlines & Intakes" },
  { key: "contactLocation", label: "Contact & Location" },
];
const editableSections = new Set(["overview", "courses", "scholarships", "admissions"]);

const countryIntakes = {
  USA: { intake: "Fall / Spring", deadline: "Most applications open from November to March." },
  UK: { intake: "September / January", deadline: "Most intakes close between January and June." },
  Canada: { intake: "Fall / Winter / Summer", deadline: "Main deadlines usually run from January to May." },
  Australia: { intake: "February / July", deadline: "Applications commonly close 3 to 6 months before intake." },
};

const livingCostGuide = {
  USA: "Estimated living cost: USD 1,400 to 2,500 per month depending on city and housing type.",
  UK: "Estimated living cost: GBP 1,000 to 1,800 per month depending on city and lifestyle.",
  Canada: "Estimated living cost: CAD 1,200 to 2,200 per month including housing and food.",
  Australia: "Estimated living cost: AUD 1,500 to 2,700 per month depending on city and accommodation.",
};

const summariseFeeText = (fees) => {
  if (!fees) return "Contact university";
  const text = String(fees).replace(/\s+/g, " ").trim();
  const firstSentence = text.split(/[.!?]/)[0]?.trim() || text;
  if (firstSentence.length <= 44) return firstSentence;
  const matches = text.match(/[A-Z]{2,3}\s?[\d,]+(?:\s?[–-]\s?[A-Z]{0,3}\s?[\d,]+)?/g);
  if (matches?.length) {
    return matches.slice(0, 2).join(" / ");
  }
  return `${firstSentence.slice(0, 41)}...`;
};

const summariseLocation = (uni) => {
  if (uni?.city && uni?.country) return `${uni.city}, ${uni.country}`;
  if (uni?.country) return uni.country;
  if (uni?.location) return String(uni.location).split(",").slice(0, 2).join(", ").trim();
  return "-";
};

const buildScholarshipSummary = (uni) => {
  if (!uni) return "";
  const parts = [];

  if (uni.scholarship_name) {
    parts.push(uni.scholarship_name);
  }

  if (uni.scholarship_type === "full_tuition") {
    parts.push("Full tuition scholarship");
  } else if (uni.scholarship_type === "percentage_waiver" && uni.scholarship_amount) {
    parts.push(`${uni.scholarship_amount}% tuition waiver`);
  } else if (uni.scholarship_type === "fixed_amount" && uni.scholarship_amount) {
    parts.push(`USD ${Number(uni.scholarship_amount).toLocaleString()} fixed award`);
  }

  if (uni.min_ielts_score) {
    parts.push(`Minimum IELTS ${uni.min_ielts_score}`);
  }

  if (uni.min_sat_score) {
    parts.push(`Minimum SAT ${uni.min_sat_score}`);
  }

  if (uni.scholarship_eligibility_note) {
    parts.push(uni.scholarship_eligibility_note);
  } else if (uni.scholarships) {
    parts.push(uni.scholarships);
  }

  return parts.filter(Boolean).join(". ");
};

const shortParagraph = (text, fallback) => {
  const value = String(text || "").replace(/\s+/g, " ").trim();
  if (!value) return fallback;
  const firstSentence = value.split(/[.!?]/)[0]?.trim() || value;
  return firstSentence.length > 190 ? `${firstSentence.slice(0, 187)}...` : `${firstSentence}${/[.!?]$/.test(firstSentence) ? "" : "."}`;
};

const buildQuickNotes = (uni, livingCostText, intakeInfo) => [
  {
    label: "Best for",
    value: uni?.courses
      ? uni.courses.split(",").map((item) => item.trim()).filter(Boolean).slice(0, 3).join(", ")
      : "General international study options",
  },
  {
    label: "Budget note",
    value: shortParagraph(livingCostText, "Living costs vary by city and housing type."),
  },
  {
    label: "Planning note",
    value: shortParagraph(intakeInfo?.deadline, "Check the official university website for intake deadlines."),
  },
];

export default function UniversityDetail() {
  const { id } = useParams();
  const [uni, setUni] = useState(null);
  const [similarUniversities, setSimilarUniversities] = useState([]);
  const [status, setStatus] = useState("");
  const [imageDraft, setImageDraft] = useState("");
  const [imageStatus, setImageStatus] = useState("");
  const [isSavingImage, setIsSavingImage] = useState(false);
  const [overviewDraft, setOverviewDraft] = useState("");
  const [coursesDraft, setCoursesDraft] = useState("");
  const [facilitiesDraft, setFacilitiesDraft] = useState("");
  const [scholarshipsDraft, setScholarshipsDraft] = useState("");
  const [admissionsDraft, setAdmissionsDraft] = useState("");
  const [editorStatus, setEditorStatus] = useState("");
  const [isSavingContent, setIsSavingContent] = useState(false);
  const [editingSection, setEditingSection] = useState("");
  const currentUser = JSON.parse(localStorage.getItem("user") || "{}");
  const token = localStorage.getItem("token");
  const canEditUniversity = currentUser.role === "agent" || currentUser.role === "admin";

  const courseItems = useMemo(() => {
    if (!uni?.courses) return [];
    return uni.courses
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }, [uni]);

  const handleApplyClick = () => {
    if (!uni) return;
    const applyUrl = getUniversityApplyUrl(uni);
    const websiteUrl = getUniversityWebsiteUrl(uni);
    const currentToken = localStorage.getItem("token");

    try {
      const raw = localStorage.getItem(APPLICATION_STORAGE_KEY);
      const all = raw ? JSON.parse(raw) : {};
      all[String(uni.id)] = {
        university_id: uni.id,
        university_name: uni.name,
        website: websiteUrl,
        apply_url: applyUrl,
        pending_confirmation: true,
        applied: all[String(uni.id)]?.applied ?? null,
        opened_apply_at: new Date().toISOString(),
      };
      localStorage.setItem(APPLICATION_STORAGE_KEY, JSON.stringify(all));
    } catch {
      // keep navigation working even if localStorage is unavailable
    }

    if (currentToken) {
      fetch("http://localhost:5000/api/profile/applications", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${currentToken}`,
        },
        body: JSON.stringify({
          university_id: uni.id,
          source: "university_detail",
          status: "shortlisted",
          notes: "Added from Apply Now on university detail page.",
        }),
      }).catch(() => {});
    }

    window.open(applyUrl, "_blank", "noopener,noreferrer");
  };

  const handleImageSave = async () => {
    if (!canEditUniversity || !token || !uni) return;
    if (!imageDraft.trim()) {
      setImageStatus("Please enter an image URL.");
      return;
    }

    try {
      setIsSavingImage(true);
      setImageStatus("");

      const res = await fetch(`http://localhost:5000/api/agent/universities/${uni.id}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: uni.name,
          country: uni.country,
          city: uni.city,
          ranking: uni.ranking,
          website: uni.website,
          overview: uni.overview,
          courses: uni.courses,
          fees: uni.fees,
          facilities: uni.facilities,
          scholarships: uni.scholarships,
          admissions: uni.admissions,
          location: uni.location,
          contact: uni.contact,
          image_url: imageDraft.trim(),
          min_ielts_score: uni.min_ielts_score,
          min_sat_score: uni.min_sat_score,
          scholarship_name: uni.scholarship_name,
          scholarship_amount: uni.scholarship_amount,
          scholarship_type: uni.scholarship_type,
          scholarship_eligibility_note: uni.scholarship_eligibility_note,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setImageStatus(data.message || "Could not update image.");
        return;
      }

      setUni((prev) => ({ ...prev, image_url: imageDraft.trim() }));
      setImageStatus("University photo updated everywhere.");
    } catch {
      setImageStatus("Could not update image.");
    } finally {
      setIsSavingImage(false);
    }
  };

  const handleContentSave = async (field) => {
    if (!canEditUniversity || !token || !uni) return;

    const draftMap = {
      overview: overviewDraft,
      courses: coursesDraft,
      facilities: facilitiesDraft,
      scholarships: scholarshipsDraft,
      admissions: admissionsDraft,
    };
    const nextValue = (draftMap[field] || "").trim();
    if (!nextValue) {
      setEditorStatus(`Please enter ${field} content.`);
      return;
    }

    try {
      setIsSavingContent(true);
      setEditorStatus("");

      const res = await fetch(`http://localhost:5000/api/agent/universities/${uni.id}`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          name: uni.name,
          country: uni.country,
          city: uni.city,
          ranking: uni.ranking,
          website: uni.website,
          overview: field === "overview" ? nextValue : uni.overview,
          courses: field === "courses" ? nextValue : uni.courses,
          fees: uni.fees,
          facilities: field === "facilities" ? nextValue : uni.facilities,
          scholarships: field === "scholarships" ? nextValue : uni.scholarships,
          admissions: field === "admissions" ? nextValue : uni.admissions,
          location: uni.location,
          contact: uni.contact,
          image_url: uni.image_url,
          min_ielts_score: uni.min_ielts_score,
          min_sat_score: uni.min_sat_score,
          scholarship_name: uni.scholarship_name,
          scholarship_amount: uni.scholarship_amount,
          scholarship_type: uni.scholarship_type,
          scholarship_eligibility_note: uni.scholarship_eligibility_note,
        }),
      });

      const data = await res.json();
      if (!res.ok) {
        setEditorStatus(data.message || `Could not update ${field}.`);
        return;
      }

      setUni((prev) => ({
        ...prev,
        overview: field === "overview" ? nextValue : prev.overview,
        courses: field === "courses" ? nextValue : prev.courses,
        facilities: field === "facilities" ? nextValue : prev.facilities,
        scholarships: field === "scholarships" ? nextValue : prev.scholarships,
        admissions: field === "admissions" ? nextValue : prev.admissions,
      }));
      setEditingSection("");
      setEditorStatus(`${field.charAt(0).toUpperCase()}${field.slice(1)} updated everywhere.`);
    } catch {
      setEditorStatus(`Could not update ${field}.`);
    } finally {
      setIsSavingContent(false);
    }
  };

  useEffect(() => {
    const loadUniversity = async () => {
      try {
        const res = await fetch(`http://localhost:5000/api/universities/${id}`);
        const data = await res.json();
        if (!res.ok) {
          setStatus(data.message || "University not found.");
          return;
        }
        setUni(data.university);
      } catch {
        setStatus("Failed to load university.");
      }
    };

    loadUniversity();
  }, [id]);

  useEffect(() => {
    const loadSimilarUniversities = async () => {
      if (!uni?.country) return;
      try {
        const params = new URLSearchParams({
          page: "1",
          limit: "40",
          country: uni.country,
        });
        const res = await fetch(`http://localhost:5000/api/universities?${params.toString()}`);
        const data = await res.json();
        if (!res.ok) return;
        setSimilarUniversities(
          (data.universities || [])
            .filter((item) => item.id !== uni.id)
            .slice(0, 4)
        );
      } catch {
        setSimilarUniversities([]);
      }
    };

    loadSimilarUniversities();
  }, [uni?.id, uni?.country]);

  useEffect(() => {
    setImageDraft(uni?.image_url || "");
    setImageStatus("");
    setOverviewDraft(uni?.overview || "");
    setCoursesDraft(uni?.courses || "");
    setFacilitiesDraft(uni?.facilities || "");
    setScholarshipsDraft(uni?.scholarships || "");
    setAdmissionsDraft(uni?.admissions || "");
    setEditorStatus("");
    setEditingSection("");
  }, [uni?.id, uni?.image_url]);

  const websiteUrl = uni ? getUniversityWebsiteUrl(uni) : "";
  const intakeInfo = uni ? countryIntakes[uni.country] || { intake: "Main annual intake", deadline: "Check the official website for course-specific deadlines." } : null;
  const livingCostText = uni ? livingCostGuide[uni.country] || "Living cost depends on city, accommodation, and student lifestyle." : "";
  const scholarshipAvailability =
    uni?.scholarship_name || uni?.scholarships || uni?.scholarship_eligibility_note
      ? "Available"
      : "Contact university";
  const tuitionSummary = summariseFeeText(uni?.fees);
  const locationSummary = summariseLocation(uni);
  const scholarshipSummary = buildScholarshipSummary(uni);
  const overviewSummary = shortParagraph(
    uni?.overview,
    `${uni?.name || "This university"} offers academic programs for international students across multiple disciplines.`
  );
  const quickNotes = buildQuickNotes(uni, livingCostText, intakeInfo);
  const heroFacts = [
    { label: "World rank", value: uni?.ranking ? `#${uni.ranking}` : "Check source" },
    { label: "Tuition", value: tuitionSummary },
    { label: "Location", value: locationSummary },
    { label: "Intake", value: intakeInfo?.intake || "Main annual intake" },
  ];
  const summaryCards = [
    {
      label: "Overview snapshot",
      value: overviewSummary,
    },
    {
      label: quickNotes[0]?.label || "Best fit",
      value: quickNotes[0]?.value || "Review the courses section for program fit.",
    },
    {
      label: "Scholarship snapshot",
      value: scholarshipSummary || "Contact the university or agent for scholarship details.",
    },
  ];
  const planningCards = quickNotes.slice(1);
  const sectionValues = {
    overview: uni?.overview || "",
    courses: uni?.courses || "",
    tuitionLiving: `${uni?.fees || "Contact university for tuition details."} ${livingCostText}`,
    scholarships: scholarshipSummary,
    admissions: uni?.admissions || "",
    deadlines: `${intakeInfo?.intake || ""}. ${intakeInfo?.deadline || ""}`,
    contactLocation: `${uni?.location || `${uni?.city || ""}, ${uni?.country || ""}`}\n${uni?.contact || "Contact details not available."}`,
  };
  const sectionDrafts = {
    overview: overviewDraft,
    courses: coursesDraft,
    tuitionLiving: facilitiesDraft,
    scholarships: scholarshipsDraft,
    admissions: admissionsDraft,
    deadlines: facilitiesDraft,
    contactLocation: facilitiesDraft,
  };
  const setSectionDraft = {
    overview: setOverviewDraft,
    courses: setCoursesDraft,
    tuitionLiving: setFacilitiesDraft,
    scholarships: setScholarshipsDraft,
    admissions: setAdmissionsDraft,
    deadlines: setFacilitiesDraft,
    contactLocation: setFacilitiesDraft,
  };

  return (
    <>
      <Navbar />
      <main className="university-detail">
        {status && <p className="universities-loading">{status}</p>}
        {uni && (
          <>
            <header className="university-hero">
              <div className="university-hero__media">
                <img src={uni.image_url} alt={uni.name} />
                <div className="university-hero__media-badge">
                  <span>World Rank</span>
                  <strong>#{uni.ranking || "-"}</strong>
                </div>
              </div>
              <div className="university-hero__content">
                <Link to="/universities" className="university-back">Back to Universities</Link>
                <h1>{uni.name}</h1>
                <p className="university-hero__location">{uni.location || `${uni.city}, ${uni.country}`}</p>
                <p className="university-hero__summary">{overviewSummary}</p>
                <div className="university-quick-facts">
                  {heroFacts.map((fact) => (
                    <div className="university-stat" key={fact.label}>
                      <span className="university-stat__label">{fact.label}</span>
                      <strong>{fact.value}</strong>
                    </div>
                  ))}
                  <div className="university-stat university-stat--emphasis">
                    <span className="university-stat__label">Scholarships</span>
                    <strong>{scholarshipAvailability}</strong>
                  </div>
                </div>
                <div className="university-meta">
                  <button type="button" className="university-apply-btn" onClick={handleApplyClick}>
                    Apply Now
                  </button>
                  <Link to={`/expense-tracker?university=${uni.id}`}>Track Expenses</Link>
                  <a href={websiteUrl} target="_blank" rel="noreferrer">
                    Official website
                  </a>
                  <button
                    type="button"
                    className="university-meta__link"
                    onClick={() =>
                      document.getElementById("university-courses-section")?.scrollIntoView({ behavior: "smooth", block: "start" })
                    }
                  >
                    Jump to Courses
                  </button>
                </div>
                {canEditUniversity && (
                  <div className="university-image-editor">
                    <div className="university-image-editor__header">
                      <span>Agent Image Control</span>
                      <strong>Change this photo everywhere</strong>
                    </div>
                    <div className="university-image-editor__controls">
                      <input
                        type="text"
                        placeholder="Paste a new image URL"
                        value={imageDraft}
                        onChange={(e) => setImageDraft(e.target.value)}
                      />
                      <button
                        type="button"
                        onClick={handleImageSave}
                        disabled={isSavingImage}
                      >
                        {isSavingImage ? "Saving..." : "Update Photo"}
                      </button>
                    </div>
                    {imageStatus && <p className="university-image-editor__status">{imageStatus}</p>}
                  </div>
                )}
              </div>
            </header>

            <section className="university-layout">
              <div className="university-main">
                <section className="university-summary-strip">
                  {summaryCards.map((card) => (
                    <article className="university-summary-card" key={card.label}>
                      <span className="university-summary-card__label">{card.label}</span>
                      <p>{card.value}</p>
                    </article>
                  ))}
                </section>

                <section className="university-summary-strip university-summary-strip--notes">
                  {planningCards.map((item) => (
                    <article key={item.label} className="university-summary-card">
                      <span className="university-summary-card__label">{item.label}</span>
                      <p>{item.value}</p>
                    </article>
                  ))}
                </section>

                <nav className="university-anchor-nav">
                  {detailSections.map((section) => (
                    <a key={section.key} href={`#university-${section.key}-section`}>
                      {section.label}
                    </a>
                  ))}
                </nav>

                {detailSections.map((section) => (
                  <article
                    className="university-panel university-panel--stacked"
                    key={section.key}
                    id={`university-${section.key}-section`}
                  >
                    <div className="university-panel__header">
                      <span className="university-panel__eyebrow">University Guide</span>
                      <h2>{section.label}</h2>
                      {canEditUniversity && editableSections.has(section.key) && editingSection !== section.key && (
                        <button
                          type="button"
                          className="university-panel__edit-btn"
                          onClick={() => {
                            setEditorStatus("");
                            setEditingSection(section.key);
                          }}
                        >
                          Edit
                        </button>
                      )}
                    </div>

                    {canEditUniversity && editableSections.has(section.key) && editingSection === section.key && (
                      <div className="university-inline-editor">
                        <div className="university-inline-editor__header">
                          <span>Agent Content Control</span>
                          <strong>Edit {section.label.toLowerCase()} from here</strong>
                        </div>
                        <textarea
                          value={sectionDrafts[section.key]}
                          onChange={(e) => setSectionDraft[section.key](e.target.value)}
                          placeholder={`Write ${section.label.toLowerCase()} here`}
                        />
                        <div className="university-inline-editor__actions">
                          <button
                            type="button"
                            onClick={() => handleContentSave(section.key)}
                            disabled={isSavingContent}
                          >
                            {isSavingContent ? "Saving..." : `Update ${section.label}`}
                          </button>
                          <button
                            type="button"
                            className="university-inline-editor__cancel"
                            onClick={() => {
                              setEditingSection("");
                              setEditorStatus("");
                              setSectionDraft[section.key](sectionValues[section.key] || "");
                            }}
                          >
                            Cancel
                          </button>
                          {editorStatus && <p className="university-inline-editor__status">{editorStatus}</p>}
                        </div>
                      </div>
                    )}

                    {section.key === "courses" ? (
                      <div className="university-courses">
                        <p className="university-panel__lead">
                          Explore the main study areas available at {uni.name}.
                        </p>
                        <div className="university-course-grid">
                          {courseItems.length ? (
                            courseItems.map((course) => (
                              <div key={course} className="university-course-card">
                                <span className="university-course-card__badge">Course</span>
                                <h3>{course}</h3>
                                <p>Program overview and specialization details are available through the university admissions portal.</p>
                              </div>
                            ))
                          ) : (
                            <p className="university-panel__lead">{sectionValues.courses}</p>
                          )}
                        </div>
                      </div>
                    ) : section.key === "tuitionLiving" ? (
                      <div className="university-panel__body university-panel__body--facts">
                        <div className="university-fact-grid">
                          <div className="university-fact-card">
                            <span>Tuition range</span>
                            <strong>{uni.fees || "Contact university"}</strong>
                          </div>
                          <div className="university-fact-card">
                            <span>Living cost guide</span>
                            <strong>{livingCostText}</strong>
                          </div>
                          <div className="university-fact-card">
                            <span>Expense planning</span>
                            <strong>Use the expense tracker to combine application costs, tuition, and monthly living estimates.</strong>
                          </div>
                        </div>
                      </div>
                    ) : section.key === "deadlines" ? (
                      <div className="university-panel__body university-panel__body--facts">
                        <div className="university-fact-grid">
                          <div className="university-fact-card">
                            <span>Main intake</span>
                            <strong>{intakeInfo?.intake || "Main annual intake"}</strong>
                          </div>
                          <div className="university-fact-card">
                            <span>Deadline guidance</span>
                            <strong>{intakeInfo?.deadline || "Check the official website for course-specific deadlines."}</strong>
                          </div>
                        </div>
                      </div>
                    ) : section.key === "contactLocation" ? (
                      <div className="university-panel__body university-panel__body--facts">
                      <div className="university-fact-grid">
                        <div className="university-fact-card">
                          <span>Location</span>
                          <strong>{uni.location || `${uni.city || "-"}, ${uni.country || "-"}`}</strong>
                        </div>
                        <div className="university-fact-card">
                          <span>Admissions contact</span>
                          <strong>{uni.contact || "Contact details not available."}</strong>
                        </div>
                        <div className="university-fact-card">
                          <span>Official website</span>
                          <strong>
                            <a href={websiteUrl} target="_blank" rel="noreferrer">
                              Visit official website
                            </a>
                          </strong>
                        </div>
                      </div>
                    </div>
                    ) : (
                      <div className="university-panel__body">
                        <p className="university-panel__lead">{sectionValues[section.key]}</p>
                      </div>
                    )}
                  </article>
                ))}
              </div>

              <aside className="university-sidebar">
                <article className="university-sidecard">
                  <span className="university-sidecard__label">Tuition & Living Cost</span>
                  <p className="university-sidecard__value">{tuitionSummary}</p>
                  <p>{livingCostText}</p>
                </article>

                <article className="university-sidecard">
                  <span className="university-sidecard__label">Admissions Contact</span>
                  <h3>{uni.city || uni.country || "Campus details"}</h3>
                  <p>{uni.contact || "Contact details not available."}</p>
                  <p>
                    <a href={websiteUrl} target="_blank" rel="noreferrer">
                      Visit official website
                    </a>
                  </p>
                </article>

                <article className="university-sidecard university-sidecard--accent">
                  <span className="university-sidecard__label">Next Steps</span>
                  <ul className="university-sidecard__list">
                    <li>Review course requirements</li>
                    <li>Estimate tuition and living costs</li>
                    <li>Prepare scholarship documents</li>
                    <li>Track your application expenses</li>
                  </ul>
                </article>
              </aside>
            </section>

            {similarUniversities.length > 0 && (
              <section className="university-similar">
                <div className="university-similar__head">
                  <span>Related Options</span>
                  <h2>Similar universities in {uni.country}</h2>
                </div>
                <div className="university-similar__grid">
                  {similarUniversities.map((item) => (
                    <Link key={item.id} to={`/universities/${item.id}`} className="university-similar__card">
                      {item.image_url && <img src={item.image_url} alt={item.name} />}
                      <div>
                        <strong>{item.name}</strong>
                        <p>#{item.ranking || "-"} | {item.city || "City"}, {item.country}</p>
                      </div>
                    </Link>
                  ))}
                </div>
              </section>
            )}
          </>
        )}
      </main>
      <Footer />
    </>
  );
}
