import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { getUniversityWebsiteUrl } from "../utils/universityLinks";

export default function ScholarshipFinder() {
  const token = localStorage.getItem("token");
  const [recommendations, setRecommendations] = useState([]);
  const [profileUsed, setProfileUsed] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [eligibilityMessage, setEligibilityMessage] = useState("");

  const gpaValue = Number(profileUsed?.gpa);
  const blockedByGpa = Number.isFinite(gpaValue) && gpaValue < 3;
  const visibleRecommendations = blockedByGpa ? [] : recommendations;

  const avgFit = useMemo(() => {
    if (!visibleRecommendations.length) return 0;
    const total = visibleRecommendations.reduce((sum, item) => sum + Number(item.fit_score || 0), 0);
    return Math.round(total / visibleRecommendations.length);
  }, [visibleRecommendations]);

  const topMatch = visibleRecommendations[0] || null;

  useEffect(() => {
    const loadRecommendations = async () => {
      if (!token) {
        setError("Please log in and complete your profile to get scholarship matches.");
        setLoading(false);
        return;
      }

      try {
        setError("");
        setEligibilityMessage("");
        const res = await fetch("http://localhost:5000/api/scholarships/recommended", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        if (!res.ok) {
          setError(data.message || "Failed to fetch scholarships.");
          return;
        }
        setProfileUsed(data.profile_used || null);
        setRecommendations(data.recommendations || []);
        setEligibilityMessage(data.eligibility_message || "");
      } catch {
        setError("Could not load scholarship recommendations.");
      } finally {
        setLoading(false);
      }
    };

    loadRecommendations();
  }, [token]);

  return (
    <>
      <Navbar />
      <main className="scholarship-page">
        <section className="scholarship-hero">
          <div className="scholarship-hero__grid">
            <div className="scholarship-hero__content">
              <p className="scholarship-kicker">Personalized Funding Matches</p>
              <h1>Scholarship Finder</h1>
              <p>
                Explore scholarship-ready universities using your academic profile, preferred countries, and test scores.
              </p>
              <div className="scholarship-hero__chips">
                <span>Merit-based matching</span>
                <span>Country-aware shortlist</span>
                <span>Fit score ranking</span>
              </div>
            </div>

            <div className="scholarship-hero__stats">
              <div className="scholarship-stat-card">
                <small>Matched Options</small>
                <strong>{visibleRecommendations.length}</strong>
                <p>Scholarship opportunities ranked for your profile.</p>
              </div>
              <div className="scholarship-stat-row">
                <div className="scholarship-mini-stat">
                  <span>Average Fit</span>
                  <strong>{avgFit || "-"}/100</strong>
                </div>
                <div className="scholarship-mini-stat">
                  <span>Top Match</span>
                  <strong>{topMatch ? topMatch.university_name : "Complete profile"}</strong>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="scholarship-content">
          {profileUsed && (
            <div className="scholarship-profile-summary">
              <div className="scholarship-profile-summary__head">
                <h3>Profile Used For Matching</h3>
                <p>The recommendation engine compares this profile against scholarship rules set for each university.</p>
              </div>
              <div className="scholarship-profile-summary__chips">
                <span><strong>GPA</strong> {profileUsed.gpa || "-"}</span>
                <span><strong>IELTS</strong> {profileUsed.ielts_score || "-"}</span>
                <span><strong>SAT</strong> {profileUsed.sat_score || "-"}</span>
                <span><strong>TOEFL</strong> {profileUsed.toefl_score || "-"}</span>
                <span><strong>GRE</strong> {profileUsed.gre_score || "-"}</span>
                <span><strong>GMAT</strong> {profileUsed.gmat_score || "-"}</span>
                <span><strong>Field</strong> {profileUsed.field_of_study || "-"}</span>
                <span><strong>Countries</strong> {profileUsed.preferred_countries || "-"}</span>
                <span><strong>Budget</strong> {profileUsed.annual_budget || "-"}</span>
              </div>
            </div>
          )}

          {!loading && !error && topMatch && (
            <section className="scholarship-spotlight">
              <div className="scholarship-spotlight__media">
                {topMatch.image_url && <img src={topMatch.image_url} alt={topMatch.university_name} />}
                <div className="scholarship-spotlight__badge">Top Match</div>
              </div>
              <div className="scholarship-spotlight__content">
                <p className="scholarship-spotlight__eyebrow">
                  {topMatch.city || "City"} | {topMatch.country || "Country"}
                </p>
                <h2>{topMatch.university_name}</h2>
                <p className="scholarship-spotlight__desc">{topMatch.note}</p>
                <div className="scholarship-spotlight__meta">
                  <div>
                    <span>Scholarship</span>
                    <strong>{topMatch.scholarship_name}</strong>
                  </div>
                  <div>
                    <span>Amount / Coverage</span>
                    <strong>{topMatch.estimated_coverage}</strong>
                  </div>
                  <div>
                    <span>Fit Score</span>
                    <strong>{topMatch.fit_score}/100</strong>
                  </div>
                </div>
                {topMatch.match_reasons?.length > 0 && (
                  <div className="scholarship-reasons">
                    {topMatch.match_reasons.map((reason) => (
                      <span key={reason} className="scholarship-reason-pill">{reason}</span>
                    ))}
                  </div>
                )}
                {topMatch.scholarship_eligibility_note && (
                  <p className="scholarship-card__note">{topMatch.scholarship_eligibility_note}</p>
                )}
                <div className="scholarship-card__actions">
                  <Link to={`/universities/${topMatch.university_id}`} className="scholarship-btn">
                    View University
                  </Link>
                  <a
                    href={getUniversityWebsiteUrl(topMatch)}
                    target="_blank"
                    rel="noreferrer"
                    className="scholarship-btn scholarship-btn--ghost"
                  >
                    Official Site
                  </a>
                </div>
              </div>
            </section>
          )}

          {loading && (
            <div className="app-state-card app-state-card--loading">
              <div className="app-skeleton app-skeleton--title" />
              <div className="app-skeleton app-skeleton--line" />
              <div className="app-skeleton app-skeleton--line" />
              <div className="scholarship-grid scholarship-grid--skeleton">
                {[1, 2, 3].map((item) => (
                  <div key={item} className="scholarship-card scholarship-card--skeleton">
                    <div className="app-skeleton app-skeleton--block" />
                    <div className="scholarship-card__body">
                      <div className="app-skeleton app-skeleton--line" />
                      <div className="app-skeleton app-skeleton--line short" />
                      <div className="app-skeleton app-skeleton--line" />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {!loading && error && (
            <div className="app-state-card app-state-card--error">
              <h3>Scholarship data could not be loaded</h3>
              <p>{error}</p>
            </div>
          )}
          {!loading && !error && visibleRecommendations.length === 0 && (
            <div className="app-state-card">
              <h3>{blockedByGpa ? "Scholarships are not available below GPA 3.0" : "No scholarship matches yet"}</h3>
              <p>
                {blockedByGpa
                  ? (eligibilityMessage || "Update your GPA to 3.0 or above to view scholarship matches.")
                  : "Add your academic scores, target countries, and study preferences first. Scholarships will appear here once your profile matches the eligibility rules set for a university."}
              </p>
              <div className="app-state-card__actions">
                <Link to="/profile/academic" className="scholarship-btn">Update academic profile</Link>
                <Link to="/profile/preferences" className="scholarship-btn scholarship-btn--ghost">Update preferences</Link>
              </div>
            </div>
          )}

          {!loading && !error && visibleRecommendations.length > 0 && (
            <>
              <div className="scholarship-list-head">
                <div>
                  <p className="scholarship-list-head__kicker">Shortlisted For You</p>
                  <h2>Recommended Scholarships</h2>
                </div>
                <div className="scholarship-list-head__count">
                  <span>Total matches</span>
                  <strong>{visibleRecommendations.length}</strong>
                </div>
              </div>

              <div className="scholarship-grid">
                {visibleRecommendations.map((item, index) => {
                  const fitScore = Math.max(0, Math.min(100, Number(item.fit_score) || 0));
                  const fitBand =
                    fitScore >= 85 ? "Excellent Fit" : fitScore >= 70 ? "Strong Fit" : fitScore >= 55 ? "Good Fit" : "Possible Fit";

                  return (
                    <article key={`${item.university_id}-${item.scholarship_name}`} className="scholarship-card">
                      {item.image_url && (
                        <img src={item.image_url} alt={item.university_name} className="scholarship-card__image" />
                      )}
                      {!item.image_url && <div className="scholarship-card__image scholarship-card__image--placeholder" />}
                      <div className="scholarship-card__body">
                        <div className="scholarship-card__topline">
                          <span className="scholarship-rank-badge">#{index + 1}</span>
                          <span className="scholarship-country-pill">{item.country}</span>
                        </div>
                        <h3>{item.university_name}</h3>
                        <p className="scholarship-card__location">{item.city || "City"} | {item.country || "Country"}</p>

                        <div className="scholarship-card__score">
                          <div className="scholarship-card__score-label">
                            <span>Fit Score</span>
                            <strong>{item.fit_score}/100</strong>
                          </div>
                          <div className="scholarship-card__score-bar">
                            <span style={{ width: `${Math.max(4, fitScore)}%` }} />
                          </div>
                          <div className="scholarship-card__fit-band">{fitBand}</div>
                        </div>

                        <div className="scholarship-card__detail-grid">
                          <div>
                            <span>Scholarship</span>
                            <strong>{item.scholarship_name}</strong>
                          </div>
                          <div>
                            <span>Amount / Coverage</span>
                            <strong>{item.estimated_coverage}</strong>
                          </div>
                        </div>

                        {(item.minimum_ielts_score || item.minimum_sat_score) && (
                          <div className="scholarship-card__detail-grid scholarship-card__detail-grid--criteria">
                            {item.minimum_ielts_score ? (
                              <div>
                                <span>Minimum IELTS</span>
                                <strong>{item.minimum_ielts_score}</strong>
                              </div>
                            ) : null}
                            {item.minimum_sat_score ? (
                              <div>
                                <span>Minimum SAT</span>
                                <strong>{item.minimum_sat_score}</strong>
                              </div>
                            ) : null}
                          </div>
                        )}

                        {item.match_reasons?.length > 0 && (
                          <div className="scholarship-card__reasons">
                            {item.match_reasons.map((reason) => (
                              <span key={`${item.university_id}-${reason}`} className="scholarship-reason-pill">
                                {reason}
                              </span>
                            ))}
                          </div>
                        )}

                        <p className="scholarship-card__note">
                          {item.scholarship_eligibility_note || item.note}
                        </p>
                        <div className="scholarship-card__actions">
                          <Link to={`/universities/${item.university_id}`} className="scholarship-btn">View University</Link>
                          <a
                            href={getUniversityWebsiteUrl(item)}
                            target="_blank"
                            rel="noreferrer"
                            className="scholarship-btn scholarship-btn--ghost"
                          >
                            Official Site
                          </a>
                        </div>
                      </div>
                    </article>
                  );
                })}
              </div>
            </>
          )}
        </section>
      </main>
      <Footer />
    </>
  );
}
