import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { getUniversityWebsiteUrl } from "../utils/universityLinks";

const PAGE_SIZE = 12;

const parseFeeValue = (fees) => {
  if (!fees) return Number.POSITIVE_INFINITY;
  const matches = String(fees).match(/[\d,]+/g);
  if (!matches?.length) return Number.POSITIVE_INFINITY;
  const values = matches
    .map((value) => Number(String(value).replace(/,/g, "")))
    .filter((value) => Number.isFinite(value) && value > 0);
  return values.length ? Math.min(...values) : Number.POSITIVE_INFINITY;
};

const getPrimarySubject = (courses) => {
  if (!courses) return "General";
  return String(courses).split(",")[0]?.trim() || "General";
};

const normalizeCountryLabel = (country) => {
  const value = String(country || "").trim().toLowerCase();
  if (value === "usa" || value === "us" || value === "united states" || value === "united states of america") {
    return "United States";
  }
  if (value === "uk" || value === "u.k." || value === "united kingdom" || value === "great britain") {
    return "United Kingdom";
  }
  if (!value) return "";
  return String(country)
    .trim()
    .replace(/\b\w/g, (char) => char.toUpperCase());
};

const buildPopularityScore = (uni) => {
  const rankingScore = uni.ranking ? Math.max(0, 220 - Number(uni.ranking)) : 20;
  const scholarshipScore = uni.scholarships ? 20 : 0;
  const imageScore = uni.image_url ? 10 : 0;
  const websiteScore = uni.website ? 10 : 0;
  return rankingScore + scholarshipScore + imageScore + websiteScore;
};

const compareSummary = (uni) => ({
  id: uni.id,
  name: uni.name,
  ranking: uni.ranking || "-",
  country: normalizeCountryLabel(uni.country) || "-",
  city: uni.city || "-",
  fees: uni.fees || "Contact university",
  subject: getPrimarySubject(uni.courses),
  scholarships: uni.scholarships ? "Available" : "Limited info",
});

export default function Universities() {
  const [items, setItems] = useState([]);
  const [query, setQuery] = useState("");
  const [countryFilter, setCountryFilter] = useState("");
  const [rankingFilter, setRankingFilter] = useState("");
  const [feeFilter, setFeeFilter] = useState("");
  const [subjectFilter, setSubjectFilter] = useState("");
  const [scholarshipFilter, setScholarshipFilter] = useState(false);
  const [sortBy, setSortBy] = useState("ranking");
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [compareIds, setCompareIds] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadUniversities = async () => {
      try {
        setLoading(true);
        setError("");
        const params = new URLSearchParams({ page: "1", limit: "200" });
        const res = await fetch(`http://localhost:5000/api/universities?${params.toString()}`);
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || "Failed to load universities.");
        }
        setItems(data.universities || []);
      } catch (err) {
        setItems([]);
        setError(err.message || "Failed to load universities.");
      } finally {
        setLoading(false);
      }
    };

    loadUniversities();
  }, []);

  const availableCountries = useMemo(
    () => [...new Set(items.map((item) => normalizeCountryLabel(item.country)).filter(Boolean))].sort(),
    [items]
  );

  const availableSubjects = useMemo(() => {
    const subjects = items
      .flatMap((item) => String(item.courses || "").split(","))
      .map((item) => item.trim())
      .filter(Boolean);
    return [...new Set(subjects)].slice(0, 30);
  }, [items]);

  const filteredItems = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();

    const filtered = items.filter((uni) => {
      const ranking = Number(uni.ranking || 99999);
      const feeValue = parseFeeValue(uni.fees);
      const courses = String(uni.courses || "").toLowerCase();
      const scholarships = String(uni.scholarships || "").trim();
      const haystack = [uni.name, uni.country, uni.city, uni.courses].join(" ").toLowerCase();

      if (normalizedQuery && !haystack.includes(normalizedQuery)) return false;
      if (countryFilter && normalizeCountryLabel(uni.country) !== countryFilter) return false;
      if (subjectFilter && !courses.includes(subjectFilter.toLowerCase())) return false;
      if (scholarshipFilter && !scholarships) return false;

      if (rankingFilter === "top50" && ranking > 50) return false;
      if (rankingFilter === "top100" && ranking > 100) return false;
      if (rankingFilter === "101plus" && ranking <= 100) return false;

      if (feeFilter === "budget" && feeValue > 25000) return false;
      if (feeFilter === "mid" && (feeValue <= 25000 || feeValue > 45000)) return false;
      if (feeFilter === "premium" && feeValue <= 45000) return false;

      return true;
    });

    return filtered.sort((a, b) => {
      if (sortBy === "ranking") {
        return (a.ranking || 99999) - (b.ranking || 99999) || a.name.localeCompare(b.name);
      }
      if (sortBy === "tuition") {
        return parseFeeValue(a.fees) - parseFeeValue(b.fees) || (a.ranking || 99999) - (b.ranking || 99999);
      }
      if (sortBy === "popularity") {
        return buildPopularityScore(b) - buildPopularityScore(a) || (a.ranking || 99999) - (b.ranking || 99999);
      }
      return a.name.localeCompare(b.name);
    });
  }, [items, query, countryFilter, rankingFilter, feeFilter, subjectFilter, scholarshipFilter, sortBy]);

  const totalPages = Math.max(1, Math.ceil(filteredItems.length / PAGE_SIZE));
  const pagedItems = useMemo(
    () => filteredItems.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [filteredItems, page]
  );

  const comparedUniversities = useMemo(
    () => items.filter((item) => compareIds.includes(item.id)).map(compareSummary),
    [items, compareIds]
  );

  useEffect(() => {
    setPage(1);
  }, [query, countryFilter, rankingFilter, feeFilter, subjectFilter, scholarshipFilter, sortBy]);

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  const toggleCompare = (id) => {
    setCompareIds((prev) => {
      if (prev.includes(id)) return prev.filter((item) => item !== id);
      if (prev.length >= 3) return [...prev.slice(1), id];
      return [...prev, id];
    });
  };

  return (
    <>
      <Navbar />
      <main className="universities-page">
        <header className="universities-hero universities-hero--rich">
          <p className="universities-hero__eyebrow">University Discovery</p>
          <h1>Find the right university with filters that match how students actually decide.</h1>
          <p>
            Search by country, subject, ranking, budget, and scholarship availability. Compare realistic options side by side before you shortlist.
          </p>
        </header>

        <section className="universities-tools">
          <div className="universities-search universities-search--wide">
            <input
              type="text"
              placeholder="Search by university, country, city, or course"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>

          <div className="universities-filters">
            <select value={countryFilter} onChange={(e) => setCountryFilter(e.target.value)}>
              <option value="">All countries</option>
              {availableCountries.map((country) => (
                <option key={country} value={country}>{country}</option>
              ))}
            </select>

            <select value={rankingFilter} onChange={(e) => setRankingFilter(e.target.value)}>
              <option value="">All ranking bands</option>
              <option value="top50">Top 50</option>
              <option value="top100">Top 100</option>
              <option value="101plus">101+</option>
            </select>

            <select value={feeFilter} onChange={(e) => setFeeFilter(e.target.value)}>
              <option value="">All fee ranges</option>
              <option value="budget">Budget-friendly</option>
              <option value="mid">Mid-range</option>
              <option value="premium">Premium</option>
            </select>

            <select value={subjectFilter} onChange={(e) => setSubjectFilter(e.target.value)}>
              <option value="">All subjects</option>
              {availableSubjects.map((subject) => (
                <option key={subject} value={subject}>{subject}</option>
              ))}
            </select>

            <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
              <option value="ranking">Sort by ranking</option>
              <option value="tuition">Sort by tuition</option>
              <option value="popularity">Sort by popularity</option>
              <option value="name">Sort by name</option>
            </select>

            <label className="universities-check">
              <input
                type="checkbox"
                checked={scholarshipFilter}
                onChange={(e) => setScholarshipFilter(e.target.checked)}
              />
              Scholarship available
            </label>
          </div>
        </section>

        {comparedUniversities.length > 0 && (
          <section className="universities-compare">
            <div className="universities-compare__head">
              <div>
                <p className="universities-compare__eyebrow">Compare shortlist</p>
                <h2>Side-by-side quick view</h2>
              </div>
              <button type="button" onClick={() => setCompareIds([])}>Clear compare</button>
            </div>
            <div className="universities-compare__grid">
              {comparedUniversities.map((uni) => (
                <article key={uni.id} className="universities-compare__card">
                  <h3>{uni.name}</h3>
                  <p><strong>Rank:</strong> {uni.ranking}</p>
                  <p><strong>Country:</strong> {uni.country}</p>
                  <p><strong>City:</strong> {uni.city}</p>
                  <p><strong>Tuition:</strong> {uni.fees}</p>
                  <p><strong>Top subject:</strong> {uni.subject}</p>
                  <p><strong>Scholarships:</strong> {uni.scholarships}</p>
                </article>
              ))}
            </div>
          </section>
        )}

        <section className="universities-grid universities-grid--rich">
          {loading && <p className="universities-loading">Loading universities...</p>}
          {!loading && error && <p className="universities-loading">{error}</p>}
          {!loading && !error && filteredItems.length === 0 && (
            <div className="universities-empty">
              <h3>No universities found for these filters.</h3>
              <p>Try broadening the search or start with one of these suggestions:</p>
              <div className="universities-empty__suggestions">
                <button type="button" onClick={() => { setQuery(""); setCountryFilter("United States"); setRankingFilter("top50"); }}>Top 50 in United States</button>
                <button type="button" onClick={() => { setQuery(""); setCountryFilter("Canada"); setScholarshipFilter(true); }}>Canada with scholarships</button>
                <button type="button" onClick={() => { setQuery("Engineering"); setCountryFilter(""); setFeeFilter(""); }}>Engineering programs</button>
                <button type="button" onClick={() => { setQuery(""); setFeeFilter("budget"); setRankingFilter(""); }}>Budget-friendly options</button>
              </div>
            </div>
          )}

          {!loading && !error && pagedItems.map((uni) => (
            <article className="university-card university-card--rich" key={uni.id || `${uni.name}-${uni.ranking || ""}`}>
              <Link to={`/universities/${uni.id || uni.name}`} className="university-card__main">
                <div className="university-card__topline">
                  <span className="university-rank">#{uni.ranking || "-"}</span>
                  <span className="university-card__tag">{uni.scholarships ? "Scholarships" : "Info available"}</span>
                </div>
                {uni.image_url && (
                  <img src={uni.image_url} alt={uni.name} className="university-image" />
                )}
                <h3>{uni.name}</h3>
                <p className="university-card__location">{uni.city || "City"} · {uni.country || "Country"}</p>
                <div className="university-card__meta-grid">
                  <div>
                    <span>Tuition</span>
                    <strong>{uni.fees || "Contact university"}</strong>
                  </div>
                  <div>
                    <span>Top subject</span>
                    <strong>{getPrimarySubject(uni.courses)}</strong>
                  </div>
                </div>
                <p className="university-card__course-line">
                  {uni.courses || "Course overview available on the detail page."}
                </p>
              </Link>

              <div className="university-card__actions">
                <label className="universities-check universities-check--compare">
                  <input
                    type="checkbox"
                    checked={compareIds.includes(uni.id)}
                    onChange={() => toggleCompare(uni.id)}
                  />
                  Compare
                </label>
                <a href={getUniversityWebsiteUrl(uni)} target="_blank" rel="noreferrer" className="university-link">
                  Visit website
                </a>
              </div>
            </article>
          ))}
        </section>

        {!loading && !error && filteredItems.length > PAGE_SIZE && (
          <div className="universities-pagination">
            <button
              type="button"
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page === 1}
            >
              Prev
            </button>
            <span>Page {page} of {totalPages}</span>
            <button
              type="button"
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
            >
              Next
            </button>
          </div>
        )}
      </main>
      <Footer />
    </>
  );
}
