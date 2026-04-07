import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const COUNTRY_OPTIONS = ["USA", "Australia", "Canada", "UK"];

export default function Countries() {
  const [selectedCountry, setSelectedCountry] = useState("USA");
  const [universities, setUniversities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    const loadUniversities = async () => {
      try {
        setLoading(true);
        setError("");
        const params = new URLSearchParams({
          page: String(page),
          limit: "10",
          country: selectedCountry,
        });
        const res = await fetch(`http://localhost:5000/api/universities?${params.toString()}`);
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.message || "Failed to load universities");
        }
        setUniversities(data.universities || []);
        setTotal(data.total || 0);
      } catch (err) {
        setError(err.message || "Failed to load universities");
        setUniversities([]);
        setTotal(0);
      } finally {
        setLoading(false);
      }
    };

    loadUniversities();
  }, [selectedCountry, page]);

  return (
    <>
      <Navbar />
      <main className="countries-page">
        <section className="countries-hero">
          <h1>Browse By Country</h1>
          <p>Select a country to explore universities.</p>
          <div className="country-tabs">
            {COUNTRY_OPTIONS.map((country) => (
              <button
                key={country}
                type="button"
                className={selectedCountry === country ? "country-tab country-tab--active" : "country-tab"}
                onClick={() => {
                  setSelectedCountry(country);
                  setPage(1);
                }}
              >
                {country}
              </button>
            ))}
          </div>
        </section>

        <section className="countries-list">
          {loading && <p className="countries-state">Loading universities...</p>}
          {!loading && error && <p className="countries-state countries-state--error">{error}</p>}
          {!loading && !error && universities.length === 0 && (
            <p className="countries-state">No universities found for {selectedCountry}.</p>
          )}

          {!loading && !error && universities.length > 0 && (
            <div className="country-university-grid">
              {universities.map((uni) => (
                <Link to={`/universities/${uni.id}`} key={uni.id} className="country-uni-card">
                  {uni.image_url && (
                    <img src={uni.image_url} alt={uni.name} className="country-uni-card__image" />
                  )}
                  <div className="country-uni-card__body">
                    <p className="country-uni-rank">#{uni.ranking || "-"}</p>
                    <h3>{uni.name}</h3>
                    <p>{uni.city || "-"}, {uni.country}</p>
                  </div>
                </Link>
              ))}
            </div>
          )}

          {!loading && total > 10 && (
            <div className="countries-pagination">
              <button type="button" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>
                Prev
              </button>
              <span>Page {page}</span>
              <button
                type="button"
                onClick={() => setPage((p) => p + 1)}
                disabled={page * 10 >= total}
              >
                Next
              </button>
            </div>
          )}
        </section>
      </main>
      <Footer />
    </>
  );
}

