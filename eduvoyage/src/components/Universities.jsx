import { Link } from "react-router-dom";

const featuredUniversities = [
  {
    name: "University of Toronto",
    country: "Canada",
    ranking: "#6",
    fee: "CAD 45,000 - 62,000",
    note: "Strong for engineering, data, medicine, and graduate pathways.",
  },
  {
    name: "University of Melbourne",
    country: "Australia",
    ranking: "#8",
    fee: "AUD 22,000 - 45,000",
    note: "Balanced academic reputation, city life, and strong professional programs.",
  },
  {
    name: "Stanford University",
    country: "USA",
    ranking: "#2",
    fee: "High-cost premium option",
    note: "Best suited for ambitious applicants targeting innovation-heavy fields.",
  },
  {
    name: "University of Oxford",
    country: "UK",
    ranking: "#4",
    fee: "GBP 28,000 - 44,000",
    note: "Shorter degree structure with a globally recognized academic profile.",
  },
];

export default function Universities() {
  return (
    <section className="universities">
      <div className="section-container">
        <div className="section-heading section-heading--split">
          <div>
            <p className="section-kicker">Universities</p>
            <h2 className="section-title">A few universities students often start with.</h2>
          </div>
          <Link to="/universities" className="section-link">See all universities</Link>
        </div>

        <div className="home-university-grid home-university-grid--simple">
          {featuredUniversities.map((uni) => (
            <article key={uni.name} className="home-university-card home-university-card--simple">
              <div className="home-university-card__body">
                <div className="home-university-card__meta">
                  <span>{uni.ranking}</span>
                  <span>{uni.country}</span>
                </div>
                <h3>{uni.name}</h3>
                <p>{uni.note}</p>
                <div className="home-university-card__footer">
                  <strong>{uni.fee}</strong>
                  <Link to="/universities">View profile</Link>
                </div>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
