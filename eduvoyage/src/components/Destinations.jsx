import { Link } from "react-router-dom";

const countries = [
  {
    name: "Australia",
    detail: "Good balance of university quality, city life, and student support.",
    stats: ["Lifestyle", "Business", "Health"],
  },
  {
    name: "United States",
    detail: "Best for variety, research opportunities, and large university choice.",
    stats: ["Research", "Variety", "Specialization"],
  },
  {
    name: "Canada",
    detail: "Popular for stable student life, support systems, and practical planning.",
    stats: ["Support", "Planning", "Balanced costs"],
  },
  {
    name: "United Kingdom",
    detail: "Known for shorter degrees, established universities, and faster admission cycles.",
    stats: ["Short degrees", "Historic", "Fast cycle"],
  },
];

export default function Destinations() {
  return (
    <section className="destinations">
      <div className="section-container">
        <div className="section-heading">
          <p className="section-kicker">Top Destinations</p>
          <h2 className="section-title">Compare the main study destinations.</h2>
          <p className="section-copy">Each country has a different cost, study style, and admission pace.</p>
        </div>

        <div className="destination-grid destination-grid--simple">
          {countries.map((country) => (
            <article key={country.name} className="destination-card destination-card--simple">
              <div className="destination-card__body">
                <h3>{country.name}</h3>
                <p>{country.detail}</p>
                <ul className="destination-card__list">
                  {country.stats.map((stat) => (
                    <li key={stat}>{stat}</li>
                  ))}
                </ul>
                <Link to="/countries" className="btn-outline">View country</Link>
              </div>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
