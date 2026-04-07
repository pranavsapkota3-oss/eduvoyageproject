import { Link } from "react-router-dom";

const trustMetrics = [
  { value: "150+", label: "universities" },
  { value: "4", label: "main destinations" },
  { value: "Student", label: "planning first" },
];

const quickLinks = [
  { label: "Explore countries", to: "/countries" },
  { label: "Find scholarships", to: "/scholarships" },
  { label: "Estimate expenses", to: "/expense-tracker" },
];

export default function Hero() {
  return (
    <section className="hero hero--simple">
      <div className="hero-content hero-content--simple">
        <div className="hero-copy hero-copy--simple">
          <p className="hero-kicker">Study Abroad, Made Clearer</p>
          <h1 className="hero-title">Find universities, compare costs, and plan your next step in one place.</h1>
          <p className="hero-subtitle">
            Use EduVoyage to shortlist universities, check scholarships, and estimate your budget before you apply.
          </p>

          <div className="hero-actions hero-actions--simple">
            <Link to="/universities" className="hero-btn hero-btn--primary">Browse Universities</Link>
            <Link to="/signup" className="hero-btn hero-btn--secondary">Create Profile</Link>
          </div>

          <div className="hero-trust-grid hero-trust-grid--simple">
            {trustMetrics.map((metric) => (
              <div key={metric.label} className="hero-trust-card hero-trust-card--simple">
                <strong>{metric.value}</strong>
                <span>{metric.label}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="hero-planner hero-planner--simple">
          <div className="hero-planner__head">
            <span className="hero-planner__eyebrow">Start Here</span>
            <h3>Pick one place to begin</h3>
            <p>You do not need to fill everything at once. Start with the part you already know.</p>
          </div>

          <div className="hero-quick-links">
            {quickLinks.map((item) => (
              <Link key={item.label} to={item.to} className="hero-quick-links__item">
                {item.label}
              </Link>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
