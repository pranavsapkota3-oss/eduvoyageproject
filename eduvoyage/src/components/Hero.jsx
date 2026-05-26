import { Link } from "react-router-dom";

const trustMetrics = [
  { value: "150+", label: "universities tracked" },
  { value: "4", label: "study destinations" },
  { value: "Profile", label: "based matching" },
];

const quickLinks = [
  {
    label: "Complete profile",
    detail: "Add your scores, country preference, and budget first.",
    to: "/profile",
  },
  {
    label: "Find scholarships",
    detail: "See matches based on your academic background.",
    to: "/scholarships",
  },
  {
    label: "Estimate expenses",
    detail: "Check tuition, living cost, and income balance.",
    to: "/expense-tracker",
  },
];

export default function Hero() {
  return (
    <section className="hero hero--simple">
      <div className="hero-content hero-content--simple">
        <div className="hero-copy hero-copy--simple">
          <p className="hero-kicker">Study Abroad, Made Clearer</p>
          <h1 className="hero-title">Plan your study-abroad shortlist, scholarships, and budget in one place.</h1>
          <p className="hero-subtitle">
            Start with your profile, compare realistic universities, then move into scholarship matching and expense planning without jumping between different tools.
          </p>

          <div className="hero-actions hero-actions--simple">
            <Link to="/universities" className="hero-btn hero-btn--primary">Browse Universities</Link>
            <Link to="/profile" className="hero-btn hero-btn--secondary">Complete Profile</Link>
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
            <span className="hero-planner__eyebrow">Start With What You Know</span>
            <h3>Choose your next step</h3>
            <p>Pick the action that matches where you are right now, then move forward from there.</p>
          </div>

          <div className="hero-quick-links">
            {quickLinks.map((item) => (
              <Link key={item.label} to={item.to} className="hero-quick-links__item">
                <strong>{item.label}</strong>
                <span>{item.detail}</span>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
