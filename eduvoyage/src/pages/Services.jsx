import Navbar from "../components/Navbar";
import Footer from "../components/Footer";

const services = [
  {
    title: "Application Strategy",
    subtitle: "Shortlist smarter, apply stronger",
    description:
      "Profile-based university shortlisting, application timeline planning, and document readiness support to improve admit chances.",
    bullets: ["Profile audit", "University shortlist", "Application timeline"],
  },
  {
    title: "Scholarship Guidance",
    subtitle: "Funding roadmap for your target countries",
    description:
      "Scholarship matching, eligibility checks, essay guidance, and deadlines tracking for merit and need-based opportunities.",
    bullets: ["Scholarship matching", "Eligibility screening", "Deadline tracking"],
  },
  {
    title: "Visa & Pre-Departure",
    subtitle: "From offer letter to landing",
    description:
      "Visa checklist support, financial document prep, interview guidance, accommodation planning, and pre-departure briefing.",
    bullets: ["Visa checklist", "Interview prep", "Pre-departure planning"],
  },
  {
    title: "Test Prep Planning",
    subtitle: "IELTS, TOEFL, GRE, GMAT support",
    description:
      "Personalized test plan, exam scheduling suggestions, score targeting, and preparation resource recommendations.",
    bullets: ["Target scores", "Study plan", "Exam scheduling"],
  },
  {
    title: "SOP / LOR Review",
    subtitle: "Polish your profile narrative",
    description:
      "Statement of Purpose review, LOR structure guidance, resume refinement, and course-specific profile positioning.",
    bullets: ["SOP review", "LOR guidance", "CV refinement"],
  },
  {
    title: "Budget & Expense Planning",
    subtitle: "Affordable study abroad planning",
    description:
      "Tuition + living cost estimation, city-wise comparison, and monthly student budget planning with cost-saving ideas.",
    bullets: ["City cost comparison", "Budget planning", "Savings suggestions"],
  },
];

const processSteps = [
  { step: "01", title: "Profile Diagnosis", text: "We evaluate academics, scores, budget, and destination preferences." },
  { step: "02", title: "Strategy Build", text: "A personalized plan is created for universities, scholarships, and timelines." },
  { step: "03", title: "Execution Support", text: "We support applications, documentation, test planning, and visa preparation." },
  { step: "04", title: "Decision & Next Steps", text: "Compare offers, plan finances, and prepare for departure." },
];

export default function Services() {
  return (
    <>
      <Navbar />
      <main className="services-page">
        <section className="services-hero">
          <div className="services-hero__glow" />
          <div className="services-hero__grid">
            <div className="services-hero__content">
              <p className="services-kicker">EduVoyage Services</p>
              <h1>End-to-end support for your study abroad journey</h1>
              <p>
                Built for students who need a clear path from profile building to final admission and financial planning.
              </p>
              <div className="services-hero__chips">
                <span>University Shortlisting</span>
                <span>Scholarship Planning</span>
                <span>Visa Support</span>
                <span>Budget Guidance</span>
              </div>
            </div>

            <div className="services-stats">
              <div className="services-stats__card">
                <small>Core Services</small>
                <strong>06</strong>
                <p>Focused modules covering admission, funding, and planning.</p>
              </div>
              <div className="services-stats__row">
                <div className="services-mini-stat">
                  <span>Scholarship-ready flow</span>
                  <strong>Profile + Marks</strong>
                </div>
                <div className="services-mini-stat">
                  <span>Destination focus</span>
                  <strong>USA | UK | Canada | Australia</strong>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="services-process">
          <div className="services-section-head">
            <p>How It Works</p>
            <h2>A structured process, not random advice</h2>
          </div>
          <div className="services-process__grid">
            {processSteps.map((item) => (
              <article className="services-process__card" key={item.step}>
                <div className="services-process__step">{item.step}</div>
                <h3>{item.title}</h3>
                <p>{item.text}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="services-grid">
          <div className="services-section-head services-section-head--light">
            <p>Service Modules</p>
            <h2>Choose the support you need, when you need it</h2>
          </div>
          {services.map((service, index) => (
            <article className="service-card" key={service.title} style={{ animationDelay: `${index * 60}ms` }}>
              <div className="service-card__badge">{String(index + 1).padStart(2, "0")}</div>
              <h3>{service.title}</h3>
              <p className="service-card__subtitle">{service.subtitle}</p>
              <p>{service.description}</p>
              <ul className="service-card__list">
                {service.bullets.map((bullet) => (
                  <li key={bullet}>{bullet}</li>
                ))}
              </ul>
            </article>
          ))}
        </section>

        <section className="services-cta">
          <div className="services-cta__panel">
            <div>
              <h2>Need a custom plan?</h2>
              <p>
                Start with Profile Completion, then use Scholarship Finder and Countries Explorer to build a realistic shortlist with budget alignment.
              </p>
            </div>
            <div className="services-cta__chips">
              <span>Profile Completion</span>
              <span>Scholarship Finder</span>
              <span>Countries Explorer</span>
              <span>Expense Tracker</span>
            </div>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}

