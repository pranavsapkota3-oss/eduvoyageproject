import { Link } from "react-router-dom";
import Navbar from "../components/Navbar";
import Hero from "../components/Hero";
import Footer from "../components/Footer";

const destinations = [
  {
    flagImage: "https://flagcdn.com/w80/us.png",
    name: "United States",
    detail: "Best if you want wide subject choice, research-heavy universities, and flexible admissions planning.",
    notes: ["Large university range", "High budget variation", "Strong scholarship competition"],
  },
  {
    flagImage: "https://flagcdn.com/w80/ca.png",
    name: "Canada",
    detail: "Good for students balancing reputation, safer planning, and more predictable city-based living costs.",
    notes: ["Balanced cost profile", "Stable student support", "Popular for post-study planning"],
  },
  {
    flagImage: "https://flagcdn.com/w80/au.png",
    name: "Australia",
    detail: "A practical option for students comparing strong universities with clear intake cycles and city lifestyle.",
    notes: ["Simple intake rhythm", "Good city campuses", "Strong health and business options"],
  },
  {
    flagImage: "https://flagcdn.com/w80/gb.png",
    name: "United Kingdom",
    detail: "Useful when you want shorter degree duration and fast-moving admission cycles.",
    notes: ["Shorter degrees", "Historic universities", "Faster timelines"],
  },
];

const recentUniversities = [
  {
    name: "University of Toronto",
    country: "Canada",
    fee: "CAD 45,000 - 62,000",
    summary: "Strong for engineering, health sciences, AI, and graduate pathways.",
    image: "https://images.unsplash.com/photo-1517090504586-fde19ea6066f?auto=format&fit=crop&w=1200&q=80",
  },
  {
    name: "University of Melbourne",
    country: "Australia",
    fee: "AUD 22,000 - 45,000",
    summary: "Good academic reputation with broad professional programs and a strong city campus setting.",
    image: "https://images.unsplash.com/photo-1523050854058-8df90110c9f1?auto=format&fit=crop&w=1200&q=80",
  },
  {
    name: "Stanford University",
    country: "United States",
    fee: "Premium-cost option",
    summary: "Best for students targeting high-competition programs, research, and startup-focused fields.",
    image: "https://images.unsplash.com/photo-1562774053-701939374585?auto=format&fit=crop&w=1200&q=80",
  },
  {
    name: "University of Oxford",
    country: "United Kingdom",
    fee: "GBP 28,000 - 44,000",
    summary: "Shorter degree structure and very strong academic recognition across disciplines.",
    image: "https://images.unsplash.com/photo-1541339907198-e08756dedf3f?auto=format&fit=crop&w=1200&q=80",
  },
];

const scholarshipHighlights = [
  {
    title: "Profile-based matching",
    text: "Scholarship suggestions use your GPA, IELTS, SAT, country preference, and budget instead of showing every option to every user.",
    link: "/scholarships",
    cta: "Open Scholarship Finder",
  },
  {
    title: "Country-specific alerts",
    text: "If a scholarship is updated for a university in your preferred country, EduVoyage can notify you by email.",
    link: "/profile/preferences",
    cta: "Set study preferences",
  },
  {
    title: "University-level scholarship rules",
    text: "Agents can set scholarship name, amount, type, minimum IELTS, minimum SAT, and eligibility notes for each university.",
    link: "/agent",
    cta: "Open Agent Panel",
  },
];

const nextSteps = [
  {
    label: "Step 1",
    title: "Complete your profile",
    text: "Add academic scores, preferred country, and budget so recommendations stop being generic.",
    to: "/profile",
  },
  {
    label: "Step 2",
    title: "Shortlist universities",
    text: "Use ranking, country, fee, and scholarship filters to narrow down realistic options.",
    to: "/universities",
  },
  {
    label: "Step 3",
    title: "Plan your expenses",
    text: "Estimate application costs, tuition, and monthly living cost before you commit to one path.",
    to: "/expense-tracker",
  },
];

export default function Home() {
  return (
    <>
      <Navbar />
      <Hero />

      <main className="home-page">
        <section className="home-section home-section--practical">
          <div className="section-container">
            <div className="section-heading section-heading--split">
              <div>
                <p className="section-kicker">Top Destinations</p>
                <h2 className="section-title">Start with countries students actually compare first.</h2>
                <p className="section-copy">
                  Each destination changes your tuition range, living cost, intake pace, and scholarship options. Use this as the first planning filter.
                </p>
              </div>
              <Link to="/countries" className="section-link">View all countries</Link>
            </div>

            <div className="home-practical-grid">
              {destinations.map((item) => (
                <article key={item.name} className="home-practical-card">
                  <div className="home-practical-card__head">
                    <img
                      src={item.flagImage}
                      alt={`${item.name} flag`}
                      className="home-practical-card__flag-image"
                    />
                    <span className="home-practical-card__label">{item.name}</span>
                  </div>
                  <h3>{item.detail}</h3>
                  <ul className="home-practical-card__list">
                    {item.notes.map((note) => (
                      <li key={note}>{note}</li>
                    ))}
                  </ul>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="home-section">
          <div className="section-container">
            <div className="section-heading section-heading--split">
              <div>
                <p className="section-kicker">Recent Universities</p>
                <h2 className="section-title">A practical starting shortlist, not a random list.</h2>
                <p className="section-copy">
                  These are strong benchmark universities across the four main destinations students on EduVoyage usually compare first.
                </p>
              </div>
              <Link to="/universities" className="section-link">Browse full directory</Link>
            </div>

            <div className="home-university-grid home-university-grid--simple">
              {recentUniversities.map((uni) => (
                <article key={uni.name} className="home-university-card home-university-card--simple">
                  <img
                    src={uni.image}
                    alt={uni.name}
                    className="home-university-card__image"
                  />
                  <div className="home-university-card__body">
                    <div className="home-university-card__meta">
                      <span>{uni.country}</span>
                      <span>{uni.fee}</span>
                    </div>
                    <h3>{uni.name}</h3>
                    <p>{uni.summary}</p>
                    <div className="home-university-card__footer">
                      <strong>Compare tuition, fit, and details</strong>
                      <Link to="/universities">View university</Link>
                    </div>
                  </div>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="home-section">
          <div className="section-container">
            <div className="section-heading section-heading--split">
              <div>
                <p className="section-kicker">Scholarship Highlights</p>
                <h2 className="section-title">Use the scholarship page as a filtered decision tool.</h2>
                <p className="section-copy">
                  Scholarship results are matched against your profile and preferences, so the page becomes more useful after profile completion.
                </p>
              </div>
              <Link to="/scholarships" className="section-link">Open scholarship page</Link>
            </div>

            <div className="home-highlight-grid home-highlight-grid--simple">
              {scholarshipHighlights.map((item) => (
                <article key={item.title} className="home-highlight-card home-highlight-card--simple">
                  <h3>{item.title}</h3>
                  <p>{item.text}</p>
                  <Link to={item.link}>{item.cta}</Link>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="home-section">
          <div className="section-container">
            <div className="section-heading">
              <p className="section-kicker">Next Step Actions</p>
              <h2 className="section-title">Use the site in this order if you are just getting started.</h2>
              <p className="section-copy">
                The platform works best when profile, university discovery, and expense planning are used as one continuous flow.
              </p>
            </div>

            <div className="workflow-grid workflow-grid--simple">
              {nextSteps.map((step) => (
                <article key={step.title} className="workflow-card workflow-card--simple">
                  <span className="workflow-card__number">{step.label}</span>
                  <h3>{step.title}</h3>
                  <p>{step.text}</p>
                  <Link to={step.to} className="section-link">Open</Link>
                </article>
              ))}
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </>
  );
}
