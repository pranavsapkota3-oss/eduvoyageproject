import { Link } from "react-router-dom";

const workflowSteps = [
  {
    title: "Build your profile",
    text: "Add your marks, preferred country, and intended subject.",
  },
  {
    title: "Compare options",
    text: "Check ranking, cost, country, and available programs before shortlisting.",
  },
  {
    title: "Check scholarships",
    text: "See which scholarships and universities fit your profile better.",
  },
  {
    title: "Plan your budget",
    text: "Estimate tuition and living cost before you apply.",
  },
];

const highlights = [
  { title: "Scholarship Finder", text: "Match scholarships using your profile.", to: "/scholarships" },
  { title: "Expense Tracker", text: "Estimate yearly study costs early.", to: "/expense-tracker" },
  { title: "Student Profile", text: "Complete your details for better results.", to: "/profile" },
];

export default function WhyChoose() {
  return (
    <section className="why-choose">
      <div className="section-container">
        <div className="section-heading">
          <p className="section-kicker">How It Works</p>
          <h2 className="section-title">A simple planning flow for students.</h2>
          <p className="section-copy">
            Start with your profile, shortlist options, and move toward scholarships and budgeting step by step.
          </p>
        </div>

        <div className="workflow-grid workflow-grid--simple">
          {workflowSteps.map((step, index) => (
            <article key={step.title} className="workflow-card workflow-card--simple">
              <span className="workflow-card__number">0{index + 1}</span>
              <h3>{step.title}</h3>
              <p>{step.text}</p>
            </article>
          ))}
        </div>

        <div className="home-highlight-grid home-highlight-grid--simple">
          {highlights.map((item) => (
            <article key={item.title} className="home-highlight-card home-highlight-card--simple">
              <h3>{item.title}</h3>
              <p>{item.text}</p>
              <Link to={item.to}>Open</Link>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
