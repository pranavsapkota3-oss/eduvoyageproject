import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { getUniversityWebsiteUrl } from "../utils/universityLinks";

const STORAGE_KEY = "expense_tracker_by_university_v1";
const APPLICATION_STORAGE_KEY = "university_application_flow_v1";

const COUNTRY_COST_GUIDES = {
  USA: {
    rent: [900, 1800],
    food: [280, 520],
    transport: [70, 180],
    utilities: [120, 260],
    insurance: [120, 260],
    books: [60, 140],
  },
  UK: {
    rent: [700, 1400],
    food: [220, 420],
    transport: [60, 160],
    utilities: [110, 220],
    insurance: [90, 180],
    books: [50, 120],
  },
  Canada: {
    rent: [750, 1500],
    food: [240, 430],
    transport: [65, 150],
    utilities: [110, 220],
    insurance: [90, 180],
    books: [55, 120],
  },
  Australia: {
    rent: [850, 1700],
    food: [260, 460],
    transport: [70, 170],
    utilities: [120, 240],
    insurance: [100, 190],
    books: [60, 130],
  },
};

const DEFAULT_GUIDE = {
  rent: [700, 1400],
  food: [220, 420],
  transport: [60, 160],
  utilities: [100, 210],
  insurance: [90, 180],
  books: [50, 120],
};

const DEFAULT_PLAN = {
  application_fee: "",
  transcript_fee: "",
  english_test_fee: "",
  visa_fee: "",
  courier_fee: "",
  deposit_fee: "",
  semester_fee: "",
  monthly_rent: "",
  monthly_insurance: "",
  monthly_food: "",
  monthly_transport: "",
  monthly_utilities: "",
  other_fee: "",
  other_note: "",
};

const ONE_TIME_FIELDS = [
  ["Application fee", "application_fee"],
  ["Transcript fee", "transcript_fee"],
  ["English test fee", "english_test_fee"],
  ["Visa fee", "visa_fee"],
  ["Courier fee", "courier_fee"],
  ["Deposit fee", "deposit_fee"],
  ["Other fee", "other_fee"],
];

const MONTHLY_FIELDS = [
  ["Rent", "monthly_rent"],
  ["Insurance", "monthly_insurance"],
  ["Food", "monthly_food"],
  ["Transport", "monthly_transport"],
  ["Utilities", "monthly_utilities"],
];

function readJson(key, fallback) {
  try {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function normalizeCountry(country = "") {
  const value = country.toLowerCase();
  if (value.includes("united states") || value === "usa") return "USA";
  if (value.includes("united kingdom") || value === "uk") return "UK";
  if (value.includes("canada")) return "Canada";
  if (value.includes("australia")) return "Australia";
  return country || "Other";
}

function parseAmount(value) {
  if (value === null || value === undefined) return 0;
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  const cleaned = String(value).replace(/[^0-9.]/g, "");
  const parsed = Number.parseFloat(cleaned);
  return Number.isFinite(parsed) ? parsed : 0;
}

function parseFeeAmount(feeText) {
  if (!feeText) return 0;
  const matches = String(feeText).match(/\d[\d,]*(?:\.\d+)?/g);
  if (!matches?.length) return 0;
  const values = matches.map((item) => parseAmount(item));
  return Math.max(...values, 0);
}

function formatMoney(amount, currency = "USD") {
  const safeAmount = Number.isFinite(amount) ? amount : 0;
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
    maximumFractionDigits: 0,
  }).format(safeAmount);
}

function getCurrencyByCountry(country) {
  const normalized = normalizeCountry(country);
  if (normalized === "USA") return "USD";
  if (normalized === "UK") return "GBP";
  if (normalized === "Canada") return "CAD";
  if (normalized === "Australia") return "AUD";
  return "USD";
}

function getCountryGuide(country) {
  const normalized = normalizeCountry(country);
  return COUNTRY_COST_GUIDES[normalized] || DEFAULT_GUIDE;
}

function getGuideMidpoint(range) {
  return Math.round((range[0] + range[1]) / 2);
}

function buildDefaultMonthlyPlan(country) {
  const guide = getCountryGuide(country);
  return {
    monthly_rent: getGuideMidpoint(guide.rent),
    monthly_insurance: getGuideMidpoint(guide.insurance),
    monthly_food: getGuideMidpoint(guide.food),
    monthly_transport: getGuideMidpoint(guide.transport),
    monthly_utilities: getGuideMidpoint(guide.utilities),
  };
}

function toStoredPlan(source, country) {
  return {
    ...DEFAULT_PLAN,
    ...buildDefaultMonthlyPlan(country),
    ...source,
  };
}

function sumValues(values) {
  return values.reduce((total, value) => total + parseAmount(value), 0);
}

function getMonthlyLivingTotal(plan, country) {
  const fallback = buildDefaultMonthlyPlan(country);
  return sumValues(
    MONTHLY_FIELDS.map(([, key]) => {
      const planValue = parseAmount(plan?.[key]);
      return planValue || fallback[key] || 0;
    })
  );
}

function buildComparisonSnapshot(university) {
  const annualTuition = parseFeeAmount(university?.fees);
  const guide = getCountryGuide(university?.country);
  const monthlyLiving = getGuideMidpoint(guide.rent)
    + getGuideMidpoint(guide.food)
    + getGuideMidpoint(guide.transport)
    + getGuideMidpoint(guide.utilities)
    + getGuideMidpoint(guide.insurance);

  return {
    annualTuition,
    monthlyLiving,
    yearlyLiving: monthlyLiving * 12,
    totalYearOne: annualTuition + monthlyLiving * 12,
  };
}

function PlannerBarChart({ data, tone = "blue" }) {
  const max = Math.max(...data.map((item) => item.value), 1);
  return (
    <div className={`planner-chart planner-chart--${tone}`}>
      {data.map((item) => (
        <div className="planner-chart__row" key={item.label}>
          <div className="planner-chart__meta">
            <span>{item.label}</span>
            <strong>{item.display}</strong>
          </div>
          <div className="planner-chart__track">
            <div
              className="planner-chart__fill"
              style={{ width: `${Math.max((item.value / max) * 100, item.value > 0 ? 10 : 0)}%` }}
            />
          </div>
        </div>
      ))}
    </div>
  );
}

export default function ExpenseTracker() {
  const [searchParams] = useSearchParams();
  const [universities, setUniversities] = useState([]);
  const [selectedUniversityId, setSelectedUniversityId] = useState("");
  const [compareUniversityId, setCompareUniversityId] = useState("");
  const [expensesMap, setExpensesMap] = useState({});
  const [applicationFlowMap, setApplicationFlowMap] = useState({});
  const [form, setForm] = useState({ category: "Rent", amount: "", month: "", note: "" });
  const [status, setStatus] = useState("");

  useEffect(() => {
    const loadUniversities = async () => {
      try {
        const params = new URLSearchParams({ page: "1", limit: "200" });
        const res = await fetch(`http://localhost:5000/api/universities?${params.toString()}`);
        const data = await res.json();
        if (!res.ok) return;
        setUniversities(data.universities || []);
      } catch {
        setUniversities([]);
      }
    };

    loadUniversities();
    setExpensesMap(readJson(STORAGE_KEY, {}));
    setApplicationFlowMap(readJson(APPLICATION_STORAGE_KEY, {}));
  }, []);

  useEffect(() => {
    if (!universities.length) return;
    const queryUniversityId = searchParams.get("university");
    const defaultId = queryUniversityId || String(universities[0]?.id || "");
    setSelectedUniversityId((prev) => prev || defaultId);
  }, [universities, searchParams]);

  useEffect(() => {
    const source = searchParams.get("source");
    const queryUniversityId = searchParams.get("university");
    if (source !== "application" || !queryUniversityId) return;

    const current = readJson(APPLICATION_STORAGE_KEY, {});
    const entry = current[String(queryUniversityId)];
    if (!entry) return;

    const nextMap = {
      ...current,
      [String(queryUniversityId)]: {
        ...entry,
        applied: true,
        pending_confirmation: false,
        confirmed_at: new Date().toISOString(),
        plan: toStoredPlan(entry.plan, entry.country),
      },
    };

    setApplicationFlowMap(nextMap);
    localStorage.setItem(APPLICATION_STORAGE_KEY, JSON.stringify(nextMap));
    setStatus("Application confirmed. Add your university-related expenses below.");
  }, [searchParams]);

  const selectedUniversity = useMemo(
    () => universities.find((item) => String(item.id) === String(selectedUniversityId)) || null,
    [selectedUniversityId, universities]
  );

  const compareUniversity = useMemo(
    () => universities.find((item) => String(item.id) === String(compareUniversityId)) || null,
    [compareUniversityId, universities]
  );

  const selectedCountry = normalizeCountry(selectedUniversity?.country);
  const currency = getCurrencyByCountry(selectedUniversity?.country);
  const annualTuition = parseFeeAmount(selectedUniversity?.fees);
  const currentExpenses = expensesMap[String(selectedUniversityId)] || [];
  const currentFlow = applicationFlowMap[String(selectedUniversityId)] || {};
  const applicationPlan = toStoredPlan(currentFlow.plan, selectedUniversity?.country);
  const didApply = currentFlow.applied === true;

  const countryRanges = useMemo(() => {
    const guide = getCountryGuide(selectedUniversity?.country);
    const totalMin = Object.values(guide).reduce((sum, [min]) => sum + min, 0);
    const totalMax = Object.values(guide).reduce((sum, [, max]) => sum + max, 0);
    return [
      { label: "Rent", range: guide.rent },
      { label: "Food", range: guide.food },
      { label: "Transport", range: guide.transport },
      { label: "Utilities", range: guide.utilities },
      { label: "Insurance", range: guide.insurance },
      { label: "Books", range: guide.books },
      { label: "Total monthly range", range: [totalMin, totalMax] },
    ];
  }, [selectedUniversity?.country]);

  const oneTimeCosts = useMemo(
    () =>
      ONE_TIME_FIELDS.map(([label, key]) => ({
        label,
        value: parseAmount(applicationPlan[key]),
      })).filter((item) => item.value > 0),
    [applicationPlan]
  );

  const preApplicationTotal = useMemo(
    () => sumValues(oneTimeCosts.map((item) => item.value)),
    [oneTimeCosts]
  );

  const plannedMonthlyLiving = useMemo(
    () => getMonthlyLivingTotal(applicationPlan, selectedUniversity?.country),
    [applicationPlan, selectedUniversity?.country]
  );

  const semesterTuition = parseAmount(applicationPlan.semester_fee);
  const tuitionYearTotal = semesterTuition > 0 ? semesterTuition * 2 : annualTuition;
  const yearlyLivingTotal = plannedMonthlyLiving * 12;
  const trackedActualTotal = sumValues(currentExpenses.map((item) => item.amount));
  const yearOneEstimate = preApplicationTotal + tuitionYearTotal + yearlyLivingTotal;

  const groupedSummary = [
    {
      label: "Pre-application costs",
      amount: preApplicationTotal,
      detail: "Application, transcript, visa, courier and deposit fees",
    },
    {
      label: "Tuition costs",
      amount: tuitionYearTotal,
      detail: semesterTuition > 0 ? "Using semester fee plan x 2" : "Using current annual tuition estimate",
    },
    {
      label: "Monthly living costs",
      amount: plannedMonthlyLiving,
      detail: "Rent, food, transport, utilities and insurance",
    },
    {
      label: "Yearly total",
      amount: yearOneEstimate,
      detail: "Year-one estimate using tuition plus 12 months of living cost",
    },
  ];

  const categoryBreakdown = useMemo(() => {
    const bucket = {
      Tuition: tuitionYearTotal,
      Rent: parseAmount(applicationPlan.monthly_rent) || buildDefaultMonthlyPlan(selectedUniversity?.country).monthly_rent,
      Food: parseAmount(applicationPlan.monthly_food) || buildDefaultMonthlyPlan(selectedUniversity?.country).monthly_food,
      Transport:
        parseAmount(applicationPlan.monthly_transport) || buildDefaultMonthlyPlan(selectedUniversity?.country).monthly_transport,
      Utilities:
        parseAmount(applicationPlan.monthly_utilities) || buildDefaultMonthlyPlan(selectedUniversity?.country).monthly_utilities,
      Insurance:
        parseAmount(applicationPlan.monthly_insurance) || buildDefaultMonthlyPlan(selectedUniversity?.country).monthly_insurance,
      Application: preApplicationTotal,
    };

    currentExpenses.forEach((expense) => {
      const key = expense.category || "Other";
      bucket[key] = (bucket[key] || 0) + parseAmount(expense.amount);
    });

    return Object.entries(bucket)
      .map(([label, value]) => ({ label, value, display: formatMoney(value, currency) }))
      .filter((item) => item.value > 0)
      .sort((a, b) => b.value - a.value);
  }, [applicationPlan, currentExpenses, currency, preApplicationTotal, selectedUniversity?.country, tuitionYearTotal]);

  const monthlyEstimateChart = useMemo(() => {
    const defaults = buildDefaultMonthlyPlan(selectedUniversity?.country);
    return [
      { label: "Rent", value: parseAmount(applicationPlan.monthly_rent) || defaults.monthly_rent },
      { label: "Food", value: parseAmount(applicationPlan.monthly_food) || defaults.monthly_food },
      { label: "Transport", value: parseAmount(applicationPlan.monthly_transport) || defaults.monthly_transport },
      { label: "Utilities", value: parseAmount(applicationPlan.monthly_utilities) || defaults.monthly_utilities },
      { label: "Insurance", value: parseAmount(applicationPlan.monthly_insurance) || defaults.monthly_insurance },
    ].map((item) => ({
      ...item,
      display: formatMoney(item.value, currency),
    }));
  }, [applicationPlan, currency, selectedUniversity?.country]);

  const comparison = useMemo(() => {
    if (!selectedUniversity || !compareUniversity) return null;
    const left = buildComparisonSnapshot(selectedUniversity);
    const right = buildComparisonSnapshot(compareUniversity);
    return { left, right };
  }, [compareUniversity, selectedUniversity]);

  const handleSubmitExpense = (event) => {
    event.preventDefault();
    if (!selectedUniversityId || !form.amount || !form.month) {
      setStatus("Choose a university and fill amount and month.");
      return;
    }

    const nextExpense = {
      id: Date.now(),
      category: form.category,
      amount: parseAmount(form.amount),
      month: form.month,
      note: form.note.trim(),
      created_at: new Date().toISOString(),
    };

    const nextMap = {
      ...expensesMap,
      [String(selectedUniversityId)]: [nextExpense, ...(expensesMap[String(selectedUniversityId)] || [])],
    };

    setExpensesMap(nextMap);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(nextMap));
    setForm({ category: "Rent", amount: "", month: "", note: "" });
    setStatus("Expense recorded.");
  };

  const deleteExpense = (expenseId) => {
    const nextItems = currentExpenses.filter((item) => item.id !== expenseId);
    const nextMap = { ...expensesMap, [String(selectedUniversityId)]: nextItems };
    setExpensesMap(nextMap);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(nextMap));
  };

  const updateApplicationPlanField = (field, value) => {
    const nextEntry = {
      ...currentFlow,
      plan: {
        ...toStoredPlan(currentFlow.plan, selectedUniversity?.country),
        [field]: value,
      },
    };
    const nextMap = {
      ...applicationFlowMap,
      [String(selectedUniversityId)]: nextEntry,
    };
    setApplicationFlowMap(nextMap);
  };

  const saveApplicationPlan = () => {
    localStorage.setItem(APPLICATION_STORAGE_KEY, JSON.stringify(applicationFlowMap));
    setStatus("Application cost plan saved.");
  };

  const setAppliedState = (applied) => {
    const nextMap = {
      ...applicationFlowMap,
      [String(selectedUniversityId)]: {
        ...currentFlow,
        applied,
        plan: toStoredPlan(currentFlow.plan, selectedUniversity?.country),
      },
    };
    setApplicationFlowMap(nextMap);
    localStorage.setItem(APPLICATION_STORAGE_KEY, JSON.stringify(nextMap));
  };

  const exportReport = () => {
    if (!selectedUniversity) return;

    const lines = [
      `EduVoyage Expense Report`,
      ``,
      `University: ${selectedUniversity.name}`,
      `Country: ${selectedUniversity.country || "-"}`,
      `City: ${selectedUniversity.city || "-"}`,
      `Tuition: ${selectedUniversity.fees || "Not available"}`,
      ``,
      `Grouped Summary`,
      ...groupedSummary.map((item) => `- ${item.label}: ${formatMoney(item.amount, currency)} (${item.detail})`),
      ``,
      `Country-Based Monthly Ranges`,
      ...countryRanges.map((item) => `- ${item.label}: ${formatMoney(item.range[0], currency)} to ${formatMoney(item.range[1], currency)}`),
      ``,
      `Recorded Expenses`,
      ...(currentExpenses.length
        ? currentExpenses.map(
            (item) => `- ${item.month}: ${item.category} ${formatMoney(item.amount, currency)}${item.note ? ` | ${item.note}` : ""}`
          )
        : ["- No recorded expenses yet."]),
    ];

    const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${selectedUniversity.name.replace(/[^a-z0-9]+/gi, "_").toLowerCase()}_expense_report.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <Navbar />
      <main className="expense-page">
        <section className="expense-hero">
          <div>
            <h1>Expense Planner</h1>
            <p>Plan year-one costs, compare university budgets, and keep a running record of every study-abroad expense.</p>

            <div className="expense-university-select">
              <label htmlFor="expense-university">Choose your primary university</label>
              <select
                id="expense-university"
                value={selectedUniversityId}
                onChange={(event) => setSelectedUniversityId(event.target.value)}
              >
                {universities.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="expense-hero__totals">
            <div className="expense-hero__total">
              <span>Year-one estimate</span>
              <strong>{formatMoney(yearOneEstimate, currency)}</strong>
            </div>
            <div className="expense-hero__total expense-hero__total--secondary">
              <span>Tracked spend</span>
              <strong>{formatMoney(trackedActualTotal, currency)}</strong>
            </div>
          </div>
        </section>

        {selectedUniversity && (
          <>
            <section className="expense-card expense-university-info">
              <h2>{selectedUniversity.name}</h2>
              <p>Use this planner to map application costs, tuition, monthly living expenses, and yearly budget before you apply.</p>
              <div className="expense-university-info__meta">
                <div>
                  <span>Location</span>
                  <strong>{selectedUniversity.city || "-"}, {selectedUniversity.country || "-"}</strong>
                </div>
                <div>
                  <span>Tuition range</span>
                  <strong>{selectedUniversity.fees || "Contact university"}</strong>
                </div>
                <div>
                  <span>Official website</span>
                  <strong>
                    <a href={getUniversityWebsiteUrl(selectedUniversity)} target="_blank" rel="noreferrer">
                      Visit university site
                    </a>
                  </strong>
                </div>
              </div>
            </section>

            {status && <p className="expense-status">{status}</p>}

            <section className="expense-card expense-application-flow">
              <div className="expense-application-flow__head">
                <div>
                  <h2>Pre-application planning</h2>
                  <p>
                    {didApply
                      ? "Track one-time application charges first, then add semester and monthly living costs."
                      : "Since you are still applying, start with IELTS, transcript, application, courier, visa, and deposit costs first."}
                  </p>
                </div>
                <Link className="expense-apply-link" to={`/universities/${selectedUniversity.id}`}>
                  Back to university details
                </Link>
              </div>

              <div className="expense-apply-prompt">
                <p>Did you already apply to {selectedUniversity.name}?</p>
                <div className="expense-apply-prompt__actions">
                  <button type="button" onClick={() => setAppliedState(true)}>Yes</button>
                  <button type="button" className="expense-apply-prompt__ghost" onClick={() => setAppliedState(false)}>
                    Not yet
                  </button>
                </div>
              </div>

              {didApply && (
                <div className="expense-application-form">
                  <div className="expense-application-form__intro">
                    <strong>Now add the actual expenses for this university.</strong>
                    <p>Include application costs first, then semester fee, rent, food, insurance, transport, and utilities.</p>
                  </div>
                  <div className="expense-application-grid">
                    {ONE_TIME_FIELDS.map(([label, key]) => (
                      <label key={key}>
                        <span>{label}</span>
                        <input
                          type="number"
                          min="0"
                          value={applicationPlan[key]}
                          onChange={(event) => updateApplicationPlanField(key, event.target.value)}
                        />
                      </label>
                    ))}

                    <label>
                      <span>Semester fee</span>
                      <input
                        type="number"
                        min="0"
                        value={applicationPlan.semester_fee}
                        onChange={(event) => updateApplicationPlanField("semester_fee", event.target.value)}
                      />
                    </label>

                    {MONTHLY_FIELDS.map(([label, key]) => (
                      <label key={key}>
                        <span>{label}</span>
                        <input
                          type="number"
                          min="0"
                          value={applicationPlan[key]}
                          onChange={(event) => updateApplicationPlanField(key, event.target.value)}
                        />
                      </label>
                    ))}

                    <label className="expense-application-grid__wide">
                      <span>Other fee note</span>
                      <input
                        type="text"
                        value={applicationPlan.other_note}
                        onChange={(event) => updateApplicationPlanField("other_note", event.target.value)}
                        placeholder="Optional note for misc. fee"
                      />
                    </label>
                  </div>

                  <button type="button" className="expense-application-save" onClick={saveApplicationPlan}>
                    Save planning data
                  </button>
                </div>
              )}
            </section>

            <section className="expense-layout expense-layout--planning">
              <article className="expense-card">
                <div className="expense-section-head">
                  <span>Budget map</span>
                  <h2>Grouped cost sections</h2>
                </div>
                {didApply ? (
                  <div className="expense-summary-grid">
                    {groupedSummary.map((item) => (
                      <div key={item.label} className="expense-summary-card">
                        <span>{item.label}</span>
                        <strong>
                          {item.label === "Monthly living costs"
                            ? `${formatMoney(item.amount, currency)}/month`
                            : formatMoney(item.amount, currency)}
                        </strong>
                        <p>{item.detail}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="expense-stage-card">
                    <span>Current stage</span>
                    <strong>You are still in the application stage.</strong>
                    <p>Monthly living costs will make more sense after you confirm the application. For now, focus on IELTS, transcript, application, courier, and visa-related spending.</p>
                  </div>
                )}
              </article>

              <article className="expense-card">
                <div className="expense-section-head">
                  <span>Suggested ranges</span>
                  <h2>{didApply ? `${selectedCountry} monthly living guide` : `${selectedCountry} early planning guide`}</h2>
                </div>
                <div className="expense-range-list">
                  {(didApply ? countryRanges : countryRanges.slice(0, 3)).map((item) => (
                    <div key={item.label} className="expense-range-row">
                      <strong>{item.label}</strong>
                      <span>
                        {formatMoney(item.range[0], currency)} - {formatMoney(item.range[1], currency)}
                      </span>
                    </div>
                  ))}
                </div>
              </article>
            </section>

            {didApply ? (
              <section className="expense-layout">
                <article className="expense-card">
                  <div className="expense-section-head">
                    <span>Planner charts</span>
                    <h2>Category breakdown</h2>
                  </div>
                  <PlannerBarChart data={categoryBreakdown.slice(0, 8)} />
                </article>

                <article className="expense-card">
                  <div className="expense-section-head">
                    <span>Monthly estimate</span>
                    <h2>Living cost by category</h2>
                  </div>
                  <PlannerBarChart data={monthlyEstimateChart} tone="teal" />
                </article>
              </section>
            ) : (
              <section className="expense-card expense-card--table">
                <div className="expense-section-head">
                  <span>Monthly costs</span>
                  <h2>Monthly planning unlocks after you confirm the application</h2>
                </div>
                <p className="expense-empty-note">
                  When you return from the university apply page and confirm <strong>Yes</strong>, this section will switch to the full semester and monthly living cost planner.
                </p>
              </section>
            )}

            <section className="expense-layout">
              <article className="expense-card">
                <div className="expense-section-head">
                  <span>Recorded spending</span>
                  <h2>Add an expense entry</h2>
                </div>
                <form className="expense-form" onSubmit={handleSubmitExpense}>
                  <select value={form.category} onChange={(event) => setForm((prev) => ({ ...prev, category: event.target.value }))}>
                      {["Rent", "Food", "Transport", "Utilities", "Insurance", "Tuition", "Visa", "Books", "IELTS", "Application", "Other"].map((option) => (
                      <option key={option} value={option}>
                        {option}
                      </option>
                    ))}
                  </select>
                  <input
                    type="number"
                    min="0"
                    placeholder="Amount"
                    value={form.amount}
                    onChange={(event) => setForm((prev) => ({ ...prev, amount: event.target.value }))}
                  />
                  <input
                    type="month"
                    value={form.month}
                    onChange={(event) => setForm((prev) => ({ ...prev, month: event.target.value }))}
                  />
                  <input
                    type="text"
                    placeholder="Note"
                    value={form.note}
                    onChange={(event) => setForm((prev) => ({ ...prev, note: event.target.value }))}
                  />
                  <button type="submit">Save</button>
                </form>

                <div className="expense-tracker-actions">
                  <button type="button" className="expense-report-btn" onClick={exportReport}>
                    Download report
                  </button>
                </div>
              </article>

              <article className="expense-card">
                <div className="expense-section-head">
                  <span>Compare options</span>
                  <h2>Compare cost with another university</h2>
                </div>
                <div className="expense-compare-select">
                  <label htmlFor="compare-university">Choose comparison university</label>
                  <select
                    id="compare-university"
                    value={compareUniversityId}
                    onChange={(event) => setCompareUniversityId(event.target.value)}
                  >
                    <option value="">Select university</option>
                    {universities
                      .filter((item) => String(item.id) !== String(selectedUniversityId))
                      .map((item) => (
                        <option key={item.id} value={item.id}>
                          {item.name}
                        </option>
                      ))}
                  </select>
                </div>

                {comparison ? (
                  <div className="expense-compare-grid">
                    <div className="expense-compare-card">
                      <h3>{selectedUniversity.name}</h3>
                      <p>Tuition: {formatMoney(comparison.left.annualTuition, currency)}</p>
                      <p>Monthly living: {formatMoney(comparison.left.monthlyLiving, currency)}</p>
                      <p>Year-one estimate: {formatMoney(comparison.left.totalYearOne, currency)}</p>
                    </div>
                    <div className="expense-compare-card expense-compare-card--accent">
                      <h3>{compareUniversity.name}</h3>
                      <p>Tuition: {formatMoney(comparison.right.annualTuition, getCurrencyByCountry(compareUniversity.country))}</p>
                      <p>Monthly living: {formatMoney(comparison.right.monthlyLiving, getCurrencyByCountry(compareUniversity.country))}</p>
                      <p>Year-one estimate: {formatMoney(comparison.right.totalYearOne, getCurrencyByCountry(compareUniversity.country))}</p>
                    </div>
                  </div>
                ) : (
                  <p className="expense-empty-note">Choose another university to compare tuition and living-cost estimates side by side.</p>
                )}
              </article>
            </section>

            <section className="expense-card expense-card--table">
              <div className="expense-section-head">
                <span>History</span>
                <h2>Recorded expenses</h2>
              </div>
              <div className="expense-table-wrap">
                <table className="expense-table">
                  <thead>
                    <tr>
                      <th>Month</th>
                      <th>Category</th>
                      <th>Amount</th>
                      <th>Note</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {currentExpenses.length ? (
                      currentExpenses.map((expense) => (
                        <tr key={expense.id}>
                          <td>{expense.month}</td>
                          <td>{expense.category}</td>
                          <td>{formatMoney(expense.amount, currency)}</td>
                          <td>{expense.note || "-"}</td>
                          <td>
                            <button type="button" className="expense-delete-btn" onClick={() => deleteExpense(expense.id)}>
                              Delete
                            </button>
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="5">No expenses recorded yet. Start by saving one from the form above.</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </main>
      <Footer />
    </>
  );
}
