import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import Navbar from "../components/Navbar";
import Footer from "../components/Footer";
import { getUniversityWebsiteUrl } from "../utils/universityLinks";

const APPLICATION_STORAGE_KEY = "university_application_flow_v1";

const STEP_KEYS = ["before-applying", "after-arriving", "monthly-plan", "expense-log", "compare"];

const DEFAULT_PLAN = {
  planner_stage: "before-applying",
  has_arrived: "",
  works_part_time: "",
  weekly_income: "",
  application_fee: "",
  transcript_fee: "",
  english_test_fee: "",
  visa_fee: "",
  courier_fee: "",
  deposit_fee: "",
  other_fee: "",
  other_note: "",
  semester_fee: "",
  monthly_rent: "",
  monthly_food: "",
  monthly_transport: "",
  monthly_utilities: "",
  monthly_insurance: "",
};

const BEFORE_APPLY_FIELDS = [
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
  ["Food", "monthly_food"],
  ["Transport", "monthly_transport"],
  ["Utilities", "monthly_utilities"],
  ["Insurance", "monthly_insurance"],
];

const EXPENSE_CATEGORIES = [
  "Application",
  "Transcript",
  "English Test",
  "Visa",
  "Courier",
  "Deposit",
  "Semester Fee",
  "Rent",
  "Food",
  "Transport",
  "Utilities",
  "Insurance",
  "Other",
];

const INCOME_CATEGORIES = ["Part-time income", "Family support", "Scholarship", "Other"];

const COUNTRY_COST_GUIDES = {
  USA: { rent: 1350, food: 400, transport: 120, utilities: 180, insurance: 180 },
  UK: { rent: 1050, food: 320, transport: 110, utilities: 150, insurance: 130 },
  Canada: { rent: 1100, food: 340, transport: 115, utilities: 160, insurance: 140 },
  Australia: { rent: 1250, food: 360, transport: 120, utilities: 170, insurance: 150 },
};

function parseAmount(value) {
  if (value === null || value === undefined || value === "") return 0;
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  const cleaned = String(value).replace(/[^0-9.]/g, "");
  const parsed = Number.parseFloat(cleaned);
  return Number.isFinite(parsed) ? parsed : 0;
}

function parseFeeAmount(feeText) {
  if (!feeText) return 0;
  const matches = String(feeText).match(/\d[\d,]*(?:\.\d+)?/g);
  if (!matches?.length) return 0;
  return Math.max(...matches.map((item) => parseAmount(item)), 0);
}

function formatMoney(amount, currency = "USD") {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency,
    maximumFractionDigits: 0,
  }).format(Number.isFinite(amount) ? amount : 0);
}

function sumValues(values) {
  return values.reduce((total, value) => total + parseAmount(value), 0);
}

function normalizeCountry(country = "") {
  const value = String(country).toLowerCase();
  if (value.includes("united states") || value === "usa") return "USA";
  if (value.includes("united kingdom") || value === "uk") return "UK";
  if (value.includes("canada")) return "Canada";
  if (value.includes("australia")) return "Australia";
  return "Other";
}

function getCurrencyByCountry(country) {
  const normalized = normalizeCountry(country);
  if (normalized === "USA") return "USD";
  if (normalized === "UK") return "GBP";
  if (normalized === "Canada") return "CAD";
  if (normalized === "Australia") return "AUD";
  return "USD";
}

function getGuide(country) {
  return COUNTRY_COST_GUIDES[normalizeCountry(country)] || COUNTRY_COST_GUIDES.USA;
}

function getDefaultExpenseMonth() {
  return new Date().toISOString().slice(0, 7);
}

function normalizePlannerStage(value) {
  const current = String(value || "").trim().toLowerCase();
  if (["before-applying", "after-arriving", "monthly-plan", "expense-log", "compare"].includes(current)) {
    return current;
  }
  if (current === "applying") return "before-applying";
  if (current === "arrived") return "after-arriving";
  if (current === "living") return "monthly-plan";
  return "before-applying";
}

function toStoredPlan(source = {}) {
  return {
    ...DEFAULT_PLAN,
    ...source,
    planner_stage: normalizePlannerStage(source?.planner_stage),
    has_arrived:
      source?.has_arrived === true || source?.has_arrived === 1 || source?.has_arrived === "1" || source?.has_arrived === "yes"
        ? "yes"
        : source?.has_arrived === false || source?.has_arrived === 0 || source?.has_arrived === "0" || source?.has_arrived === "no"
          ? "no"
          : "",
    works_part_time:
      source?.works_part_time === true || source?.works_part_time === 1 || source?.works_part_time === "1" || source?.works_part_time === "yes"
        ? "yes"
        : source?.works_part_time === false || source?.works_part_time === 0 || source?.works_part_time === "0" || source?.works_part_time === "no"
          ? "no"
          : "",
  };
}

function getLatestApplicationUniversityId() {
  try {
    const raw = localStorage.getItem(APPLICATION_STORAGE_KEY);
    const all = raw ? JSON.parse(raw) : {};
    const rankedEntries = Object.values(all)
      .filter((item) => item?.university_id)
      .sort((a, b) => {
        const aPending = a?.pending_confirmation ? 1 : 0;
        const bPending = b?.pending_confirmation ? 1 : 0;
        if (aPending !== bPending) return bPending - aPending;
        const aTime = new Date(a?.opened_apply_at || a?.confirmed_at || 0).getTime();
        const bTime = new Date(b?.opened_apply_at || b?.confirmed_at || 0).getTime();
        return bTime - aTime;
      });

    return rankedEntries[0] ? String(rankedEntries[0].university_id) : "";
  } catch {
    return "";
  }
}

function getPlannerEntryMonth(updatedAt) {
  if (!updatedAt) return getDefaultExpenseMonth();
  const parsed = new Date(updatedAt);
  if (Number.isNaN(parsed.getTime())) return getDefaultExpenseMonth();
  return parsed.toISOString().slice(0, 7);
}

function getPlannerEntries(plan, updatedAt) {
  const plannerMonth = getPlannerEntryMonth(updatedAt);
  const baseEntries = [
    ...BEFORE_APPLY_FIELDS.map(([label, key]) => ({
      label,
      key,
      category: label.replace(" fee", ""),
      amount: parseAmount(plan[key]),
      note: key === "other_fee" ? plan.other_note || "Saved from planner" : "Saved from planner",
    })),
    { label: "Semester fee", key: "semester_fee", category: "Semester Fee", amount: parseAmount(plan.semester_fee), note: "Saved from planner" },
    ...MONTHLY_FIELDS.map(([label, key]) => ({
      label,
      key,
      category: label,
      amount: parseAmount(plan[key]),
      note: "Saved from planner",
    })),
  ];

  return baseEntries
    .filter((entry) => entry.amount > 0)
    .map((entry) => ({
      id: `planner-${entry.key}`,
      entry_type: "expense",
      category: entry.category,
      amount: entry.amount,
      month: plannerMonth,
      note: entry.note,
      source: "planner",
      created_at: updatedAt || null,
    }));
}

function sortEntries(entries) {
  return [...entries].sort((a, b) => {
    const monthCompare = String(b.month || "").localeCompare(String(a.month || ""));
    if (monthCompare !== 0) return monthCompare;
    return new Date(b.created_at || 0).getTime() - new Date(a.created_at || 0).getTime();
  });
}

export default function ExpenseTracker() {
  const [searchParams] = useSearchParams();
  const token = localStorage.getItem("token");
  const [universities, setUniversities] = useState([]);
  const [selectedUniversityId, setSelectedUniversityId] = useState("");
  const [compareUniversityId, setCompareUniversityId] = useState("");
  const [activeStep, setActiveStep] = useState("before-applying");
  const [applicationFlowMap, setApplicationFlowMap] = useState({});
  const [expensesMap, setExpensesMap] = useState({});
  const [status, setStatus] = useState("");
  const [statusKind, setStatusKind] = useState("");
  const [isSavingPlan, setIsSavingPlan] = useState(false);
  const [isSavingEntry, setIsSavingEntry] = useState(false);
  const [editingExpenseId, setEditingExpenseId] = useState(null);
  const [form, setForm] = useState({
    entryType: "expense",
    category: "Rent",
    amount: "",
    month: getDefaultExpenseMonth(),
    note: "",
  });

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
  }, []);

  useEffect(() => {
    if (!universities.length) return;
    const queryUniversityId = searchParams.get("university");
    const storedUniversityId = getLatestApplicationUniversityId();
    const resolvedUniversityId =
      queryUniversityId
      || (storedUniversityId && universities.some((item) => String(item.id) === storedUniversityId) ? storedUniversityId : "")
      || String(universities[0]?.id || "");
    setSelectedUniversityId((prev) => prev || resolvedUniversityId);
  }, [universities, searchParams]);

  useEffect(() => {
    const loadExpensePlans = async () => {
      if (!token) {
        setApplicationFlowMap({});
        return;
      }

      try {
        const res = await fetch("http://localhost:5000/api/expense-plans", {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        if (!res.ok) return;

        const nextMap = (data.plans || []).reduce((acc, plan) => {
          acc[String(plan.university_id)] = {
            applied: !!plan.applied,
            plan: toStoredPlan(plan),
            updated_at: plan.updated_at || null,
          };
          return acc;
        }, {});

        setApplicationFlowMap(nextMap);
      } catch {
        setApplicationFlowMap({});
      }
    };

    loadExpensePlans();
  }, [token]);

  useEffect(() => {
    const loadExpenseEntries = async () => {
      if (!token || !selectedUniversityId) return;

      try {
        const params = new URLSearchParams({ university_id: String(selectedUniversityId) });
        const res = await fetch(`http://localhost:5000/api/expense-entries?${params.toString()}`, {
          headers: { Authorization: `Bearer ${token}` },
        });
        const data = await res.json();
        if (!res.ok) return;

        setExpensesMap((prev) => ({
          ...prev,
          [String(selectedUniversityId)]: data.expenses || [],
        }));
      } catch {
        setExpensesMap((prev) => ({
          ...prev,
          [String(selectedUniversityId)]: [],
        }));
      }
    };

    loadExpenseEntries();
  }, [selectedUniversityId, token]);

  const selectedUniversity = useMemo(
    () => universities.find((item) => String(item.id) === String(selectedUniversityId)) || null,
    [selectedUniversityId, universities]
  );

  const compareUniversity = useMemo(
    () => universities.find((item) => String(item.id) === String(compareUniversityId)) || null,
    [compareUniversityId, universities]
  );

  const currentFlow = applicationFlowMap[String(selectedUniversityId)] || {};
  const plan = toStoredPlan(currentFlow.plan || {});
  const didApply = currentFlow.applied === true;
  const selectedCurrency = getCurrencyByCountry(selectedUniversity?.country);
  const weeklyIncome = parseAmount(plan.weekly_income);
  const worksPartTime = plan.works_part_time === "yes";
  const oneTimeTotal = sumValues(BEFORE_APPLY_FIELDS.map(([, key]) => plan[key]));
  const monthlyLivingTotal = sumValues(MONTHLY_FIELDS.map(([, key]) => plan[key]));
  const yearlyTuition = parseAmount(plan.semester_fee) * 2;
  const estimatedYearOne = oneTimeTotal + yearlyTuition + monthlyLivingTotal * 12;
  const currentEntries = expensesMap[String(selectedUniversityId)] || [];
  const plannerEntries = useMemo(
    () => getPlannerEntries(plan, currentFlow.updated_at),
    [currentFlow.updated_at, plan]
  );
  const allEntries = useMemo(
    () => sortEntries([...plannerEntries, ...currentEntries]),
    [currentEntries, plannerEntries]
  );
  const spentSoFar = sumValues(allEntries.filter((entry) => entry.entry_type !== "income").map((entry) => entry.amount));
  const moneyReceived = sumValues(currentEntries.filter((entry) => entry.entry_type === "income").map((entry) => entry.amount));
  const monthlyIncome = weeklyIncome * 4;
  const leftAmount = monthlyIncome + moneyReceived - spentSoFar;
  const compareGuide = getGuide(compareUniversity?.country);
  const compareTotal = compareUniversity
    ? parseFeeAmount(compareUniversity.fees)
      + (compareGuide.rent + compareGuide.food + compareGuide.transport + compareGuide.utilities + compareGuide.insurance) * 12
    : 0;
  const difference = compareUniversity ? estimatedYearOne - compareTotal : 0;
  const comparisonAreas = compareUniversity
    ? [
        { label: "Tuition", value: yearlyTuition - parseFeeAmount(compareUniversity.fees) },
        {
          label: "Living cost",
          value: monthlyLivingTotal * 12 - (compareGuide.rent + compareGuide.food + compareGuide.transport + compareGuide.utilities + compareGuide.insurance) * 12,
        },
        { label: "Before applying", value: oneTimeTotal },
      ]
    : [];
  const mainDifference = comparisonAreas.length
    ? comparisonAreas.reduce((best, current) => (Math.abs(current.value) > Math.abs(best.value) ? current : best), comparisonAreas[0])
    : null;

  useEffect(() => {
    if (!selectedUniversityId) return;
    const savedStep = normalizePlannerStage(currentFlow?.plan?.planner_stage);
    setActiveStep((prev) => {
      if (prev === "compare") return prev;
      if (!didApply && prev !== "before-applying") return "before-applying";
      return savedStep || "before-applying";
    });
  }, [currentFlow?.plan?.planner_stage, didApply, selectedUniversityId]);

  useEffect(() => {
    setCompareUniversityId((prev) => (String(prev) === String(selectedUniversityId) ? "" : prev));
  }, [selectedUniversityId]);

  const ensureLoggedIn = () => {
    if (token) return true;
    setStatus("Login first to save expense data.");
    setStatusKind("error");
    return false;
  };

  const syncApplicationStorage = (universityId, updates) => {
    try {
      const raw = localStorage.getItem(APPLICATION_STORAGE_KEY);
      const all = raw ? JSON.parse(raw) : {};
      const key = String(universityId);
      if (!all[key]) return;
      all[key] = { ...all[key], ...updates };
      localStorage.setItem(APPLICATION_STORAGE_KEY, JSON.stringify(all));
    } catch {
      // ignore localStorage issues
    }
  };

  const updateLocalPlan = (patch) => {
    const key = String(selectedUniversityId);
    setApplicationFlowMap((prev) => ({
      ...prev,
      [key]: {
        applied: prev[key]?.applied ?? false,
        updated_at: prev[key]?.updated_at ?? null,
        plan: {
          ...toStoredPlan(prev[key]?.plan || {}),
          ...patch,
        },
      },
    }));
  };

  const savePlan = async ({ nextStep, successMessage, appliedOverride } = {}) => {
    if (!selectedUniversityId || !ensureLoggedIn()) return false;

    const key = String(selectedUniversityId);
    const current = applicationFlowMap[key] || {};
    const applied = typeof appliedOverride === "boolean" ? appliedOverride : !!current.applied;
    const planToSave = {
      ...toStoredPlan(current.plan || {}),
      planner_stage: nextStep || activeStep,
    };

    try {
      setIsSavingPlan(true);
      setStatus("");
      setStatusKind("");
      const res = await fetch(`http://localhost:5000/api/expense-plans/${selectedUniversityId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          applied,
          ...planToSave,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        setStatus(data.message || "Could not save expense plan.");
        setStatusKind("error");
        return false;
      }

      setApplicationFlowMap((prev) => ({
        ...prev,
        [key]: {
          applied,
          updated_at: data.plan?.updated_at || new Date().toISOString(),
          plan: toStoredPlan(data.plan || planToSave),
        },
      }));

      syncApplicationStorage(selectedUniversityId, {
        confirmed_applied: applied,
        pending_confirmation: false,
        confirmed_at: new Date().toISOString(),
      });

      if (nextStep) {
        setActiveStep(nextStep);
      }

      if (successMessage) {
        setStatus(successMessage);
        setStatusKind("success");
      }

      return true;
    } catch {
      setStatus("Could not save expense plan.");
      setStatusKind("error");
      return false;
    } finally {
      setIsSavingPlan(false);
    }
  };

  const handleAppliedChoice = async (value) => {
    if (!selectedUniversityId || !ensureLoggedIn()) return;
    const applied = value === "yes";
    updateLocalPlan({});
    setApplicationFlowMap((prev) => ({
      ...prev,
      [String(selectedUniversityId)]: {
        applied,
        updated_at: prev[String(selectedUniversityId)]?.updated_at || null,
        plan: toStoredPlan(prev[String(selectedUniversityId)]?.plan || {}),
      },
    }));
    if (!applied) {
      setActiveStep("before-applying");
    }
    await savePlan({
      appliedOverride: applied,
      nextStep: applied ? normalizePlannerStage(plan.planner_stage) : "before-applying",
      successMessage: applied ? "Application confirmed. Continue through the steps below." : "Application status saved. Start from before applying.",
    });
  };

  const handlePlanFieldChange = (key, value) => {
    updateLocalPlan({ [key]: value });
  };

  const resetEntryForm = () => {
    setEditingExpenseId(null);
    setForm({
      entryType: "expense",
      category: "Rent",
      amount: "",
      month: getDefaultExpenseMonth(),
      note: "",
    });
  };

  const handleSubmitEntry = async (event) => {
    event.preventDefault();
    if (!selectedUniversityId || !ensureLoggedIn()) return;

    const endpoint = editingExpenseId
      ? `http://localhost:5000/api/expense-entries/${editingExpenseId}`
      : "http://localhost:5000/api/expense-entries";
    const method = editingExpenseId ? "PUT" : "POST";

    try {
      setIsSavingEntry(true);
      setStatus("");
      setStatusKind("");
      const res = await fetch(endpoint, {
        method,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          university_id: selectedUniversityId,
          entry_type: form.entryType,
          category: form.category,
          amount: form.amount,
          month: form.month,
          note: form.note,
        }),
      });
      const data = await res.json();

      if (!res.ok) {
        setStatus(data.message || "Could not save record.");
        setStatusKind("error");
        return;
      }

      setExpensesMap((prev) => {
        const current = prev[String(selectedUniversityId)] || [];
        const nextItems = editingExpenseId
          ? current.map((item) => (item.id === editingExpenseId ? data.expense : item))
          : [data.expense, ...current];
        return {
          ...prev,
          [String(selectedUniversityId)]: nextItems,
        };
      });
      resetEntryForm();
      setStatus(editingExpenseId ? "Record updated." : "Record saved.");
      setStatusKind("success");
    } catch {
      setStatus("Could not save record.");
      setStatusKind("error");
    } finally {
      setIsSavingEntry(false);
    }
  };

  const startEditing = (entry) => {
    setEditingExpenseId(entry.id);
    setForm({
      entryType: entry.entry_type === "income" ? "income" : "expense",
      category: entry.category || "Rent",
      amount: String(entry.amount || ""),
      month: entry.month || getDefaultExpenseMonth(),
      note: entry.note || "",
    });
    setActiveStep("expense-log");
  };

  const deleteEntry = async (entryId) => {
    if (!ensureLoggedIn()) return;

    try {
      const res = await fetch(`http://localhost:5000/api/expense-entries/${entryId}`, {
        method: "DELETE",
        headers: { Authorization: `Bearer ${token}` },
      });
      const data = await res.json();
      if (!res.ok) {
        setStatus(data.message || "Could not delete record.");
        setStatusKind("error");
        return;
      }

      setExpensesMap((prev) => ({
        ...prev,
        [String(selectedUniversityId)]: (prev[String(selectedUniversityId)] || []).filter((entry) => entry.id !== entryId),
      }));
      setStatus("Record deleted.");
      setStatusKind("success");
    } catch {
      setStatus("Could not delete record.");
      setStatusKind("error");
    }
  };

  const exportReport = () => {
    if (!selectedUniversity) return;

    const lines = [
      `Expense Tracker Report - ${selectedUniversity.name}`,
      `Estimated year-one cost: ${formatMoney(estimatedYearOne, selectedCurrency)}`,
      `Monthly living cost: ${formatMoney(monthlyLivingTotal, selectedCurrency)}`,
      `Weekly income: ${weeklyIncome ? formatMoney(weeklyIncome, selectedCurrency) : "Not added"}`,
      `Spent so far: ${formatMoney(spentSoFar, selectedCurrency)}`,
      `Money received: ${formatMoney(moneyReceived, selectedCurrency)}`,
      `Left: ${formatMoney(leftAmount, selectedCurrency)}`,
      "",
      "Expense log:",
      ...allEntries.map((entry) => `${entry.month} - ${entry.category} - ${formatMoney(parseAmount(entry.amount), selectedCurrency)}${entry.entry_type === "income" ? " (Money received)" : ""}${entry.note ? ` - ${entry.note}` : ""}`),
    ];

    const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${selectedUniversity.name.replace(/[^a-z0-9]+/gi, "-").toLowerCase()}-expense-report.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const topSummaryCards = [
    {
      label: "Estimated year-one cost",
      value: formatMoney(estimatedYearOne, selectedCurrency),
      note: "Upfront, tuition, and 12 months of living cost.",
    },
    {
      label: "Monthly living cost",
      value: formatMoney(monthlyLivingTotal, selectedCurrency),
      note: "Rent, food, transport, utilities, and insurance.",
    },
    {
      label: "Your weekly income",
      value: weeklyIncome ? formatMoney(weeklyIncome, selectedCurrency) : "Not added",
      note: worksPartTime ? "Based on your current part-time work entry." : "Add this after arriving if you work.",
    },
    {
      label: "Income vs expense",
      value: monthlyIncome || moneyReceived || spentSoFar ? formatMoney(leftAmount, selectedCurrency) : "No income added",
      note:
        !(monthlyIncome || moneyReceived)
          ? "Add weekly income or money received to see your balance."
          : leftAmount < 0
            ? `You're in loss by ${formatMoney(Math.abs(leftAmount), selectedCurrency)}.`
            : `You're in profit by ${formatMoney(leftAmount, selectedCurrency)}.`,
    },
  ];

  const compareInsight = compareUniversity
    ? difference === 0
      ? "Both universities currently look equal on the year-one estimate."
      : `${selectedUniversity?.name || "This university"} is ${difference > 0 ? "more expensive" : "cheaper"} than ${compareUniversity.name} by ${formatMoney(Math.abs(difference), selectedCurrency)}. Main difference: ${mainDifference?.label || "overall total"}.`
    : "";

  const stepDisabled = (step) => !didApply && ["after-arriving", "monthly-plan", "expense-log"].includes(step);
  const currentEntryCategories = form.entryType === "income" ? INCOME_CATEGORIES : EXPENSE_CATEGORIES;

  return (
    <>
      <Navbar />
      <main className="expense-final-page">
        <section className="expense-final-hero">
          <div>
            <p className="expense-final-hero__eyebrow">Expense tracker</p>
            <h1>{selectedUniversity ? selectedUniversity.name : "Choose a university"}</h1>
            <p>
              {selectedUniversity
                ? `${selectedUniversity.city || ""}${selectedUniversity.city && selectedUniversity.country ? ", " : ""}${selectedUniversity.country || ""}`
                : "Select one university and track the whole cost flow step by step."}
            </p>
          </div>
          <div className="expense-final-hero__actions">
            <select value={selectedUniversityId} onChange={(event) => setSelectedUniversityId(event.target.value)}>
              {universities.map((university) => (
                <option key={university.id} value={university.id}>
                  {university.name}
                </option>
              ))}
            </select>
            {selectedUniversity && (
              <>
                <Link to={`/universities/${selectedUniversity.id}`} className="expense-final-link">
                  View university
                </Link>
                {getUniversityWebsiteUrl(selectedUniversity) && (
                  <a className="expense-final-link expense-final-link--ghost" href={getUniversityWebsiteUrl(selectedUniversity)} target="_blank" rel="noreferrer">
                    Visit website
                  </a>
                )}
              </>
            )}
          </div>
        </section>

        <section className="expense-final-apply">
          <div>
            <span>Did you apply to this university?</span>
            <p>Keep this updated so the later steps open at the right time.</p>
          </div>
          <div className="expense-final-choice">
            <button
              type="button"
              className={didApply ? "expense-final-choice__btn expense-final-choice__btn--active" : "expense-final-choice__btn"}
              onClick={() => handleAppliedChoice("yes")}
            >
              Yes
            </button>
            <button
              type="button"
              className={!didApply ? "expense-final-choice__btn expense-final-choice__btn--active" : "expense-final-choice__btn"}
              onClick={() => handleAppliedChoice("no")}
            >
              No
            </button>
          </div>
        </section>

        {status && <p className={`settings-state ${statusKind === "success" ? "settings-state--success" : "settings-state--error"}`}>{status}</p>}

        <section className="expense-final-summary">
          {topSummaryCards.map((card) => (
            <article key={card.label} className="expense-final-summary__card">
              <span>{card.label}</span>
              <strong>{card.value}</strong>
              <p>{card.note}</p>
            </article>
          ))}
        </section>

        <section className="expense-final-steps">
          {STEP_KEYS.map((step) => (
            <button
              key={step}
              type="button"
              className={activeStep === step ? "expense-final-step expense-final-step--active" : "expense-final-step"}
              disabled={stepDisabled(step)}
              onClick={() => setActiveStep(step)}
            >
              {step === "before-applying" && "Before applying"}
              {step === "after-arriving" && "After arriving"}
              {step === "monthly-plan" && "Monthly plan"}
              {step === "expense-log" && "Expense log"}
              {step === "compare" && "Compare"}
            </button>
          ))}
        </section>

        {activeStep === "before-applying" && (
          <section className="expense-final-card">
            <div className="expense-final-card__head">
              <span>Step 1</span>
              <h2>Before applying</h2>
              <p>Only add the one-time costs you expect before or during the application process.</p>
            </div>
            <div className="expense-final-grid">
              {BEFORE_APPLY_FIELDS.map(([label, key]) => (
                <label key={key}>
                  <span>{label}</span>
                  <input type="number" min="0" value={plan[key]} onChange={(event) => handlePlanFieldChange(key, event.target.value)} />
                </label>
              ))}
              <label className="expense-final-grid__wide">
                <span>Other fee note</span>
                <input type="text" value={plan.other_note} placeholder="Optional note" onChange={(event) => handlePlanFieldChange("other_note", event.target.value)} />
              </label>
            </div>
            <div className="expense-final-actions">
              <button type="button" className="expense-final-primary" onClick={() => savePlan({ nextStep: didApply ? "after-arriving" : "before-applying", successMessage: didApply ? "Before applying costs saved." : "Before applying costs saved. Mark the university as applied when you move to the next step." })}>
                {isSavingPlan ? "Saving..." : "Save and continue"}
              </button>
            </div>
          </section>
        )}

        {activeStep === "after-arriving" && (
          <section className="expense-final-card">
            <div className="expense-final-card__head">
              <span>Step 2</span>
              <h2>After arriving</h2>
              <p>Answer these simple arrival questions before you move to monthly costs.</p>
            </div>
            <div className="expense-final-grid expense-final-grid--compact">
              <label>
                <span>Have you arrived?</span>
                <select value={plan.has_arrived} onChange={(event) => handlePlanFieldChange("has_arrived", event.target.value)}>
                  <option value="">Select</option>
                  <option value="yes">Yes</option>
                  <option value="no">No</option>
                </select>
              </label>
              <label>
                <span>Do you work?</span>
                <select value={plan.works_part_time} onChange={(event) => handlePlanFieldChange("works_part_time", event.target.value)}>
                  <option value="">Select</option>
                  <option value="yes">Yes</option>
                  <option value="no">No</option>
                </select>
              </label>
              {plan.works_part_time === "yes" && (
                <label>
                  <span>Weekly income</span>
                  <input type="number" min="0" value={plan.weekly_income} onChange={(event) => handlePlanFieldChange("weekly_income", event.target.value)} />
                </label>
              )}
            </div>
            <div className="expense-final-actions">
              <button type="button" className="expense-final-secondary" onClick={() => setActiveStep("before-applying")}>
                Back
              </button>
              <button type="button" className="expense-final-primary" onClick={() => savePlan({ nextStep: "monthly-plan", successMessage: "Arrival details saved." })}>
                {isSavingPlan ? "Saving..." : "Save and continue"}
              </button>
            </div>
          </section>
        )}

        {activeStep === "monthly-plan" && (
          <section className="expense-final-card">
            <div className="expense-final-card__head">
              <span>Step 3</span>
              <h2>Monthly living + tuition</h2>
              <p>Add semester fee and simple monthly costs only.</p>
            </div>
            <div className="expense-final-grid">
              <label>
                <span>Semester fee</span>
                <input type="number" min="0" value={plan.semester_fee} onChange={(event) => handlePlanFieldChange("semester_fee", event.target.value)} />
              </label>
              {MONTHLY_FIELDS.map(([label, key]) => (
                <label key={key}>
                  <span>{label}</span>
                  <input type="number" min="0" value={plan[key]} onChange={(event) => handlePlanFieldChange(key, event.target.value)} />
                </label>
              ))}
            </div>
            <div className="expense-final-actions">
              <button type="button" className="expense-final-secondary" onClick={() => setActiveStep("after-arriving")}>
                Back
              </button>
              <button type="button" className="expense-final-primary" onClick={() => savePlan({ nextStep: "expense-log", successMessage: "Monthly plan saved." })}>
                {isSavingPlan ? "Saving..." : "Save all expenses"}
              </button>
            </div>
          </section>
        )}

        {activeStep === "expense-log" && (
          <>
            <section className="expense-final-card">
              <div className="expense-final-card__head">
                <span>Step 4</span>
                <h2>Expense log</h2>
                <p>Add real expense rows or money received entries here.</p>
              </div>

              <div className="expense-final-record-summary">
                <article className="expense-final-record-summary__card">
                  <span>Spent so far</span>
                  <strong>{formatMoney(spentSoFar, selectedCurrency)}</strong>
                  <p>Total of all expense rows shown below.</p>
                </article>
                <article className="expense-final-record-summary__card">
                  <span>Money received</span>
                  <strong>{formatMoney(moneyReceived, selectedCurrency)}</strong>
                  <p>Total of the money received entries from the log.</p>
                </article>
                <article className="expense-final-record-summary__card">
                  <span>Left</span>
                  <strong>{monthlyIncome || moneyReceived ? formatMoney(leftAmount, selectedCurrency) : "No income added"}</strong>
                  <p>{leftAmount < 0 ? `You're in loss by ${formatMoney(Math.abs(leftAmount), selectedCurrency)}.` : "Money left after weekly income and received money."}</p>
                </article>
              </div>

              <form className="expense-final-entry-form" onSubmit={handleSubmitEntry}>
                <select value={form.entryType} onChange={(event) => setForm((prev) => ({ ...prev, entryType: event.target.value, category: event.target.value === "income" ? INCOME_CATEGORIES[0] : EXPENSE_CATEGORIES[0] }))}>
                  <option value="expense">Expense</option>
                  <option value="income">Money received</option>
                </select>
                <select value={form.category} onChange={(event) => setForm((prev) => ({ ...prev, category: event.target.value }))}>
                  {currentEntryCategories.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
                <input type="number" min="0" placeholder="Amount" value={form.amount} onChange={(event) => setForm((prev) => ({ ...prev, amount: event.target.value }))} />
                <input type="month" value={form.month} onChange={(event) => setForm((prev) => ({ ...prev, month: event.target.value }))} />
                <input type="text" placeholder="Note" value={form.note} onChange={(event) => setForm((prev) => ({ ...prev, note: event.target.value }))} />
                <button type="submit" className="expense-final-primary">
                  {isSavingEntry ? "Saving..." : editingExpenseId ? "Update" : "Save"}
                </button>
              </form>

              <div className="expense-final-actions expense-final-actions--inline">
                {editingExpenseId && (
                  <button type="button" className="expense-final-secondary" onClick={resetEntryForm}>
                    Cancel edit
                  </button>
                )}
                <button type="button" className="expense-final-secondary" onClick={exportReport}>
                  Download report
                </button>
              </div>
            </section>

            <section className="expense-final-card">
              <div className="expense-final-card__head">
                <span>Recorded entries</span>
                <h2>Expense log list</h2>
                <p>Planner-saved rows appear here too so you can see the full picture in one place.</p>
              </div>
              {allEntries.length ? (
                <div className="expense-final-log">
                  {allEntries.map((entry) => (
                    <article key={entry.id} className="expense-final-log__item">
                      <div>
                        <strong>
                          {entry.month} - {entry.category}
                          {entry.entry_type === "income" ? " (Money received)" : ""}
                        </strong>
                        <p>{formatMoney(parseAmount(entry.amount), selectedCurrency)}{entry.note ? ` | ${entry.note}` : ""}</p>
                      </div>
                      <div className="expense-final-log__actions">
                        {entry.source === "planner" ? (
                          <button type="button" className="expense-final-secondary" onClick={() => setActiveStep(entry.category === "Semester Fee" || MONTHLY_FIELDS.some(([label]) => label === entry.category) ? "monthly-plan" : "before-applying")}>
                            Edit in planner
                          </button>
                        ) : (
                          <>
                            <button type="button" className="expense-final-secondary" onClick={() => startEditing(entry)}>
                              Edit
                            </button>
                            <button type="button" className="expense-final-danger" onClick={() => deleteEntry(entry.id)}>
                              Delete
                            </button>
                          </>
                        )}
                      </div>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="expense-final-empty">
                  <p>No entries recorded yet.</p>
                  <span>Save the planner steps or add a manual entry above.</span>
                </div>
              )}
            </section>
          </>
        )}

        {activeStep === "compare" && (
          <section className="expense-final-card">
            <div className="expense-final-card__head">
              <span>Compare</span>
              <h2>Compare with another university</h2>
              <p>Keep this separate so the main tracker stays simple.</p>
            </div>
            <div className="expense-final-compare-select">
              <select value={compareUniversityId} onChange={(event) => setCompareUniversityId(event.target.value)}>
                <option value="">Select comparison university</option>
                {universities
                  .filter((university) => String(university.id) !== String(selectedUniversityId))
                  .map((university) => (
                    <option key={university.id} value={university.id}>
                      {university.name}
                    </option>
                  ))}
              </select>
            </div>
            {compareUniversity ? (
              <>
                <div className="expense-final-compare-grid">
                  <article className="expense-final-compare-card">
                    <span>This university total</span>
                    <strong>{formatMoney(estimatedYearOne, selectedCurrency)}</strong>
                  </article>
                  <article className="expense-final-compare-card">
                    <span>Comparison university total</span>
                    <strong>{formatMoney(compareTotal, getCurrencyByCountry(compareUniversity.country))}</strong>
                  </article>
                  <article className="expense-final-compare-card">
                    <span>Difference</span>
                    <strong>{formatMoney(Math.abs(difference), selectedCurrency)}</strong>
                  </article>
                  <article className="expense-final-compare-card">
                    <span>Main expensive area</span>
                    <strong>{mainDifference?.label || "-"}</strong>
                  </article>
                </div>
                <div className="expense-final-compare-note">
                  <p>{compareInsight}</p>
                </div>
              </>
            ) : (
              <div className="expense-final-empty">
                <p>No comparison selected yet.</p>
                <span>Choose another university to see the year-one difference.</span>
              </div>
            )}
          </section>
        )}
      </main>
      <Footer />
    </>
  );
}
