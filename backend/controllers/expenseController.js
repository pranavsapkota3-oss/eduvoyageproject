import { toNumber } from "../utils/number.js";

function toNullableBool(value) {
  if (value === true || value === 1 || value === "1" || value === "yes") return 1;
  if (value === false || value === 0 || value === "0" || value === "no") return 0;
  return null;
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

export function createExpenseController({ db }) {
  return {
    getExpensePlans: async (req, res) => {
      try {
        const [rows] = await db.query(
          `SELECT university_id, applied, planner_stage, has_arrived, works_part_time, weekly_income,
                  application_fee, transcript_fee, english_test_fee,
                  visa_fee, courier_fee, deposit_fee, semester_fee, monthly_rent,
                  monthly_insurance, monthly_food, monthly_transport, monthly_utilities,
                  other_fee, other_note, updated_at
           FROM expense_plans
           WHERE user_id = ?
           ORDER BY updated_at DESC`,
          [req.user.id]
        );

        return res.json({ plans: rows });
      } catch (err) {
        console.error("GET EXPENSE PLANS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    saveExpensePlan: async (req, res) => {
      try {
        const universityId = Number(req.params.universityId);

        if (!Number.isInteger(universityId) || universityId <= 0) {
          return res.status(400).json({ message: "Valid university id is required" });
        }

        const {
          applied,
          planner_stage,
          has_arrived,
          works_part_time,
          weekly_income,
          application_fee,
          transcript_fee,
          english_test_fee,
          visa_fee,
          courier_fee,
          deposit_fee,
          semester_fee,
          monthly_rent,
          monthly_insurance,
          monthly_food,
          monthly_transport,
          monthly_utilities,
          other_fee,
          other_note,
        } = req.body;

        await db.query(
          `INSERT INTO expense_plans
            (user_id, university_id, applied, planner_stage, has_arrived, works_part_time, weekly_income,
             application_fee, transcript_fee, english_test_fee,
             visa_fee, courier_fee, deposit_fee, semester_fee, monthly_rent, monthly_insurance,
             monthly_food, monthly_transport, monthly_utilities, other_fee, other_note)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON DUPLICATE KEY UPDATE
             applied = VALUES(applied),
             planner_stage = VALUES(planner_stage),
             has_arrived = VALUES(has_arrived),
             works_part_time = VALUES(works_part_time),
             weekly_income = VALUES(weekly_income),
             application_fee = VALUES(application_fee),
             transcript_fee = VALUES(transcript_fee),
             english_test_fee = VALUES(english_test_fee),
             visa_fee = VALUES(visa_fee),
             courier_fee = VALUES(courier_fee),
             deposit_fee = VALUES(deposit_fee),
             semester_fee = VALUES(semester_fee),
             monthly_rent = VALUES(monthly_rent),
             monthly_insurance = VALUES(monthly_insurance),
             monthly_food = VALUES(monthly_food),
             monthly_transport = VALUES(monthly_transport),
             monthly_utilities = VALUES(monthly_utilities),
             other_fee = VALUES(other_fee),
             other_note = VALUES(other_note)`,
          [
            req.user.id,
            universityId,
            applied ? 1 : 0,
            normalizePlannerStage(planner_stage),
            toNullableBool(has_arrived),
            toNullableBool(works_part_time),
            toNumber(weekly_income),
            toNumber(application_fee),
            toNumber(transcript_fee),
            toNumber(english_test_fee),
            toNumber(visa_fee),
            toNumber(courier_fee),
            toNumber(deposit_fee),
            toNumber(semester_fee),
            toNumber(monthly_rent),
            toNumber(monthly_insurance),
            toNumber(monthly_food),
            toNumber(monthly_transport),
            toNumber(monthly_utilities),
            toNumber(other_fee),
            other_note || null,
          ]
        );

        const [[savedPlan]] = await db.query(
          `SELECT university_id, applied, planner_stage, has_arrived, works_part_time, weekly_income,
                  application_fee, transcript_fee, english_test_fee,
                  visa_fee, courier_fee, deposit_fee, semester_fee, monthly_rent,
                  monthly_insurance, monthly_food, monthly_transport, monthly_utilities,
                  other_fee, other_note, updated_at
           FROM expense_plans
           WHERE user_id = ? AND university_id = ?`,
          [req.user.id, universityId]
        );

        return res.json({ message: "Expense plan saved", plan: savedPlan });
      } catch (err) {
        console.error("SAVE EXPENSE PLAN ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    getExpenseEntries: async (req, res) => {
      try {
        const universityId = Number(req.query.university_id);

        if (!Number.isInteger(universityId) || universityId <= 0) {
          return res.status(400).json({ message: "Valid university_id is required" });
        }

        const [rows] = await db.query(
          `SELECT id, university_id, entry_type, category, amount, month, note, created_at
           FROM expense_entries
           WHERE user_id = ? AND university_id = ?
           ORDER BY month DESC, created_at DESC`,
          [req.user.id, universityId]
        );

        return res.json({ expenses: rows });
      } catch (err) {
        console.error("GET EXPENSE ENTRIES ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    createExpenseEntry: async (req, res) => {
      try {
        const { university_id, entry_type, category, amount, month, note } = req.body;
        const universityId = Number(university_id);

        if (!Number.isInteger(universityId) || universityId <= 0) {
          return res.status(400).json({ message: "Valid university_id is required" });
        }

        if (!category || !month || toNumber(amount) === null) {
          return res.status(400).json({
            message: "university_id, category, amount, and month are required",
          });
        }

        const [result] = await db.query(
          `INSERT INTO expense_entries
            (user_id, university_id, entry_type, category, amount, month, note)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
          [
            req.user.id,
            universityId,
            entry_type === "income" ? "income" : "expense",
            String(category).trim(),
            toNumber(amount),
            String(month).trim(),
            note || null,
          ]
        );

        const [[entry]] = await db.query(
          `SELECT id, university_id, entry_type, category, amount, month, note, created_at
           FROM expense_entries
           WHERE id = ? AND user_id = ?`,
          [result.insertId, req.user.id]
        );

        return res.status(201).json({ message: "Expense entry saved", expense: entry });
      } catch (err) {
        console.error("ADD EXPENSE ENTRY ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateExpenseEntry: async (req, res) => {
      try {
        const expenseId = Number(req.params.id);
        const { entry_type, category, amount, month, note } = req.body;

        if (!Number.isInteger(expenseId) || expenseId <= 0) {
          return res.status(400).json({ message: "Valid expense id is required" });
        }

        if (!category || !month || toNumber(amount) === null) {
          return res.status(400).json({
            message: "category, amount, and month are required",
          });
        }

        const [result] = await db.query(
          `UPDATE expense_entries
           SET entry_type = ?, category = ?, amount = ?, month = ?, note = ?
           WHERE id = ? AND user_id = ?`,
          [
            entry_type === "income" ? "income" : "expense",
            String(category).trim(),
            toNumber(amount),
            String(month).trim(),
            note || null,
            expenseId,
            req.user.id,
          ]
        );

        if (!result.affectedRows) {
          return res.status(404).json({ message: "Expense entry not found" });
        }

        const [[entry]] = await db.query(
          `SELECT id, university_id, entry_type, category, amount, month, note, created_at
           FROM expense_entries
           WHERE id = ? AND user_id = ?`,
          [expenseId, req.user.id]
        );

        return res.json({ message: "Expense entry updated", expense: entry });
      } catch (err) {
        console.error("UPDATE EXPENSE ENTRY ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    deleteExpenseEntry: async (req, res) => {
      try {
        const expenseId = Number(req.params.id);

        if (!Number.isInteger(expenseId) || expenseId <= 0) {
          return res.status(400).json({ message: "Valid expense id is required" });
        }

        const [result] = await db.query(
          `DELETE FROM expense_entries
           WHERE id = ? AND user_id = ?`,
          [expenseId, req.user.id]
        );

        if (!result.affectedRows) {
          return res.status(404).json({ message: "Expense entry not found" });
        }

        return res.json({ message: "Expense entry deleted" });
      } catch (err) {
        console.error("DELETE EXPENSE ENTRY ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },
  };
}
