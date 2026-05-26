import express from "express";

export function registerExpenseRoutes(app, { authMiddleware, controller }) {
  const router = express.Router();

  router.get("/expense-plans", authMiddleware, controller.getExpensePlans);
  router.put("/expense-plans/:universityId", authMiddleware, controller.saveExpensePlan);
  router.get("/expense-entries", authMiddleware, controller.getExpenseEntries);
  router.post("/expense-entries", authMiddleware, controller.createExpenseEntry);
  router.put("/expense-entries/:id", authMiddleware, controller.updateExpenseEntry);
  router.delete("/expense-entries/:id", authMiddleware, controller.deleteExpenseEntry);

  app.use("/api", router);
}
