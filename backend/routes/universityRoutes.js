import express from "express";

export function registerUniversityRoutes(app, {
  authMiddleware,
  requireAdmin,
  requireAgentOrAdmin,
  controller,
}) {
  const publicRouter = express.Router();
  const agentRouter = express.Router();

  publicRouter.get("/universities", controller.listUniversities);
  publicRouter.get("/universities/:id", controller.getUniversityDetail);
  publicRouter.get("/scholarships/recommended", authMiddleware, controller.getScholarshipRecommendations);

  agentRouter.post("/universities", authMiddleware, requireAgentOrAdmin, controller.createUniversity);
  agentRouter.patch("/universities/:id", authMiddleware, requireAgentOrAdmin, controller.updateUniversity);
  agentRouter.delete("/universities/:id", authMiddleware, requireAdmin, controller.deleteUniversity);

  app.use("/api", publicRouter);
  app.use("/api/agent", agentRouter);
}
