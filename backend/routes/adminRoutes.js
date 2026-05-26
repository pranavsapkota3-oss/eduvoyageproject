import express from "express";

export function registerAdminRoutes(app, {
  authMiddleware,
  requireAdmin,
  requireAgentOrAdmin,
  controller,
}) {
  const router = express.Router();

  router.get("/admin/users", authMiddleware, requireAdmin, controller.listUsers);
  router.patch("/admin/users/:id/role", authMiddleware, requireAdmin, controller.updateUserRole);
  router.patch("/admin/users/:id/status", authMiddleware, requireAdmin, controller.updateUserStatus);
  router.delete("/admin/users/:id", authMiddleware, requireAdmin, controller.deleteUser);

  router.get("/admin/summary", authMiddleware, requireAgentOrAdmin, controller.getSummary);
  router.get("/admin/documents", authMiddleware, requireAgentOrAdmin, controller.listDocuments);
  router.patch("/admin/documents/:id/review", authMiddleware, requireAgentOrAdmin, controller.reviewDocument);
  router.get("/admin/applications", authMiddleware, requireAgentOrAdmin, controller.listApplications);
  router.patch("/admin/applications/:id/status", authMiddleware, requireAgentOrAdmin, controller.updateApplicationStatus);

  router.get("/agent/university-audit", authMiddleware, requireAgentOrAdmin, controller.listUniversityAuditLogs);

  app.use("/api", router);
}
