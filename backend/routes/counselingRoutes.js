import express from "express";

export function registerCounselingRoutes(app, {
  authMiddleware,
  requireAgentOrAdmin,
  controller,
}) {
  const router = express.Router();

  router.post("/profile/counseling-requests", authMiddleware, controller.createRequest);
  router.get("/admin/counseling-requests", authMiddleware, requireAgentOrAdmin, controller.listAdminRequests);
  router.patch("/admin/counseling-requests/:id", authMiddleware, requireAgentOrAdmin, controller.updateAdminRequest);

  app.use("/api", router);
}
