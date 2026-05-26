import express from "express";

export function registerProfileRoutes(app, { authMiddleware, controller }) {
  const router = express.Router();

  router.get("/profile", authMiddleware, controller.getProfile);
  router.get("/profile/personal", authMiddleware, controller.getPersonal);
  router.put("/profile/personal", authMiddleware, controller.updatePersonal);
  router.get("/profile/academic", authMiddleware, controller.getAcademic);
  router.put("/profile/academic", authMiddleware, controller.updateAcademic);
  router.get("/profile/preferences", authMiddleware, controller.getPreferences);
  router.put("/profile/preferences", authMiddleware, controller.updatePreferences);
  router.get("/profile/applications", authMiddleware, controller.listApplications);
  router.post("/profile/applications", authMiddleware, controller.createApplication);
  router.patch("/profile/applications/:id/status", authMiddleware, controller.updateApplicationStatus);

  app.use("/api", router);
}
