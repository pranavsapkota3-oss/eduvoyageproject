import express from "express";

export function registerSettingsRoutes(app, { authMiddleware, controller }) {
  const router = express.Router();

  router.get("/", authMiddleware, controller.getSettings);
  router.put("/profile", authMiddleware, controller.updateProfile);
  router.put("/password", authMiddleware, controller.updatePassword);
  router.put("/preferences", authMiddleware, controller.updatePreferences);
  router.post("/logout-all-devices", authMiddleware, controller.logoutAllDevices);
  router.post("/deactivate-account", authMiddleware, controller.deactivateAccount);

  app.use("/api/settings", router);
}
