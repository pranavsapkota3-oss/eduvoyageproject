import express from "express";

export function registerAuthRoutes(app, controller) {
  const router = express.Router();

  router.post("/signup", controller.signup);
  router.post("/verify-otp", controller.verifyOtp);
  router.post("/resend-otp", controller.resendOtp);
  router.post("/forgot-password", controller.forgotPassword);
  router.post("/reset-password", controller.resetPassword);
  router.post("/login", controller.login);
  router.post("/google", controller.googleAuth);

  app.use("/api/auth", router);
}
