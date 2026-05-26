import express from "express";

export function registerDocumentRoutes(app, {
  authMiddleware,
  documentVaultPinMiddleware,
  upload,
  controller,
}) {
  const router = express.Router();

  router.get("/profile/documents/vault-status", authMiddleware, controller.getVaultStatus);
  router.put("/profile/documents/vault-pin", authMiddleware, controller.setVaultPin);
  router.post("/profile/documents/vault-unlock", authMiddleware, controller.unlockVault);
  router.get("/profile/documents", authMiddleware, controller.listDocuments);
  router.get("/profile/documents/:id/download", authMiddleware, controller.downloadDocument);
  router.post(
    "/profile/documents",
    authMiddleware,
    documentVaultPinMiddleware,
    upload.array("documents", 10),
    controller.uploadDocuments
  );
  router.delete("/profile/documents/:id", authMiddleware, controller.deleteDocument);

  app.use("/api", router);
}
