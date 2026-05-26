export function createDocumentController({
  db,
  bcrypt,
  fs,
  crypto,
  ensureSettingsTable,
  getDocumentVaultPinHash,
  verifyDocumentVaultPin,
  requireDocumentVaultPin,
  resolveDocumentAbsolutePath,
  sanitizeDocumentType,
  formatFileSize,
  buildDocumentDownloadUrl,
}) {
  return {
    getVaultStatus: async (req, res) => {
      try {
        const hasPin = !!(await getDocumentVaultPinHash(req.user.id));
        return res.json({ has_pin: hasPin });
      } catch (err) {
        console.error("GET DOCUMENT VAULT STATUS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    setVaultPin: async (req, res) => {
      try {
        const pin = String(req.body.pin || "").trim();
        const currentPin = String(req.body.current_pin || "").trim();

        if (!/^\d{4,8}$/.test(pin)) {
          return res.status(400).json({ message: "PIN must be 4 to 8 digits." });
        }

        const existingHash = await getDocumentVaultPinHash(req.user.id);
        if (existingHash) {
          const ok = await verifyDocumentVaultPin(req.user.id, currentPin);
          if (!ok) {
            return res.status(403).json({ message: "Current document vault PIN is incorrect." });
          }
        }

        const pinHash = await bcrypt.hash(pin, 10);

        await ensureSettingsTable();
        await db.query(
          `INSERT INTO user_settings
            (user_id, email_notifications, scholarship_alerts, marketing_updates, preferred_currency, document_vault_pin_hash, document_vault_pin_updated_at)
           VALUES (?, 1, 1, 0, 'USD', ?, NOW())
           ON DUPLICATE KEY UPDATE
             document_vault_pin_hash = VALUES(document_vault_pin_hash),
             document_vault_pin_updated_at = VALUES(document_vault_pin_updated_at)`,
          [req.user.id, pinHash]
        );

        return res.json({ message: existingHash ? "Document vault PIN updated." : "Document vault PIN created." });
      } catch (err) {
        console.error("SET DOCUMENT VAULT PIN ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    unlockVault: async (req, res) => {
      try {
        const pin = String(req.body.pin || "").trim();
        const hasPin = !!(await getDocumentVaultPinHash(req.user.id));

        if (!hasPin) {
          return res.json({ message: "Document vault does not have a PIN yet.", unlocked: true });
        }

        const ok = await verifyDocumentVaultPin(req.user.id, pin);
        if (!ok) {
          return res.status(403).json({ message: "Invalid document vault PIN." });
        }

        return res.json({ message: "Document vault unlocked.", unlocked: true });
      } catch (err) {
        console.error("UNLOCK DOCUMENT VAULT ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    listDocuments: async (req, res) => {
      try {
        if (!(await requireDocumentVaultPin(req, res))) {
          return;
        }

        const [rows] = await db.query(
          `SELECT id, file_name, file_size, file_size_bytes, file_url, mime_type, created_at,
                  review_status, review_comment, reviewed_at, document_type, storage_scope
           FROM user_documents
           WHERE user_id = ?
           ORDER BY created_at DESC`,
          [req.user.id]
        );

        return res.json({
          documents: rows.map((document) => ({
            ...document,
            download_url: buildDocumentDownloadUrl(document.id),
          })),
        });
      } catch (err) {
        console.error("GET DOCUMENTS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    downloadDocument: async (req, res) => {
      try {
        const documentId = Number(req.params.id);
        if (!Number.isInteger(documentId) || documentId <= 0) {
          return res.status(400).json({ message: "Valid document id is required" });
        }

        const [rows] = await db.query(
          `SELECT id, user_id, file_name, file_url, stored_name, mime_type
           FROM user_documents
           WHERE id = ?`,
          [documentId]
        );

        const document = rows[0];
        if (!document) {
          return res.status(404).json({ message: "Document not found" });
        }

        const isOwner = Number(document.user_id) === Number(req.user.id);
        const isPrivileged = req.user.role === "admin" || req.user.role === "agent";
        if (!isOwner && !isPrivileged) {
          return res.status(403).json({ message: "Access denied" });
        }

        if (isOwner && !isPrivileged && !(await requireDocumentVaultPin(req, res))) {
          return;
        }

        const absolutePath = resolveDocumentAbsolutePath(document);
        if (!absolutePath || !fs.existsSync(absolutePath)) {
          return res.status(404).json({ message: "Stored file not found" });
        }

        return res.download(absolutePath, document.file_name || absolutePath);
      } catch (err) {
        console.error("DOCUMENT DOWNLOAD ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    uploadDocuments: async (req, res) => {
      try {
        const files = req.files || [];
        const documentType = sanitizeDocumentType(req.body.document_type, req.body.custom_document_type);

        if (files.length === 0) {
          return res.status(400).json({ message: "No documents provided" });
        }

        const values = files.map((file) => {
          const fileBuffer = fs.readFileSync(file.path);
          const fileHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
          return [
            req.user.id,
            file.originalname || "Document",
            formatFileSize(file.size),
            null,
            file.mimetype || null,
            file.filename,
            file.size,
            fileHash,
            documentType,
            "vault",
          ];
        });

        await db.query(
          `INSERT INTO user_documents
            (user_id, file_name, file_size, file_url, mime_type, stored_name, file_size_bytes, file_hash, document_type, storage_scope)
           VALUES ?`,
          [values]
        );

        const [rows] = await db.query(
          `SELECT id, file_name, file_size, file_size_bytes, file_url, mime_type, created_at,
                  review_status, review_comment, reviewed_at, document_type, storage_scope
           FROM user_documents
           WHERE user_id = ?
           ORDER BY created_at DESC`,
          [req.user.id]
        );

        return res.json({
          message: "Documents saved in vault",
          documents: rows.map((document) => ({
            ...document,
            download_url: buildDocumentDownloadUrl(document.id),
          })),
        });
      } catch (err) {
        console.error("ADD DOCUMENTS ERROR:", err);
        const message = err.message === "Unsupported document type"
          ? "Only PDF, JPG, PNG, WEBP, DOC, and DOCX files are allowed."
          : err.code === "LIMIT_FILE_SIZE"
            ? "Each file must be 10 MB or smaller."
            : "Server error";
        return res.status(500).json({ message, details: err.message });
      }
    },

    deleteDocument: async (req, res) => {
      try {
        if (!(await requireDocumentVaultPin(req, res))) {
          return;
        }

        const { id } = req.params;
        const [rows] = await db.query(
          "SELECT id, user_id, file_url, stored_name FROM user_documents WHERE id = ? AND user_id = ?",
          [id, req.user.id]
        );

        const document = rows[0];
        if (!document) {
          return res.status(404).json({ message: "Document not found" });
        }

        const absolutePath = resolveDocumentAbsolutePath(document);
        await db.query(
          "DELETE FROM user_documents WHERE id = ? AND user_id = ?",
          [id, req.user.id]
        );

        if (absolutePath && fs.existsSync(absolutePath)) {
          fs.unlinkSync(absolutePath);
        }

        return res.json({ message: "Document deleted" });
      } catch (err) {
        console.error("DELETE DOCUMENT ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },
  };
}
