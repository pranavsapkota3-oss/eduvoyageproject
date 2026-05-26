export function createAdminController({ db, buildDocumentDownloadUrl }) {
  return {
    listUsers: async (req, res) => {
      try {
        const [rows] = await db.query(
          "SELECT id, full_name, email, role, is_active, created_at FROM users ORDER BY id DESC"
        );
        return res.json({ users: rows });
      } catch (err) {
        console.error("ADMIN LIST ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateUserRole: async (req, res) => {
      try {
        const { role } = req.body;
        const allowedRoles = ["student", "agent", "admin"];
        if (!role) {
          return res.status(400).json({ message: "role is required" });
        }
        if (!allowedRoles.includes(role)) {
          return res.status(400).json({ message: "Invalid role" });
        }
        await db.query("UPDATE users SET role = ? WHERE id = ?", [role, req.params.id]);
        return res.json({ message: "Role updated" });
      } catch (err) {
        console.error("ADMIN ROLE ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateUserStatus: async (req, res) => {
      try {
        const { is_active } = req.body;
        await db.query("UPDATE users SET is_active = ? WHERE id = ?", [
          is_active ? 1 : 0,
          req.params.id,
        ]);
        return res.json({ message: "Status updated" });
      } catch (err) {
        console.error("ADMIN STATUS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    deleteUser: async (req, res) => {
      try {
        await db.query("DELETE FROM users WHERE id = ?", [req.params.id]);
        return res.json({ message: "User deleted" });
      } catch (err) {
        console.error("ADMIN DELETE ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    getSummary: async (req, res) => {
      try {
        const [[studentRows], [agentRows], [documentRows]] = await Promise.all([
          db.query("SELECT COUNT(*) AS count FROM users WHERE role = 'student'"),
          db.query("SELECT COUNT(*) AS count FROM users WHERE role = 'agent' AND is_active = 1"),
          db.query("SELECT COUNT(*) AS count FROM user_documents WHERE review_status = 'pending' OR review_status IS NULL"),
        ]);

        let applicationsSubmitted = 0;
        try {
          const [[applicationRows]] = await db.query("SELECT COUNT(*) AS count FROM applications");
          applicationsSubmitted = applicationRows.count || 0;
        } catch {
          applicationsSubmitted = 0;
        }

        return res.json({
          total_students: studentRows[0]?.count || 0,
          active_agents: agentRows[0]?.count || 0,
          pending_document_reviews: documentRows[0]?.count || 0,
          applications_submitted: applicationsSubmitted,
        });
      } catch (err) {
        console.error("ADMIN SUMMARY ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    listDocuments: async (req, res) => {
      try {
        const [rows] = await db.query(
          `SELECT d.id, d.user_id, d.file_name, d.file_size, d.file_size_bytes, d.file_url, d.mime_type, d.created_at,
                  d.review_status, d.review_comment, d.reviewed_at, d.document_type, d.storage_scope,
                  u.full_name, u.email,
                  reviewer.full_name AS reviewer_name
           FROM user_documents d
           JOIN users u ON u.id = d.user_id
           LEFT JOIN users reviewer ON reviewer.id = d.reviewed_by
           ORDER BY d.created_at DESC`
        );

        return res.json({
          documents: rows.map((document) => ({
            ...document,
            download_url: buildDocumentDownloadUrl(document.id),
          })),
        });
      } catch (err) {
        console.error("ADMIN DOCUMENTS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    reviewDocument: async (req, res) => {
      try {
        const documentId = Number(req.params.id);
        const reviewStatus = String(req.body.status || "").trim().toLowerCase();
        const reviewComment = String(req.body.comment || "").trim();

        if (!Number.isInteger(documentId) || documentId <= 0) {
          return res.status(400).json({ message: "Valid document id is required" });
        }

        if (!["approved", "rejected", "pending"].includes(reviewStatus)) {
          return res.status(400).json({ message: "Valid review status is required" });
        }

        await db.query(
          `UPDATE user_documents
           SET review_status = ?, review_comment = ?, reviewed_by = ?, reviewed_at = ?
           WHERE id = ?`,
          [
            reviewStatus,
            reviewComment || null,
            reviewStatus === "pending" ? null : req.user.id,
            reviewStatus === "pending" ? null : new Date(),
            documentId,
          ]
        );

        const [[updatedDocument]] = await db.query(
          `SELECT d.id, d.user_id, d.file_name, d.file_size, d.file_size_bytes, d.file_url, d.mime_type, d.created_at,
                  d.review_status, d.review_comment, d.reviewed_at, d.document_type, d.storage_scope,
                  u.full_name, u.email,
                  reviewer.full_name AS reviewer_name
           FROM user_documents d
           JOIN users u ON u.id = d.user_id
           LEFT JOIN users reviewer ON reviewer.id = d.reviewed_by
           WHERE d.id = ?`,
          [documentId]
        );

        if (!updatedDocument) {
          return res.status(404).json({ message: "Document not found" });
        }

        return res.json({
          message: "Document review updated",
          document: {
            ...updatedDocument,
            download_url: buildDocumentDownloadUrl(updatedDocument.id),
          },
        });
      } catch (err) {
        console.error("ADMIN DOCUMENT REVIEW ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    listApplications: async (req, res) => {
      try {
        const [rows] = await db.query(
          `SELECT a.id, a.user_id, a.university_id, a.status, a.source, a.notes, a.submitted_at, a.created_at, a.updated_at,
                  u.full_name, u.email,
                  un.name AS university_name, un.country AS university_country, un.city AS university_city
           FROM applications a
           JOIN users u ON u.id = a.user_id
           JOIN universities un ON un.id = a.university_id
           ORDER BY a.updated_at DESC
           LIMIT 200`
        );

        return res.json({ applications: rows });
      } catch (err) {
        console.error("ADMIN APPLICATIONS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateApplicationStatus: async (req, res) => {
      try {
        const applicationId = Number(req.params.id);
        const status = String(req.body.status || "").trim().toLowerCase();
        const notes = String(req.body.notes || "").trim();
        const allowedStatuses = ["shortlisted", "applying", "submitted", "offer received", "accepted", "rejected", "stopped applying"];

        if (!Number.isInteger(applicationId) || applicationId <= 0) {
          return res.status(400).json({ message: "Valid application id is required" });
        }

        if (!allowedStatuses.includes(status)) {
          return res.status(400).json({ message: "Valid application status is required" });
        }

        await db.query(
          `UPDATE applications
           SET status = ?, notes = COALESCE(NULLIF(?, ''), notes), submitted_at = CASE WHEN ? = 'submitted' AND submitted_at IS NULL THEN CURRENT_TIMESTAMP ELSE submitted_at END
           WHERE id = ?`,
          [status, notes, status, applicationId]
        );

        const [[application]] = await db.query(
          `SELECT a.id, a.user_id, a.university_id, a.status, a.source, a.notes, a.submitted_at, a.created_at, a.updated_at,
                  u.full_name, u.email,
                  un.name AS university_name, un.country AS university_country, un.city AS university_city
           FROM applications a
           JOIN users u ON u.id = a.user_id
           JOIN universities un ON un.id = a.university_id
           WHERE a.id = ?`,
          [applicationId]
        );

        if (!application) {
          return res.status(404).json({ message: "Application not found" });
        }

        return res.json({ message: "Application status updated", application });
      } catch (err) {
        console.error("ADMIN APPLICATION STATUS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    listUniversityAuditLogs: async (req, res) => {
      try {
        const limit = Math.max(1, Math.min(50, Number(req.query.limit || 20)));
        const [rows] = await db.query(
          `SELECT l.id, l.university_id, l.action, l.editor_user_id, l.editor_role, l.changed_fields, l.created_at,
                  un.name AS university_name,
                  u.full_name AS editor_name
           FROM university_audit_logs l
           JOIN universities un ON un.id = l.university_id
           JOIN users u ON u.id = l.editor_user_id
           ORDER BY l.created_at DESC
           LIMIT ?`,
          [limit]
        );

        return res.json({ logs: rows });
      } catch (err) {
        console.error("UNIVERSITY AUDIT LIST ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },
  };
}
