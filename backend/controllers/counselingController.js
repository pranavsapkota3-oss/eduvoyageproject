export function createCounselingController({ db }) {
  return {
    createRequest: async (req, res) => {
      try {
        const topic = String(req.body.topic || "").trim();
        const message = String(req.body.message || "").trim();
        const preferredCountry = String(req.body.preferred_country || "").trim();
        const priority = String(req.body.priority || "normal").trim().toLowerCase();

        if (!topic || !message) {
          return res.status(400).json({ message: "Topic and message are required" });
        }

        if (!["low", "normal", "high"].includes(priority)) {
          return res.status(400).json({ message: "Valid priority is required" });
        }

        const [result] = await db.query(
          `INSERT INTO counseling_requests (user_id, topic, message, preferred_country, priority, status)
           VALUES (?, ?, ?, ?, ?, 'pending')`,
          [req.user.id, topic, message, preferredCountry || null, priority]
        );

        const [[requestRow]] = await db.query(
          `SELECT c.id, c.user_id, c.topic, c.message, c.preferred_country, c.priority, c.status, c.created_at, c.updated_at,
                  u.full_name, u.email
           FROM counseling_requests c
           JOIN users u ON u.id = c.user_id
           WHERE c.id = ?`,
          [result.insertId]
        );

        return res.status(201).json({ message: "Counseling request created", request: requestRow });
      } catch (err) {
        console.error("CREATE COUNSELING REQUEST ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    listAdminRequests: async (req, res) => {
      try {
        const [rows] = await db.query(
          `SELECT c.id, c.user_id, c.topic, c.message, c.preferred_country, c.priority, c.status, c.created_at, c.updated_at,
                  u.full_name, u.email
           FROM counseling_requests c
           JOIN users u ON u.id = c.user_id
           ORDER BY c.updated_at DESC
           LIMIT 200`
        );

        return res.json({ requests: rows });
      } catch (err) {
        console.error("COUNSELING REQUESTS ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },

    updateAdminRequest: async (req, res) => {
      try {
        const requestId = Number(req.params.id);
        const status = String(req.body.status || "").trim().toLowerCase();
        const priority = String(req.body.priority || "").trim().toLowerCase();
        const allowedStatuses = ["pending", "in progress", "resolved"];
        const allowedPriorities = ["low", "normal", "high"];

        if (!Number.isInteger(requestId) || requestId <= 0) {
          return res.status(400).json({ message: "Valid counseling request id is required" });
        }

        if (!allowedStatuses.includes(status) || !allowedPriorities.includes(priority)) {
          return res.status(400).json({ message: "Valid counseling status and priority are required" });
        }

        await db.query(
          `UPDATE counseling_requests
           SET status = ?, priority = ?
           WHERE id = ?`,
          [status, priority, requestId]
        );

        const [[requestRow]] = await db.query(
          `SELECT c.id, c.user_id, c.topic, c.message, c.preferred_country, c.priority, c.status, c.created_at, c.updated_at,
                  u.full_name, u.email
           FROM counseling_requests c
           JOIN users u ON u.id = c.user_id
           WHERE c.id = ?`,
          [requestId]
        );

        if (!requestRow) {
          return res.status(404).json({ message: "Counseling request not found" });
        }

        return res.json({ message: "Counseling request updated", request: requestRow });
      } catch (err) {
        console.error("COUNSELING REQUEST UPDATE ERROR:", err);
        return res.status(500).json({ message: "Server error", details: err.message });
      }
    },
  };
}
