import jwt from "jsonwebtoken";

export function createAuthGuards(db) {
  const authMiddleware = (req, res, next) => {
    const header = req.headers.authorization;
    const token = header?.startsWith("Bearer ") ? header.split(" ")[1] : null;

    if (!token) {
      return res.status(401).json({ message: "Missing token" });
    }

    try {
      req.user = jwt.verify(token, process.env.JWT_SECRET);
      next();
    } catch {
      return res.status(403).json({ message: "Invalid token" });
    }
  };

  const requireRole = (allowedRoles, deniedMessage) => async (req, res, next) => {
    try {
      const [rows] = await db.query(
        "SELECT role, is_active FROM users WHERE id = ?",
        [req.user.id]
      );

      if (!rows.length) {
        return res.status(403).json({ message: "Access denied" });
      }

      if (!rows[0].is_active) {
        return res.status(403).json({ message: "Account is inactive" });
      }

      if (!allowedRoles.includes(rows[0].role)) {
        return res.status(403).json({ message: deniedMessage });
      }

      next();
    } catch (err) {
      console.error("ROLE CHECK ERROR:", err);
      return res.status(500).json({ message: "Server error", details: err.message });
    }
  };

  return {
    authMiddleware,
    requireAdmin: requireRole(["admin"], "Admin access required"),
    requireAgent: requireRole(["agent"], "Agent access required"),
    requireAgentOrAdmin: requireRole(["agent", "admin"], "Agent access required"),
  };
}
