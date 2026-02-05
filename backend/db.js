import mysql from "mysql2/promise";
import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ✅ Always load the .env from the backend folder (no CWD issues)
dotenv.config({ path: path.join(__dirname, ".env") });

console.log("ENV CHECK:", {
  DB_HOST: process.env.DB_HOST,
  DB_USER: process.env.DB_USER,
  DB_PASS_LEN: process.env.DB_PASS ? process.env.DB_PASS.length : 0,
  DB_NAME: process.env.DB_NAME,
  DB_PORT: process.env.DB_PORT,
});


export const db = mysql.createPool({
  host: process.env.DB_HOST || "127.0.0.1",
  user: process.env.DB_USER,
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME,
  port: Number(process.env.DB_PORT || 3307),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});
