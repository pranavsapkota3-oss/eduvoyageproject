import { useEffect } from "react";
import { Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Dashboard from "./pages/Dashboard";
import Profile from "./pages/Profile";
import AcademicBackground from "./pages/AcademicBackground";
import StudyPreferences from "./pages/StudyPreferences";
import Documents from "./pages/Documents";
import DocumentVault from "./pages/DocumentVault";
import ReviewSubmit from "./pages/ReviewSubmit";
import AgentDashboard from "./pages/AgentDashboard";
import AgentUniversityEditor from "./pages/AgentUniversityEditor";
import Universities from "./pages/Universities";
import UniversityDetail from "./pages/UniversityDetail";
import ScholarshipFinder from "./pages/ScholarshipFinder";
import Countries from "./pages/Countries";
import ExpenseTracker from "./pages/ExpenseTracker";
import Services from "./pages/Services";
import Settings from "./pages/Settings";
import MyApplications from "./pages/MyApplications";

export default function App() {
  useEffect(() => {
    const validateStoredToken = async () => {
      const token = localStorage.getItem("token");
      if (!token) return;

      try {
        const res = await fetch("http://localhost:5000/api/profile", {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (res.ok) {
          return;
        }

        const data = await res.json().catch(() => ({}));
        const message = String(data.message || "");
        const shouldClearToken = res.status === 401 || (res.status === 403 && message === "Invalid token");

        if (!shouldClearToken) {
          return;
        }

        localStorage.removeItem("token");
        localStorage.removeItem("user");
        sessionStorage.removeItem("document_vault_session_pin_v1");

        const currentPath = window.location.pathname;
        if (currentPath !== "/login" && currentPath !== "/signup") {
          window.location.replace("/login");
        }
      } catch {
        // ignore backend-unavailable state here; page-level requests will show normal errors
      }
    };

    validateStoredToken();
  }, []);

  return (
    <Routes>
      <Route path="/" element={<Home />} />
      <Route path="/login" element={<Login />} />
      <Route path="/signup" element={<Signup />} />
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="/profile" element={<Profile />} />
      <Route path="/profile/academic" element={<AcademicBackground />} />
      <Route path="/profile/preferences" element={<StudyPreferences />} />
      <Route path="/profile/documents" element={<Documents />} />
      <Route path="/document-vault" element={<DocumentVault />} />
      <Route path="/profile/review" element={<ReviewSubmit />} />
      <Route path="/agent" element={<AgentDashboard />} />
      <Route path="/agent/universities/new" element={<AgentUniversityEditor />} />
      <Route path="/agent/universities/:id/edit" element={<AgentUniversityEditor />} />
      <Route path="/universities" element={<Universities />} />
      <Route path="/universities/:id" element={<UniversityDetail />} />
      <Route path="/countries" element={<Countries />} />
      <Route path="/expense-tracker" element={<ExpenseTracker />} />
      <Route path="/scholarships" element={<ScholarshipFinder />} />
      <Route path="/services" element={<Services />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="/applications" element={<MyApplications />} />
    </Routes>
  );
}
