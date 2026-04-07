import { Routes, Route } from "react-router-dom";
import Home from "./pages/Home";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Dashboard from "./pages/Dashboard";
import Profile from "./pages/Profile";
import AcademicBackground from "./pages/AcademicBackground";
import StudyPreferences from "./pages/StudyPreferences";
import Documents from "./pages/Documents";
import ReviewSubmit from "./pages/ReviewSubmit";
import AgentDashboard from "./pages/AgentDashboard";
import Universities from "./pages/Universities";
import UniversityDetail from "./pages/UniversityDetail";
import ScholarshipFinder from "./pages/ScholarshipFinder";
import Countries from "./pages/Countries";
import ExpenseTracker from "./pages/ExpenseTracker";
import Services from "./pages/Services";
import Settings from "./pages/Settings";

export default function App() {
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
      <Route path="/profile/review" element={<ReviewSubmit />} />
      <Route path="/agent" element={<AgentDashboard />} />
      <Route path="/universities" element={<Universities />} />
      <Route path="/universities/:id" element={<UniversityDetail />} />
      <Route path="/countries" element={<Countries />} />
      <Route path="/expense-tracker" element={<ExpenseTracker />} />
      <Route path="/scholarships" element={<ScholarshipFinder />} />
      <Route path="/services" element={<Services />} />
      <Route path="/settings" element={<Settings />} />
    </Routes>
  );
}
