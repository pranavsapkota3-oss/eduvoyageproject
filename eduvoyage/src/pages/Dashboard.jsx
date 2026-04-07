import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Navbar from "../components/Navbar";

export default function Dashboard() {
  const navigate = useNavigate();
  const [profile, setProfile] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) {
      navigate("/login");
      return;
    }

    const loadProfile = async () => {
      try {
        const res = await fetch("http://localhost:5000/api/profile", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        const data = await res.json();

        if (!res.ok) {
          // token expired or invalid
          localStorage.removeItem("token");
          localStorage.removeItem("user");
          navigate("/login");
          return;
        }

        setProfile(data.user);
      } catch (err) {
        console.error(err);
        alert("Backend not running or network error");
      } finally {
        setLoading(false);
      }
    };

    loadProfile();
  }, [navigate]);

  return (
    <>
      <Navbar />
      <div style={{ maxWidth: 900, margin: "0 auto", padding: 30 }}>
        <h1>Dashboard</h1>

        {loading && <p>Loading profile...</p>}

        {!loading && profile && (
          <div style={{ marginTop: 16 }}>
            <p><b>Name:</b> {profile.full_name}</p>
            <p><b>Email:</b> {profile.email}</p>
            <p><b>User ID:</b> {profile.id}</p>
          </div>
        )}
      </div>
    </>
  );
}
