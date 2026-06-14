import React, { useEffect, useState } from "react";
import axios from "axios";
import { Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, Title, Tooltip, Legend);

const API_BASE = process.env.REACT_APP_API_BASE || "http://localhost:8000";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total_events: 0,
    malicious_count: 0,
    normal_count: 0,
    blocked_ips: [],
  });
  const [error, setError] = useState(null);

  const fetchData = async () => {
    try {
      const [alertsRes, statsRes] = await Promise.all([
        axios.get(`${API_BASE}/alerts?limit=20`),
        axios.get(`${API_BASE}/stats`),
      ]);
      setAlerts(alertsRes.data);
      setStats(statsRes.data);
      setError(null);
    } catch (err) {
      setError("Unable to reach CyberSasi AI API. Is the backend running?");
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // refresh every 5s
    return () => clearInterval(interval);
  }, []);

  const chartData = {
    labels: alerts.map((a) => new Date(a.timestamp).toLocaleTimeString()).reverse(),
    datasets: [
      {
        label: "Confidence (malicious score)",
        data: alerts.map((a) => a.confidence).reverse(),
        borderColor: "#f87171",
        backgroundColor: "rgba(248,113,113,0.2)",
        tension: 0.3,
      },
    ],
  };

  return (
    <div style={{ padding: "24px", maxWidth: "1100px", margin: "0 auto" }}>
      <h1 style={{ color: "#38bdf8" }}>CyberSasi AI — Network Security Dashboard</h1>

      {error && (
        <div style={{ background: "#7f1d1d", padding: "12px", borderRadius: "8px", marginBottom: "16px" }}>
          {error}
        </div>
      )}

      <div style={{ display: "flex", gap: "16px", marginBottom: "24px", flexWrap: "wrap" }}>
        <StatCard label="Total Events" value={stats.total_events} color="#38bdf8" />
        <StatCard label="Malicious" value={stats.malicious_count} color="#f87171" />
        <StatCard label="Normal" value={stats.normal_count} color="#4ade80" />
        <StatCard label="Blocked IPs" value={stats.blocked_ips.length} color="#facc15" />
      </div>

      <div style={{ background: "#1e293b", padding: "16px", borderRadius: "8px", marginBottom: "24px" }}>
        <h2>Traffic Confidence Over Time</h2>
        <Line data={chartData} />
      </div>

      <div style={{ background: "#1e293b", padding: "16px", borderRadius: "8px" }}>
        <h2>Recent Alerts</h2>
        <table style={{ width: "100%", borderCollapse: "collapse" }}>
          <thead>
            <tr style={{ textAlign: "left", borderBottom: "1px solid #334155" }}>
              <th style={{ padding: "8px" }}>Time</th>
              <th style={{ padding: "8px" }}>Source IP</th>
              <th style={{ padding: "8px" }}>Destination IP</th>
              <th style={{ padding: "8px" }}>Protocol</th>
              <th style={{ padding: "8px" }}>Label</th>
              <th style={{ padding: "8px" }}>Confidence</th>
              <th style={{ padding: "8px" }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id + a.timestamp} style={{ borderBottom: "1px solid #334155" }}>
                <td style={{ padding: "8px" }}>{new Date(a.timestamp).toLocaleString()}</td>
                <td style={{ padding: "8px" }}>{a.src_ip}</td>
                <td style={{ padding: "8px" }}>{a.dst_ip}</td>
                <td style={{ padding: "8px" }}>{a.protocol}</td>
                <td style={{ padding: "8px", color: a.label === "malicious" ? "#f87171" : "#4ade80" }}>
                  {a.label}
                </td>
                <td style={{ padding: "8px" }}>{a.confidence}</td>
                <td style={{ padding: "8px" }}>{a.action_taken}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: "#1e293b", padding: "16px", borderRadius: "8px", flex: "1", minWidth: "150px" }}>
      <div style={{ fontSize: "14px", color: "#94a3b8" }}>{label}</div>
      <div style={{ fontSize: "32px", fontWeight: "bold", color }}>{value}</div>
    </div>
  );
}

export default App;
