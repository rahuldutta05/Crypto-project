import { Link, useLocation } from "react-router-dom";

const NAV_LINKS = [
  { to: "/", label: "📤 Send Anon" },
  { to: "/chat", label: "💬 Chat" },
  { to: "/inbox", label: "📥 Inbox" },
  { to: "/register", label: "🔑 Register" },
  { to: "/verify", label: "🔍 Verify" },
  { to: "/attacker", label: "🔴 Attacker" },
  { to: "/sniffer", label: "📡 Sniffer" },
];

export default function Layout({ children }) {
  const { pathname } = useLocation();
  return (
    <div className="app-layout">
      <nav className="navbar">
        <div className="nav-brand">🔐 SecureChat</div>
        <div className="nav-links">
          {NAV_LINKS.map((l) => (
            <Link key={l.to} to={l.to}
              className={`nav-link ${pathname === l.to ? "active" : ""}`}>
              {l.label}
            </Link>
          ))}
        </div>
      </nav>
      <main className="main-content">{children}</main>
    </div>
  );
}
