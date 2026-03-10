import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { Shield, MessageSquare, BarChart3, Zap } from 'lucide-react'
import { useState, useEffect } from 'react'
import { connectSocket } from './utils/socketManager'
import ChatApp from './pages/ChatApp'
import AdminDashboard from './pages/AdminDashboard'
import './index.css'

export default function App() {
  const [connected, setConnected] = useState(false)

  useEffect(() => {
    const socket = connectSocket()
    socket.on('connect', () => setConnected(true))
    socket.on('disconnect', () => setConnected(false))
    return () => { socket.off('connect'); socket.off('disconnect') }
  }, [])

  return (
    <BrowserRouter>
      <div className="app">
        {/* ── Top Bar ─────────────────────────────────────── */}
        <header className="topbar">
          <NavLink to="/" className="topbar-brand">
            <Shield size={22} />
            CryptoChat <span style={{ color: 'var(--accent-purple)', fontWeight: 800 }}>v2</span>
          </NavLink>

          <nav className="topbar-nav">
            <NavLink to="/" end className={({ isActive }) => `nav-btn${isActive ? ' active' : ''}`}>
              <MessageSquare size={14} /> Chat
            </NavLink>
            <NavLink to="/admin" className={({ isActive }) => `nav-btn${isActive ? ' active' : ''}`}>
              <BarChart3 size={14} /> Dashboard
            </NavLink>
          </nav>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{
              fontSize: '0.7rem',
              fontFamily: 'var(--font-mono)',
              color: connected ? 'var(--accent-green)' : 'var(--text-muted)',
              letterSpacing: '0.04em',
              transition: 'color 0.4s',
            }}>
              {connected ? 'LIVE' : 'OFF'}
            </span>
            <div
              title={connected ? 'Connected' : 'Disconnected'}
              style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}
            >
              <div className={`status-dot${connected ? ' connected' : ''}`} />
            </div>
          </div>
        </header>

        {/* ── Page Content ────────────────────────────────── */}
        <main className="page">
          <Routes>
            <Route path="/" element={<ChatApp />} />
            <Route path="/pair" element={<ChatApp />} />
            <Route path="/admin" element={<AdminDashboard />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
