import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { Shield, MessageSquare, BarChart3 } from 'lucide-react'
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
        {/* ── Top Bar ─────────────────── */}
        <header className="topbar">
          <NavLink to="/" className="topbar-brand">
            <Shield size={22} />
            CryptoChat v2
          </NavLink>

          <nav className="topbar-nav">
            <NavLink to="/" end className={({ isActive }) => `nav-btn${isActive ? ' active' : ''}`}>
              <MessageSquare size={15} /> Chat
            </NavLink>
            <NavLink to="/admin" className={({ isActive }) => `nav-btn${isActive ? ' active' : ''}`}>
              <BarChart3 size={15} /> Dashboard
            </NavLink>
          </nav>

          <div title={connected ? 'Connected' : 'Disconnected'}>
            <div className={`status-dot${connected ? ' connected' : ''}`} />
          </div>
        </header>

        {/* ── Page Content ────────────── */}
        <main className="page">
          <Routes>
            <Route path="/" element={<ChatApp />} />
            <Route path="/admin" element={<AdminDashboard />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
