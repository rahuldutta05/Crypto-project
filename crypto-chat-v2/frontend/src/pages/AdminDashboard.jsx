import { useState, useEffect, useCallback } from 'react'
import { BarChart3, RefreshCw, Download, Shield, Activity, AlertTriangle, Clock, Zap } from 'lucide-react'

// Backend base URL — set VITE_API_URL in Vercel env vars to reach Railway backend
const API_BASE = (import.meta.env.VITE_API_URL || '').replace(/\/$/, '')
const api = (path) => `${API_BASE}${path}`

export default function AdminDashboard() {
    const [stats, setStats] = useState(null)
    const [summary, setSummary] = useState(null)
    const [events, setEvents] = useState([])
    const [threat, setThreat] = useState(null)
    const [report, setReport] = useState(null)
    const [loading, setLoading] = useState(true)
    const [autoRefresh, setAutoRefresh] = useState(false)
    const [simulating, setSimulating] = useState(null)  // attack_type currently being simulated
    const [simResult, setSimResult] = useState(null)    // { ok, message }

    const fetchAll = useCallback(async () => {
        setLoading(true)
        try {
            const [statsRes, summaryRes, eventsRes, threatRes, reportRes] = await Promise.all([
                fetch(api('/api/admin/system-stats')),
                fetch(api('/api/admin/attack-summary')),
                fetch(api('/api/admin/security-events')),
                fetch(api('/api/admin/threat-assessment')),
                fetch(api('/api/admin/penetration-test-report'))
            ])
            const [s, sum, ev, th, rep] = await Promise.all([
                statsRes.json(), summaryRes.json(), eventsRes.json(), threatRes.json(), reportRes.json()
            ])
            setStats(s)
            setSummary(sum)
            setEvents((ev.events || []).slice(-50).reverse())  // latest 50
            setThreat(th)
            setReport(rep)
        } catch (e) {
            console.error('Dashboard fetch error', e)
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { fetchAll() }, [fetchAll])

    useEffect(() => {
        if (!autoRefresh) return
        const id = setInterval(fetchAll, 5000)
        return () => clearInterval(id)
    }, [autoRefresh, fetchAll])

    const exportJSON = async () => {
        const res = await fetch(api('/api/admin/export-events?format=json'))
        const blob = await res.blob()
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url; a.download = 'security_events.json'; a.click()
        URL.revokeObjectURL(url)
    }

    const simulateAttack = async (attackType) => {
        setSimulating(attackType)
        setSimResult(null)
        try {
            const res = await fetch(api('/api/admin/simulate-attack'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attack_type: attackType })
            })
            const data = await res.json()
            setSimResult({ ok: res.ok, message: data.message || data.error })
            if (res.ok) await fetchAll()   // refresh dashboard so event appears
        } catch (e) {
            setSimResult({ ok: false, message: e.message })
        } finally {
            setSimulating(null)
        }
    }

    const severityClass = (sev) => {
        const map = { info: 'info', warning: 'warning', high: 'high', critical: 'critical' }
        return `sev-badge sev-${map[sev] ?? 'info'}`
    }

    const formatTime = (iso) => iso ? new Date(iso).toLocaleString() : '—'

    const attacksBy = summary?.summary?.attacks_by_type ?? {}
    const maxAttack = Math.max(1, ...Object.values(attacksBy))

    const attackLabels = {
        replay_attack_detected: 'Replay Attacks',
        brute_force_detected: 'Brute Force',
        mitm_detected: 'MITM Attempts',
        unauthorized_attempt: 'Unauthorized Access',
        timing_anomaly: 'Timing Attacks',
        suspicious_pattern: 'Suspicious Pattern'
    }

    return (
        <div className="admin-layout">
            {/* Header */}
            <div className="admin-header">
                <div className="admin-title">
                    <BarChart3 size={20} color="var(--accent-cyan)" />
                    <h2>Security Monitoring Dashboard</h2>
                </div>
                <div className="flex items-center gap-sm">
                    <label className="flex items-center gap-sm text-muted" style={{ cursor: 'pointer', fontSize: '0.82rem' }}>
                        <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} />
                        Auto-refresh (5s)
                    </label>
                    <button className="btn btn-ghost btn-sm" onClick={fetchAll} disabled={loading}>
                        <RefreshCw size={14} className={loading ? 'spinning' : ''} /> Refresh
                    </button>
                    <button className="btn btn-ghost btn-sm" onClick={exportJSON}>
                        <Download size={14} /> Export JSON
                    </button>
                </div>
            </div>

            {/* Attacker Simulation Card */}
            <div className="card" style={{ marginBottom: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                    <Zap size={16} color="var(--accent-orange)" />
                    <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--accent-orange)' }}>Attacker Simulation</span>
                    <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginLeft: '0.25rem' }}>
                        — fire simulated events to test the dashboard
                    </span>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                    {[
                        { type: 'replay_attack_detected',  label: '🔁 Replay Attack',       color: 'var(--accent-red)' },
                        { type: 'unauthorized_attempt',    label: '🚫 Unauthorized Access',  color: 'var(--accent-orange)' },
                        { type: 'auth_failure',            label: '🔑 Auth Failure',         color: 'var(--accent-yellow, #f0c040)' },
                        { type: 'brute_force_detected',    label: '💥 Brute Force',          color: 'var(--accent-red)' },
                        { type: 'suspicious_pattern',      label: '👁 Suspicious Pattern',   color: 'var(--accent-cyan)' },
                        { type: 'mitm_detected',           label: '🕵 MITM Attempt',         color: 'var(--accent-purple, #a78bfa)' },
                    ].map(({ type, label, color }) => (
                        <button
                            key={type}
                            className="btn btn-ghost btn-sm"
                            style={{ borderColor: color, color, opacity: simulating ? 0.6 : 1 }}
                            disabled={!!simulating}
                            onClick={() => simulateAttack(type)}
                        >
                            {simulating === type ? '⏳ Sending…' : label}
                        </button>
                    ))}
                </div>
                {simResult && (
                    <div style={{
                        marginTop: '0.6rem', fontSize: '0.78rem', padding: '0.3rem 0.6rem',
                        borderRadius: '4px', background: simResult.ok ? 'rgba(0,255,150,0.08)' : 'rgba(255,80,80,0.1)',
                        color: simResult.ok ? 'var(--accent-green, #4ade80)' : 'var(--accent-red)'
                    }}>
                        {simResult.ok ? '✓' : '✗'} {simResult.message}
                    </div>
                )}
            </div>

            {/* Threat Level Banner */}
            {threat && (
                <div className={`threat-level threat-${threat.threat_level}`}>
                    <div className="threat-dot" />
                    <div>
                        <div style={{ fontWeight: 700, fontSize: '0.9rem' }}>Threat Level: {threat.threat_level}</div>
                        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                            {threat.recommendation}
                        </div>
                    </div>
                    <div className="flex items-center gap-sm" style={{ marginLeft: 'auto', flexWrap: 'wrap' }}>
                        {[
                            ['Critical Events', threat.recent_activity?.critical_events, 'var(--accent-red)'],
                            ['High Events', threat.recent_activity?.high_events, 'var(--accent-orange)'],
                            ['Total (1hr)', threat.recent_activity?.total_events, 'var(--text-secondary)']
                        ].map(([label, val, color]) => (
                            <div key={label} style={{ textAlign: 'center' }}>
                                <div style={{ fontSize: '1.3rem', fontWeight: 700, color, fontFamily: 'var(--font-mono)' }}>{val ?? 0}</div>
                                <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>{label}</div>
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Stats grid */}
            <div className="stats-grid">
                {[
                    { label: 'Total Security Events', value: summary?.summary?.total_security_events ?? '—', cls: 'cyan', sub: 'All time' },
                    { label: 'Attacks Detected', value: summary?.summary?.total_attacks_detected ?? '—', cls: 'orange', sub: 'All types' },
                    { label: 'Successful Attacks', value: summary?.summary?.successful_attacks ?? 0, cls: 'red', sub: 'Should be 0!' },
                    { label: 'Attack Success Rate', value: `${((summary?.summary?.attack_success_rate) ?? 0).toFixed(1)}%`, cls: 'red', sub: summary?.interpretation?.verdict },
                    { label: 'Devices Registered', value: stats?.core_principles?.anonymous_verifiable?.total_devices ?? '—', cls: 'cyan', sub: 'Anonymous IDs' },
                    { label: 'Proofs Created', value: stats?.core_principles?.proof_of_existence?.total_proofs ?? '—', cls: 'green', sub: 'Content NOT stored' },
                    { label: 'Messages Expired', value: stats?.core_principles?.cryptographic_expiry?.expired_messages ?? '—', cls: 'orange', sub: 'Keys destroyed' },
                    { label: 'Nonces Tracked', value: stats?.security?.nonces_tracked ?? '—', cls: 'purple', sub: 'Replay prevention' }
                ].map(({ label, value, cls, sub }) => (
                    <div key={label} className="stat-card">
                        <div className="stat-label">{label}</div>
                        <div className={`stat-value ${cls}`}>{value}</div>
                        {sub && <div className="stat-sub">{sub}</div>}
                    </div>
                ))}
            </div>

            <div className="two-col">
                {/* Attack type breakdown */}
                <div className="card p-md">
                    <div className="section-title">📊 Attacks by Type</div>
                    {Object.keys(attacksBy).length === 0 ? (
                        <div className="text-muted" style={{ fontSize: '0.82rem' }}>No attacks detected yet — system is secure ✓</div>
                    ) : (
                        Object.entries(attacksBy).map(([type, count]) => (
                            <div key={type} className="attack-bar">
                                <div className="attack-bar-label">{attackLabels[type] ?? type}</div>
                                <div className="attack-bar-track">
                                    <div className="attack-bar-fill" style={{ width: `${(count / maxAttack) * 100}%` }} />
                                </div>
                                <div className="attack-bar-count">{count}</div>
                            </div>
                        ))
                    )}
                </div>

                {/* Pentest strengths */}
                <div className="card p-md">
                    <div className="section-title">🛡 Security Strengths</div>
                    {(report?.report?.security_strengths ?? []).length === 0 ? (
                        <div className="text-muted" style={{ fontSize: '0.82rem' }}>No data yet — run some tests first</div>
                    ) : (
                        <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                            {(report?.report?.security_strengths ?? []).map((s, i) => (
                                <li key={i} style={{ fontSize: '0.82rem', color: 'var(--accent-green)', display: 'flex', gap: '0.4rem' }}>
                                    <span style={{ flexShrink: 0 }}>✓</span> {s.replace('✓ ', '')}
                                </li>
                            ))}
                        </ul>
                    )}

                    {(report?.report?.vulnerabilities_found ?? []).length > 0 && (
                        <>
                            <div className="section-title mt-md">⚠ Vulnerabilities Found</div>
                            {(report.report.vulnerabilities_found).map((v, i) => (
                                <div key={i} style={{ fontSize: '0.82rem', color: 'var(--accent-red)', marginBottom: '0.35rem' }}>{v}</div>
                            ))}
                        </>
                    )}

                    {/* Verdict */}
                    <div className="mt-md flex items-center gap-sm">
                        <Shield size={14} />
                        <span style={{ fontSize: '0.82rem', color: 'var(--text-secondary)' }}>Verdict: </span>
                        <span className={`verdict-badge verdict-${summary?.interpretation?.verdict ?? 'SECURE'}`}>
                            {summary?.interpretation?.verdict ?? 'SECURE'}
                        </span>
                    </div>
                </div>
            </div>

            {/* Core principles status */}
            <div className="card p-md">
                <div className="section-title">🔐 Core Principles Status</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem' }}>
                    {[
                        {
                            title: '1. Anonymous but Verifiable',
                            icon: '🕶',
                            items: [
                                `Devices: ${stats?.core_principles?.anonymous_verifiable?.total_devices ?? 0}`,
                                `Paired: ${stats?.core_principles?.anonymous_verifiable?.paired_devices ?? 0}`,
                                `Method: ${stats?.core_principles?.anonymous_verifiable?.verification_method ?? 'ZKP'}`
                            ],
                            color: 'var(--accent-cyan)'
                        },
                        {
                            title: '2. Proof-of-Existence',
                            icon: '🔗',
                            items: [
                                `Proofs: ${stats?.core_principles?.proof_of_existence?.total_proofs ?? 0}`,
                                `Content stored: ${stats?.core_principles?.proof_of_existence?.content_stored ? '⚠ YES' : '✓ NO'}`,
                                `Verified: ${stats?.core_principles?.proof_of_existence?.messages_verified ?? 0}`
                            ],
                            color: 'var(--accent-green)'
                        },
                        {
                            title: '3. Cryptographic Expiry',
                            icon: '💀',
                            items: [
                                `Active msgs: ${stats?.core_principles?.cryptographic_expiry?.active_messages ?? 0}`,
                                `Keys destroyed: ${stats?.core_principles?.cryptographic_expiry?.keys_destroyed ?? 0}`,
                                `Recovery possible: ${stats?.core_principles?.cryptographic_expiry?.recovery_possible ? '⚠ YES' : '✓ NO'}`
                            ],
                            color: 'var(--accent-orange)'
                        }
                    ].map(({ title, icon, items, color }) => (
                        <div key={title} style={{ padding: '0.75rem', background: 'var(--bg-surface)', borderRadius: '8px', border: '1px solid var(--border)' }}>
                            <div style={{ fontSize: '0.82rem', fontWeight: 600, color, marginBottom: '0.5rem' }}>{icon} {title}</div>
                            {items.map(item => (
                                <div key={item} style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginBottom: '0.2rem' }}>{item}</div>
                            ))}
                        </div>
                    ))}
                </div>
            </div>

            {/* Recent events table */}
            <div className="card p-md" style={{ minHeight: 200 }}>
                <div className="section-title flex items-center gap-sm">
                    <Activity size={14} /> Recent Security Events ({events.length})
                </div>
                {events.length === 0 ? (
                    <div className="text-muted" style={{ fontSize: '0.82rem' }}>
                        No events yet. Start the chat and try sending messages to generate events.
                    </div>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table className="events-table">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Event Type</th>
                                    <th>Severity</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {events.map(ev => (
                                    <tr key={ev.id}>
                                        <td style={{ whiteSpace: 'nowrap', color: 'var(--text-muted)' }}>
                                            <Clock size={11} style={{ display: 'inline', marginRight: 4 }} />
                                            {formatTime(ev.timestamp)}
                                        </td>
                                        <td>
                                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                                                {ev.event_type}
                                            </span>
                                        </td>
                                        <td><span className={severityClass(ev.severity)}>{ev.severity}</span></td>
                                        <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                            {JSON.stringify(ev.details)}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Pentest recommendations */}
            {(report?.recommendation?.length > 0) && (
                <div className="card p-md">
                    <div className="section-title">📋 Recommendations</div>
                    {report.recommendation.map((r, i) => (
                        <div key={i} style={{
                            fontSize: '0.82rem', marginBottom: '0.4rem',
                            color: r.startsWith('🚨') ? 'var(--accent-red)' : r.startsWith('⚠') ? 'var(--accent-orange)' : 'var(--accent-green)'
                        }}>
                            {r}
                        </div>
                    ))}
                </div>
            )}
        </div>
    )
}
