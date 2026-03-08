import { ShieldCheck, AlertTriangle } from 'lucide-react'

export default function SafetyNumber({ safetyNumber, verified = true }) {
    if (!safetyNumber) return null

    const digits = safetyNumber.split('')

    return (
        <div className="safety-bar">
            <span className="safety-label">
                🔢 Safety Number — compare verbally with your contact:
            </span>

            <div className="safety-numbers">
                {digits.map((d, i) => (
                    <div key={i} className="safety-digit">{d}</div>
                ))}
            </div>

            <div className={`safety-verified`} style={{ color: verified ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                {verified
                    ? <><ShieldCheck size={14} /> Verified</>
                    : <><AlertTriangle size={14} /> Unverified</>
                }
            </div>
        </div>
    )
}
