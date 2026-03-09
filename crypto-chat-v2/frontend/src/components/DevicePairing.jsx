import { useState } from 'react'
import { QRCodeSVG } from 'qrcode.react'
import { QrCode, Scan, ArrowLeft, CheckCircle, Copy } from 'lucide-react'

export default function DevicePairing({ onPaired }) {
    const [mode, setMode] = useState('select')   // select | generate | scan | scanned | completing
    const [pairingData, setPairingData] = useState(null)   // from /api/pairing/initiate
    const [scannedResult, setScannedResult] = useState(null) // Device B's scan response
    const [scanInput, setScanInput] = useState('')
    const [error, setError] = useState(null)
    const [loading, setLoading] = useState(false)
    const [copied, setCopied] = useState(false)

    // ── Step 1: Generate QR ──────────────────────────────────────────────────────
    const handleGenerate = async () => {
        setLoading(true)
        setError(null)
        try {
            const res = await fetch('/api/pairing/initiate', { method: 'POST' })
            const data = await res.json()
            if (!res.ok) throw new Error(data.error || 'Failed to initiate pairing')
            setPairingData(data)
            setMode('generate')
        } catch (e) {
            setError(e.message)
        } finally {
            setLoading(false)
        }
    }

    // ── Step 2 (Device B): Scan QR → show DH public key for Device A ────────────
    const handleScan = async () => {
        if (!scanInput.trim()) return
        setLoading(true)
        setError(null)
        try {
            const qrObject = JSON.parse(scanInput.trim())
            const res = await fetch('/api/pairing/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ qr_data: qrObject })
            })
            const data = await res.json()
            if (!res.ok) throw new Error(data.error || 'Scan failed')

            // Hold the result and show it so the user can copy dh_public_key to Device A
            setScannedResult(data)
            setMode('scanned')
        } catch (e) {
            setError(e.message)
        } finally {
            setLoading(false)
        }
    }

    // ── Step 2b (Device B): Copy DH public key helper ────────────────────────────
    const copyDhPublicKey = () => {
        if (scannedResult?.dh_public_key) {
            navigator.clipboard.writeText(scannedResult.dh_public_key)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
        }
    }

    // ── Step 2c (Device B): Proceed to chat after sharing the key ─────────────────
    const handleProceedAfterScan = () => {
        onPaired({
            deviceId: scannedResult.device_id,
            privateKey: scannedResult.private_key,
            publicKey: scannedResult.public_key,
            pairedWith: scannedResult.paired_device,
            safetyNumber: scannedResult.safety_number,
            sessionKey: scannedResult.session_key
        })
    }

    // ── Step 2 (Device A): Complete DH with Device B's public key ─────────────────
    const handleComplete = async () => {
        if (!scanInput.trim() || !pairingData) return
        setLoading(true)
        setError(null)
        try {
            const device2DhPublic = scanInput.trim()
            const res = await fetch('/api/pairing/complete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device_id: pairingData.device_id,
                    device2_dh_public: device2DhPublic
                })
            })
            const data = await res.json()
            if (!res.ok) throw new Error(data.error || 'Complete failed')

            onPaired({
                deviceId: pairingData.device_id,
                privateKey: pairingData.private_key,
                publicKey: pairingData.public_key,
                pairedWith: data.paired_device,
                safetyNumber: data.safety_number,
                sessionKey: data.session_key
            })
        } catch (e) {
            setError(e.message)
        } finally {
            setLoading(false)
        }
    }

    const copyQR = () => {
        if (pairingData?.qr_data) {
            navigator.clipboard.writeText(JSON.stringify(pairingData.qr_data))
        }
    }

    // ── Render ────────────────────────────────────────────────────────────────────
    return (
        <div className="pairing-screen">
            <div className="card pairing-card">

                {/* Header */}
                {mode !== 'select' && (
                    <button className="btn btn-ghost btn-sm mb-sm" style={{ width: 'fit-content' }}
                        onClick={() => { setMode('select'); setError(null); setScanInput('') }}>
                        <ArrowLeft size={14} /> Back
                    </button>
                )}

                <div className="pairing-header">
                    <div className="lock-icon">
                        {mode === 'select' ? <QrCode size={28} color="var(--accent-cyan)" /> :
                            mode === 'generate' ? <QrCode size={28} color="var(--accent-cyan)" /> :
                                <Scan size={28} color="var(--accent-purple)" />}
                    </div>
                    <h1>
                        {mode === 'select' && 'Secure Device Pairing'}
                        {mode === 'generate' && 'QR Code Generated'}
                        {mode === 'scan' && 'Connect to Device'}
                        {mode === 'scanned' && 'Share Your Public Key'}
                        {mode === 'completing' && 'Complete Pairing'}
                    </h1>
                    <p>
                        {mode === 'select' && 'No login required — cryptographic zero-knowledge proof'}
                        {mode === 'generate' && 'Share the QR code with the second device, then paste in its DH public key'}
                        {mode === 'scan' && 'Paste the QR JSON data from the first device'}
                        {mode === 'scanned' && 'Copy your DH public key and give it to Device A to complete pairing'}
                        {mode === 'completing' && 'Paste the DH public key returned by Device B'}
                    </p>
                </div>

                {/* ── SELECT ── */}
                {mode === 'select' && (
                    <div className="pairing-options">
                        <button className="btn btn-primary" onClick={handleGenerate} disabled={loading}>
                            {loading ? <span className="spinner" /> : <QrCode size={16} />}
                            Generate QR Code (Device A)
                        </button>
                        <button className="btn btn-secondary" onClick={() => setMode('scan')}>
                            <Scan size={16} /> Scan QR Code (Device B)
                        </button>
                        <ul className="pairing-steps mt-sm" style={{ paddingLeft: '1.2rem' }}>
                            <li><b>Device A:</b> Click "Generate QR Code" → show QR to Device B</li>
                            <li><b>Device B:</b> Click "Scan QR Code" → paste the QR JSON → get session key</li>
                            <li><b>Device A:</b> Paste Device B's DH public key to finalise pairing</li>
                            <li><b>Both:</b> Compare safety numbers to detect MITM</li>
                        </ul>
                    </div>
                )}

                {/* ── GENERATE ── */}
                {mode === 'generate' && pairingData && (
                    <div className="qr-display">
                        {pairingData.qr_code
                            ? <img src={pairingData.qr_code} alt="QR Code" />
                            : <QRCodeSVG value={JSON.stringify(pairingData.qr_data)} size={220}
                                bgColor="#0f1020" fgColor="#00e5ff" />
                        }
                        <button className="btn btn-ghost btn-sm" onClick={copyQR}>
                            <Copy size={13} /> Copy QR JSON
                        </button>
                        <p className="qr-label">Device ID: <span className="mono">{pairingData.device_id.slice(0, 12)}…</span></p>
                        <hr style={{ width: '100%', border: 'none', borderTop: '1px solid var(--border)' }} />
                        <p className="qr-label" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                            After Device B scans, paste its DH public key below:
                        </p>
                        <div className="scan-input-area w-full">
                            <textarea className="input" placeholder="Paste Device B's dh_public_key here…"
                                value={scanInput} onChange={e => setScanInput(e.target.value)} rows={3} />
                            <button className="btn btn-primary" onClick={handleComplete} disabled={loading || !scanInput}>
                                {loading ? <span className="spinner" /> : <CheckCircle size={15} />}
                                Complete Pairing
                            </button>
                        </div>
                    </div>
                )}

                {/* ── SCAN ── */}
                {mode === 'scan' && (
                    <div className="scan-input-area">
                        <label className="text-muted">Paste QR JSON from Device A:</label>
                        <textarea className="input" rows={5}
                            placeholder='{"device_id":"...","dh_public_key":"...","challenge":"...",...}'
                            value={scanInput} onChange={e => setScanInput(e.target.value)} />
                        <button className="btn btn-primary" onClick={handleScan} disabled={loading || !scanInput}>
                            {loading ? <span className="spinner" /> : <CheckCircle size={15} />}
                            Connect & Pair
                        </button>
                    </div>
                )}

                {/* ── SCANNED (Device B shares its DH public key with Device A) ── */}
                {mode === 'scanned' && scannedResult && (
                    <div className="scan-input-area">
                        <label className="text-muted" style={{ fontWeight: 600 }}>
                            Your DH Public Key — paste this into Device A:
                        </label>
                        <textarea
                            className="input mono"
                            rows={4}
                            readOnly
                            value={scannedResult.dh_public_key}
                            style={{ fontSize: '0.74rem', wordBreak: 'break-all', cursor: 'text' }}
                        />
                        <button className="btn btn-secondary" onClick={copyDhPublicKey}>
                            <Copy size={14} />
                            {copied ? '✓ Copied!' : 'Copy DH Public Key'}
                        </button>
                        <p className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.4rem' }}>
                            Once Device A has pasted your key and completed pairing, click below:
                        </p>
                        <button className="btn btn-primary" onClick={handleProceedAfterScan}>
                            <CheckCircle size={15} /> Continue to Chat
                        </button>
                    </div>
                )}

                {error && (
                    <div className="mt-sm" style={{
                        padding: '0.65rem', background: 'rgba(255,56,96,0.12)',
                        border: '1px solid rgba(255,56,96,0.3)', borderRadius: '8px',
                        color: 'var(--accent-red)', fontSize: '0.82rem'
                    }}>
                        ⚠ {error}
                    </div>
                )}
            </div>
        </div>
    )
}
