import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { QRCodeSVG } from 'qrcode.react'
import { QrCode, Scan, ArrowLeft, CheckCircle, Copy, Link as LinkIcon, Hash } from 'lucide-react'
import { api } from '../utils/api'

export default function DevicePairing({ onPaired }) {
    const [searchParams] = useSearchParams()
    const initialCode = (searchParams.get('code') || '').trim()

    const [mode, setMode] = useState('select')   // select | generate | scan | scanned
    const [pairingData, setPairingData] = useState(null)   // from /api/pairing/initiate
    const [scannedResult, setScannedResult] = useState(null) // Device B's scan response
    const [scanInput, setScanInput] = useState('')
    const [error, setError] = useState(null)
    const [loading, setLoading] = useState(false)
    const [copied, setCopied] = useState(false)
    const [autoCompleting, setAutoCompleting] = useState(false)

    // ── Step 1: Generate QR ──────────────────────────────────────────────────────
    const handleGenerate = async () => {
        setLoading(true)
        setError(null)
        try {
            const res = await fetch(api('/api/pairing/initiate'), { method: 'POST' })
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

    // ── Step 2 (Device B): Join with 6-digit code (or deep link) ─────────────────
    const handleJoinWithCode = async (code) => {
        const clean = (code || '').trim()
        if (!clean) return
        setLoading(true)
        setError(null)
        try {
            const lookupRes = await fetch(api(`/api/pairing/lookup?code=${encodeURIComponent(clean)}`))
            const lookup = await lookupRes.json()
            if (!lookupRes.ok) throw new Error(lookup.error || 'Invalid or expired pairing code')

            const res = await fetch(api('/api/pairing/scan'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ qr_data: lookup.qr_data })
            })
            const data = await res.json()
            if (!res.ok) throw new Error(data.error || 'Pairing failed')

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
        onPaired?.({
            deviceId: scannedResult.device_id,
            privateKey: scannedResult.private_key,
            publicKey: scannedResult.public_key,
            pairedWith: scannedResult.paired_device,
            safetyNumber: scannedResult.safety_number,
            sessionKey: scannedResult.session_key,
            isInitiator: false  // Device B: send="recv-chain", recv="send-chain"
        })
    }

    // ── Step 2 (Device A): Auto-complete once Device B joined ────────────────────
    const handleAutoComplete = async (isAuto = false) => {
        if (!pairingData?.device_id) return
        if (!isAuto) setAutoCompleting(true)
        setError(null)
        try {
            const res = await fetch(api('/api/pairing/complete-auto'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    device_id: pairingData.device_id
                })
            })
            const data = await res.json()
            
            // If polling and not ready yet, just return silently
            if (isAuto && res.status === 409) return

            if (!res.ok) throw new Error(data.error || 'Complete failed')

            onPaired?.({
                deviceId: pairingData.device_id,
                privateKey: pairingData.private_key,
                publicKey: pairingData.public_key,
                pairedWith: data.paired_device,
                safetyNumber: data.safety_number,
                sessionKey: data.session_key,
                isInitiator: true   // Device A: send="send-chain", recv="recv-chain"
            })
        } catch (e) {
            if (!isAuto) setError(e.message)
        } finally {
            if (!isAuto) setAutoCompleting(false)
        }
    }

    const copyPairUrl = () => {
        if (pairingData?.pair_url) {
            navigator.clipboard.writeText(pairingData.pair_url)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
        }
    }

    const copyCode = () => {
        if (pairingData?.pairing_code) {
            navigator.clipboard.writeText(pairingData.pairing_code)
            setCopied(true)
            setTimeout(() => setCopied(false), 2000)
        }
    }

    const qrValue = useMemo(() => pairingData?.pair_url || '', [pairingData?.pair_url])

    // Background polling for Device A to auto-complete pairing
    useEffect(() => {
        if (mode !== 'generate' || !pairingData?.device_id) return
        
        const interval = setInterval(() => {
            handleAutoComplete(true)
        }, 3000) // Poll every 3 seconds

        return () => clearInterval(interval)
    }, [mode, pairingData?.device_id])

    // Auto-join when opened from camera deep link (/pair?code=XXXXXX)
    useEffect(() => {
        if (!initialCode) return
        setMode('scan')
        setScanInput(initialCode)
        handleJoinWithCode(initialCode)
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [initialCode])

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
                        {mode === 'generate' && 'Pairing Link Generated'}
                        {mode === 'scan' && 'Join with Code'}
                        {mode === 'scanned' && 'Share Your Public Key'}
                    </h1>
                    <p>
                        {mode === 'select' && 'No login required — cryptographic zero-knowledge proof'}
                        {mode === 'generate' && 'Device B can scan this QR (it opens a link) or enter the 6-digit code'}
                        {mode === 'scan' && 'Enter the 6-digit pairing code (or open /pair?code=XXXXXX)'}
                        {mode === 'scanned' && 'Copy your DH public key and give it to Device A to complete pairing'}
                    </p>
                </div>

                {/* ── SELECT ── */}
                {mode === 'select' && (
                    <div className="pairing-options">
                        <button className="btn btn-primary" onClick={handleGenerate} disabled={loading}>
                            {loading ? <span className="spinner" /> : <QrCode size={16} />}
                            Generate Link + Code (Device A)
                        </button>
                        <button className="btn btn-secondary" onClick={() => setMode('scan')}>
                            <Scan size={16} /> Scan QR Code (Device B)
                        </button>
                        <ul className="pairing-steps mt-sm" style={{ paddingLeft: '1.2rem' }}>
                            <li><b>Device A:</b> Generate a link + 6-digit code → show QR to Device B</li>
                            <li><b>Device B:</b> Scan QR (opens link) or enter code → pairing happens automatically</li>
                            <li><b>Device A:</b> Click “Complete Pairing” (no copy/paste)</li>
                            <li><b>Both:</b> Compare safety numbers to detect MITM</li>
                        </ul>
                    </div>
                )}

                {/* ── GENERATE ── */}
                {mode === 'generate' && pairingData && (
                    <div className="qr-display">
                        {qrValue && (
                            <QRCodeSVG value={qrValue} size={220} bgColor="#0f1020" fgColor="#00e5ff" />
                        )}

                        <div className="w-full" style={{ display: 'grid', gap: '0.6rem' }}>
                            <div className="card p-md" style={{ background: 'rgba(15,24,40,0.65)' }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <Hash size={14} />
                                        <span style={{ fontWeight: 700, fontSize: '0.85rem' }}>Pairing code</span>
                                    </div>
                                    <button className="btn btn-ghost btn-sm" onClick={copyCode}>
                                        <Copy size={13} /> {copied ? 'Copied' : 'Copy'}
                                    </button>
                                </div>
                                <div className="mono" style={{
                                    marginTop: '0.5rem',
                                    fontSize: '1.6rem',
                                    letterSpacing: '0.25em',
                                    textAlign: 'center',
                                    color: 'var(--accent-cyan)'
                                }}>
                                    {pairingData.pairing_code}
                                </div>
                                <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.4rem', textAlign: 'center' }}>
                                    Expires in ~2 minutes
                                </div>
                            </div>

                            <div className="card p-md" style={{ background: 'rgba(15,24,40,0.65)' }}>
                                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.75rem' }}>
                                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                        <LinkIcon size={14} />
                                        <span style={{ fontWeight: 700, fontSize: '0.85rem' }}>Pairing link</span>
                                    </div>
                                    <button className="btn btn-ghost btn-sm" onClick={copyPairUrl}>
                                        <Copy size={13} /> {copied ? 'Copied' : 'Copy'}
                                    </button>
                                </div>
                                <div className="mono" style={{
                                    marginTop: '0.5rem',
                                    fontSize: '0.72rem',
                                    wordBreak: 'break-all',
                                    color: 'var(--text-secondary)'
                                }}>
                                    {pairingData.pair_url}
                                </div>
                            </div>
                        </div>

                        <p className="qr-label">Device ID: <span className="mono">{pairingData.device_id.slice(0, 12)}…</span></p>
                        <hr style={{ width: '100%', border: 'none', borderTop: '1px solid var(--border)' }} />
                        <div className="scan-input-area w-full">
                            <button className="btn btn-primary" onClick={handleAutoComplete} disabled={autoCompleting}>
                                {autoCompleting ? <span className="spinner" /> : <CheckCircle size={15} />}
                                Complete Pairing
                            </button>
                            <div className="text-muted" style={{ fontSize: '0.78rem', textAlign: 'center' }}>
                                If Device B hasn’t joined yet, this will tell you to wait.
                            </div>
                        </div>
                    </div>
                )}

                {/* ── SCAN ── */}
                {mode === 'scan' && (
                    <div className="scan-input-area">
                        <label className="text-muted">Enter pairing code (6 digits):</label>
                        <input
                            className="input mono"
                            placeholder="e.g. 482917"
                            value={scanInput}
                            onChange={e => setScanInput(e.target.value)}
                        />
                        <button className="btn btn-primary" onClick={() => handleJoinWithCode(scanInput)} disabled={loading || !scanInput}>
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
