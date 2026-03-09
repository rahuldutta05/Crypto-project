import { useState, useEffect, useRef, useCallback } from 'react'
import { Send, Lock, Clock, AlertTriangle, Zap } from 'lucide-react'
import { initDoubleRatchet, ratchetEncrypt, ratchetDecrypt, generateNonce } from '../utils/cryptoUtils'
import { getSocket } from '../utils/socketManager'
import SafetyNumber from './SafetyNumber'

export default function ChatInterface({ deviceInfo }) {
    const { deviceId, pairedWith, safetyNumber, sessionKey, isInitiator } = deviceInfo

    const [messages, setMessages] = useState([])
    const [input, setInput] = useState('')
    const [expiryMinutes, setExpiryMinutes] = useState(60)
    const [burnOnRead, setBurnOnRead] = useState(false)
    const [sending, setSending] = useState(false)
    const [verified, setVerified] = useState(false)
    const bottomRef = useRef(null)
    const messagesAreaRef = useRef(null)
    const prevMsgCountRef = useRef(0)
    const socket = getSocket()
    // Double Ratchet state — held in a ref so React re-renders don't reset the chain
    const ratchetRef = useRef(null)

    // ── Initialise Double Ratchet chains from shared session key ───────────────────────
    useEffect(() => {
        if (sessionKey) {
            initDoubleRatchet(sessionKey, isInitiator ?? true).then(state => {
                ratchetRef.current = state
            })
        }
    }, [sessionKey, isInitiator])

    // ── Verify device via WebSocket (reliable on all devices) ────────────────
    // Called inside 'connect' so it fires whether the socket was already
    // connected when this component mounted or connects later (e.g. on mobile).
    const emitVerify = () => {
        socket.emit('verify_device', {
            device_id: deviceId,
            signature: 'demo_signature',
            challenge: 'demo_challenge'
        })
    }

    // ── Socket event listeners ────────────────────────────────────────────────────
    useEffect(() => {
        const onVerified = () => setVerified(true)
        const onVerificationFailed = () => setVerified(false)

        const onReceiveMessage = async (data) => {
            let content = '[encrypted]'
            // Ratchet-decrypt using the per-message HKDF-derived key
            if (ratchetRef.current && data.encrypted_data && data.encrypted_data.step) {
                try {
                    const { plaintext, newState } = await ratchetDecrypt(data.encrypted_data, ratchetRef.current)
                    ratchetRef.current = newState   // advance recv chain — old key discarded
                    content = plaintext
                } catch (err) {
                    content = `[decryption failed: ${err.message}]`
                }
            } else if (typeof data.encrypted_data === 'string') {
                content = data.encrypted_data  // plain-text fallback for legacy messages
            }

            setMessages(prev => [...prev, {
                id: data.message_id,
                content,
                sender: data.sender,
                mine: false,
                timestamp: data.timestamp,
                expiresAt: data.expires_at,
                proofHash: data.proof_hash,
                expired: false,
                burnOnRead: data.burn_on_read
            }])

            // PILLAR 3 NOVELTY: Burn on Read — notify server to destroy proof immediately
            if (data.burn_on_read) {
                setTimeout(() => {
                    socket.emit('destroy_message', { message_id: data.message_id })
                }, 500) // Small delay to ensure client has processed it
            }
        }

        const onMessageSent = (data) => {
            // Mark the pending message as sent
            setMessages(prev => prev.map(m =>
                m.id === 'pending' ? { ...m, id: data.message_id, proofHash: data.proof_hash, expiresAt: data.expires_at } : m
            ))
        }

        const onError = (data) => {
            setMessages(prev => [...prev, {
                id: Date.now().toString(),
                content: `⚠ ${data.message}`,
                sender: 'system',
                mine: false,
                timestamp: new Date().toISOString(),
                isSystem: true
            }])
        }

        const onMessageDestroyed = (data) => {
            setMessages(prev => prev.map(m =>
                m.id === data.message_id ? { ...m, expired: true, content: '🗑 Burned on Read', isBurned: true } : m
            ))
        }

        socket.on('verified', onVerified)
        socket.on('verification_failed', onVerificationFailed)
        socket.on('receive_message', onReceiveMessage)
        socket.on('message_sent', onMessageSent)
        socket.on('message_destroyed', onMessageDestroyed)
        socket.on('error', onError)

        // Emit verify_device on every (re)connect — works on mobile where the
        // connection may establish after ChatInterface has already mounted.
        socket.on('connect', emitVerify)
        // Also emit immediately if already connected (desktop fast-path).
        if (socket.connected) emitVerify()

        return () => {
            socket.off('verified', onVerified)
            socket.off('verification_failed', onVerificationFailed)
            socket.off('receive_message', onReceiveMessage)
            socket.off('message_sent', onMessageSent)
            socket.off('error', onError)
            socket.off('connect', emitVerify)
        }
    }, [socket, sessionKey, deviceId])

    // ── Smart Auto-scroll ─────────────────────────────────────────────────────────
    // Only snap to bottom when a NEW message arrives (prevMsgCount < messages.length).
    // Timer ticks that update remainingMs don't increase count, so they don't scroll.
    // Also respects user scroll position — won't snap if they're reading old messages.
    useEffect(() => {
        const area = messagesAreaRef.current
        const newCount = messages.length
        if (newCount > prevMsgCountRef.current) {
            prevMsgCountRef.current = newCount
            if (area) {
                const distFromBottom = area.scrollHeight - area.scrollTop - area.clientHeight
                if (distFromBottom < 150) {
                    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
                }
            } else {
                bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
            }
        }
    }, [messages])

    // ── Expiry countdowns ─────────────────────────────────────────────────────────
    useEffect(() => {
        const timer = setInterval(() => {
            const now = Date.now()
            setMessages(prev => prev.map(m => {
                if (m.expiresAt && !m.expired) {
                    // Robust ISO parsing
                    const targetDate = new Date(m.expiresAt)
                    const remaining = targetDate.getTime() - now
                    
                    if (isNaN(remaining)) return m
                    if (remaining <= 0) return { ...m, expired: true, content: '[key destroyed — permanently unrecoverable]', remainingMs: 0 }
                    return { ...m, remainingMs: remaining }
                }
                return m
            }))
        }, 1000)
        return () => clearInterval(timer)
    }, [])

    // ── Send message ──────────────────────────────────────────────────────────────
    const handleSend = useCallback(async () => {
        if (!input.trim() || sending) return
        setSending(true)

        const plaintext = input.trim()
        setInput('')

        // Optimistic add
        const tempId = 'pending'
        setMessages(prev => [...prev, {
            id: tempId,
            content: plaintext,
            sender: deviceId,
            mine: true,
            timestamp: new Date().toISOString(),
            expiresAt: null,
            proofHash: null,
            expired: false
        }])

        try {
            if (!ratchetRef.current) throw new Error('Ratchet not initialised yet')
            const { payload, newState } = await ratchetEncrypt(plaintext, ratchetRef.current)
            ratchetRef.current = newState   // advance send chain — old key discarded

            socket.emit('send_message', {
                recipient_id: pairedWith,
                encrypted_data: payload,    // { ciphertext, iv, step }
                nonce: generateNonce(),
                signature: 'demo_sig',
                expiry_minutes: expiryMinutes,
                burn_on_read: burnOnRead
            })
        } catch (e) {
            setMessages(prev => prev.map(m =>
                m.id === tempId ? { ...m, content: `[send failed: ${e.message}]`, isError: true } : m
            ))
        } finally {
            setSending(false)
        }
    }, [input, sending, deviceId, pairedWith, sessionKey, expiryMinutes, socket])

    const handleKeyDown = (e) => {
        if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────────
    const formatTime = (iso) => {
        if (!iso) return ''
        return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }

    const formatRemaining = (ms) => {
        if (!ms || isNaN(ms) || ms <= 0) return null
        const s = Math.floor(ms / 1000)
        if (s < 60) return `${s}s`
        const m = Math.floor(s / 60)
        if (m < 60) return `${m}m ${s % 60}s`
        return `${Math.floor(m / 60)}h ${m % 60}m`
    }

    // ── Render ────────────────────────────────────────────────────────────────────
    return (
        <div className="chat-layout">
            {/* Safety number bar */}
            <SafetyNumber safetyNumber={safetyNumber} verified={verified} />

            {/* Chat header */}
            <div className="chat-header">
                <div className="peer-info">
                    <div className="avatar">{pairedWith ? pairedWith.slice(0, 2).toUpperCase() : '??'}</div>
                    <div>
                        <div className="peer-name">Paired Device</div>
                        <div className="peer-id">{pairedWith?.slice(0, 16)}…</div>
                    </div>
                </div>
                <div className="flex items-center gap-sm">
                    {verified
                        ? <span className="badge badge-success"><Lock size={10} /> E2E Encrypted</span>
                        : <span className="badge badge-warning"><AlertTriangle size={10} /> Linking…</span>
                    }
                </div>
            </div>

            {/* Messages */}
            <div className="messages-area" ref={messagesAreaRef}>
                {messages.length === 0 && (
                    <div className="empty-state">
                        <Lock size={40} />
                        <p>No messages yet</p>
                        <p style={{ fontSize: '0.78rem' }}>Messages are end-to-end encrypted and content is never stored</p>
                    </div>
                )}

                {messages.map(msg => {
                    if (msg.isSystem) return (
                        <div key={msg.id} className="system-msg">{msg.content}</div>
                    )

                    return (
                        <div key={msg.id} className={`msg-row${msg.mine ? ' sent' : ''}`}>
                            {!msg.mine && (
                                <div className="avatar" style={{ width: 28, height: 28, fontSize: '0.7rem' }}>
                                    {msg.sender?.slice(0, 2).toUpperCase() ?? '??'}
                                </div>
                            )}
                            <div>
                                <div className={`msg-bubble${msg.mine ? ' sent' : ' received'}${msg.expired ? ' expired' : ''}`}
                                    style={msg.expired ? { opacity: 0.5, fontStyle: 'italic' } : {}}>
                                    {msg.content}
                                </div>
                                <div className="msg-meta">
                                    <span className="msg-time">{formatTime(msg.timestamp)}</span>
                                    {msg.proofHash && (
                                        <span className="msg-proof" title={msg.proofHash}>
                                            🔒 {msg.proofHash.slice(0, 8)}…
                                        </span>
                                    )}
                                    {msg.expired
                                        ? <span className="msg-expired-label">🗑 Key destroyed</span>
                                        : msg.remainingMs > 0 && (
                                            <span className="msg-expiry" title="Time until key destruction">
                                                <Clock size={10} style={{ display: 'inline', marginRight: 2 }} />
                                                {formatRemaining(msg.remainingMs)}
                                            </span>
                                        )
                                    }
                                    <span className="msg-encrypted-badge">
                                        <Lock size={9} /> AES-256-GCM
                                    </span>
                                </div>
                            </div>
                        </div>
                    )
                })}
                <div ref={bottomRef} />
            </div>

            {/* Composer */}
            <div className="chat-composer">
                <select className="expiry-select" value={expiryMinutes}
                    onChange={e => setExpiryMinutes(Number(e.target.value))}>
                    <option value={1}>Expires: 1min</option>
                    <option value={5}>Expires: 5min</option>
                    <option value={30}>Expires: 30min</option>
                    <option value={60}>Expires: 1hr</option>
                    <option value={720}>Expires: 12hr</option>
                    <option value={1440}>Expires: 24hr</option>
                </select>
                <div className="flex items-center gap-xs ml-sm mr-sm" style={{ minWidth: 'max-content' }}>
                    <input type="checkbox" id="burn-toggle" checked={burnOnRead} 
                        onChange={e => setBurnOnRead(e.target.checked)} />
                    <label htmlFor="burn-toggle" style={{ fontSize: '0.75rem', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '2px' }}>
                        <Zap size={10} style={{ color: burnOnRead ? 'var(--accent-cyan)' : 'inherit' }} /> Burn
                    </label>
                </div>
                <textarea
                    className="input composer-input"
                    placeholder="Type a message… (Enter to send, Shift+Enter for newline)"
                    value={input}
                    onChange={e => setInput(e.target.value)}
                    onKeyDown={handleKeyDown}
                    rows={1}
                />
                <button className="btn btn-primary" onClick={handleSend} disabled={sending || !input.trim()}>
                    {sending ? <span className="spinner" /> : <Send size={16} />}
                </button>
            </div>
        </div>
    )
}
