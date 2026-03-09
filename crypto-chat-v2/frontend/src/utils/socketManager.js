/**
 * socketManager.js
 * Singleton wrapper around socket.io-client.
 */
import { io } from 'socket.io-client'

let socket = null

export function getSocket() {
    if (!socket) {
        // In dev: Vite proxies '/' → localhost:5000, so no URL needed.
        // In production: point directly at the Render backend.
        const backendUrl = import.meta.env.VITE_BACKEND_URL || '/'
        socket = io(backendUrl, {
            transports: ['websocket', 'polling'],
            autoConnect: false
        })
    }
    return socket
}

export function connectSocket() {
    const s = getSocket()
    if (!s.connected) s.connect()
    return s
}

export function disconnectSocket() {
    if (socket && socket.connected) socket.disconnect()
}
