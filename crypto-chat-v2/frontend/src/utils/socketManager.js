import { getApiBase } from './api'
import { io } from 'socket.io-client'

let socket = null

export function getSocket() {
    if (!socket) {
        // Use the base backend URL (no trailing slash / path).
        // Socket.io appends /socket.io/ itself — passing api('/') can
        // confuse the path when running behind Vercel's rewrite proxy.
        const backendUrl = getApiBase() || window.location.origin
        socket = io(backendUrl, {
            transports: ['websocket', 'polling'],
            autoConnect: false,
            path: '/socket.io/'
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
