/**
 * socketManager.js
 * Singleton wrapper around socket.io-client.
 */
import { io } from 'socket.io-client'

let socket = null

export function getSocket() {
    if (!socket) {
        socket = io('/', {          // proxied to localhost:5000 via vite
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
