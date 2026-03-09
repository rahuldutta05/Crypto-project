import { api } from './api'
import { io } from 'socket.io-client'

let socket = null

export function getSocket() {
    if (!socket) {
        const backendUrl = api('/')
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
