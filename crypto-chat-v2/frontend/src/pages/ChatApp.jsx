import { useState, useEffect } from 'react'
import { connectSocket } from '../utils/socketManager'
import DevicePairing from '../components/DevicePairing'
import ChatInterface from '../components/ChatInterface'

export default function ChatApp() {
    const [deviceInfo, setDeviceInfo] = useState(null)
    const [wsReady, setWsReady] = useState(false)

    // Connect WebSocket when component mounts
    useEffect(() => {
        const socket = connectSocket()
        const onConnect = () => setWsReady(true)
        const onDisconnect = () => setWsReady(false)
        socket.on('connect', onConnect)
        socket.on('disconnect', onDisconnect)
        if (socket.connected) setWsReady(true)
        return () => { socket.off('connect', onConnect); socket.off('disconnect', onDisconnect) }
    }, [])

    const handlePaired = (info) => {
        setDeviceInfo(info)
    }

    if (!deviceInfo) {
        return <DevicePairing onPaired={handlePaired} />
    }

    return <ChatInterface deviceInfo={deviceInfo} />
}
