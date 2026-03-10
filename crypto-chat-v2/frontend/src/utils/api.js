/**
 * api.js — Centralized API URL handling for cross-domain deployments.
 */

const API_BASE = (
    import.meta.env.VITE_API_URL ||
    import.meta.env.VITE_BACKEND_URL ||
    ''
).replace(/\/$/, '')

/**
 * Builds an absolute URL for an API endpoint.
 * @param {string} path - The relative path (e.g., '/api/auth/verify')
 * @returns {string} The full URL
 */
export const api = (path) => {
    if (!path.startsWith('/')) path = `/${path}`
    return `${API_BASE}${path}`
}

export const getApiBase = () => API_BASE
