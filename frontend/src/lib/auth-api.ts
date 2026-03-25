/** PhisMail — Auth API Client */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || '';

export interface AuthUser {
  id: string;
  email: string;
  display_name: string | null;
  auth_provider: 'local' | 'google';
  avatar_url: string | null;
  created_at: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: AuthUser;
}

let accessToken: string | null = null;

export function getAccessToken(): string | null {
  return accessToken;
}

export function setAccessToken(token: string | null) {
  accessToken = token;
}

/** Add auth header to any fetch call */
export function authHeaders(): Record<string, string> {
  if (!accessToken) return {};
  return { Authorization: `Bearer ${accessToken}` };
}

export async function signup(email: string, password: string, displayName?: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/v1/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email, password, display_name: displayName }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Signup failed' }));
    throw new Error(err.detail || `Signup failed: ${res.status}`);
  }
  const data: AuthResponse = await res.json();
  accessToken = data.access_token;
  return data;
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ email, password }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Login failed' }));
    throw new Error(err.detail || `Login failed: ${res.status}`);
  }
  const data: AuthResponse = await res.json();
  accessToken = data.access_token;
  return data;
}

export async function googleLogin(credential: string): Promise<AuthResponse> {
  const res = await fetch(`${API_BASE}/api/v1/auth/google`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ credential }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Google login failed' }));
    throw new Error(err.detail || `Google login failed: ${res.status}`);
  }
  const data: AuthResponse = await res.json();
  accessToken = data.access_token;
  return data;
}

export async function refreshAccessToken(): Promise<string | null> {
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
      method: 'POST',
      credentials: 'include',
    });
    if (!res.ok) {
      accessToken = null;
      return null;
    }
    const data = await res.json();
    accessToken = data.access_token;
    return data.access_token;
  } catch {
    accessToken = null;
    return null;
  }
}

export async function fetchCurrentUser(): Promise<AuthUser | null> {
  if (!accessToken) {
    const refreshed = await refreshAccessToken();
    if (!refreshed) return null;
  }
  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/me`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      credentials: 'include',
    });
    if (!res.ok) {
      if (res.status === 401) {
        const refreshed = await refreshAccessToken();
        if (!refreshed) return null;
        const retry = await fetch(`${API_BASE}/api/v1/auth/me`, {
          headers: { Authorization: `Bearer ${accessToken}` },
          credentials: 'include',
        });
        if (!retry.ok) return null;
        return retry.json();
      }
      return null;
    }
    return res.json();
  } catch {
    return null;
  }
}

export async function logout(): Promise<void> {
  await fetch(`${API_BASE}/api/v1/auth/logout`, {
    method: 'POST',
    credentials: 'include',
  }).catch(() => {});
  accessToken = null;
}
