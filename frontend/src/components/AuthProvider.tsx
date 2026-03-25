"use client";

import { createContext, useContext, useEffect, useState, useCallback } from "react";
import type { AuthUser } from "@/lib/auth-api";
import {
  fetchCurrentUser,
  login as apiLogin,
  signup as apiSignup,
  googleLogin as apiGoogleLogin,
  logout as apiLogout,
  setAccessToken,
} from "@/lib/auth-api";

interface AuthContextValue {
  user: AuthUser | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, password: string, displayName?: string) => Promise<void>;
  googleLogin: (credential: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  loading: true,
  login: async () => {},
  signup: async () => {},
  googleLogin: async () => {},
  logout: async () => {},
});

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Try to restore session on mount via refresh token cookie
  useEffect(() => {
    fetchCurrentUser()
      .then((u) => setUser(u))
      .finally(() => setLoading(false));
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = await apiLogin(email, password);
    setUser(res.user);
  }, []);

  const signup = useCallback(async (email: string, password: string, displayName?: string) => {
    const res = await apiSignup(email, password, displayName);
    setUser(res.user);
  }, []);

  const googleLogin = useCallback(async (credential: string) => {
    const res = await apiGoogleLogin(credential);
    setUser(res.user);
  }, []);

  const logout = useCallback(async () => {
    await apiLogout();
    setAccessToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, login, signup, googleLogin, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
