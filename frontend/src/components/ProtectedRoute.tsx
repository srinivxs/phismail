"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "./AuthProvider";

/**
 * Wrap page content with this component to require authentication.
 * Redirects to /login if not authenticated.
 *
 * Usage:
 *   <ProtectedRoute>
 *     <YourPageContent />
 *   </ProtectedRoute>
 */
export default function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const router = useRouter();

  useEffect(() => {
    if (!loading && !user) {
      router.replace("/login");
    }
  }, [user, loading, router]);

  if (loading) {
    return (
      <div className="flex items-center justify-center pt-20">
        <div className="h-40 w-full max-w-md loading-shimmer rounded-xl" />
      </div>
    );
  }

  if (!user) return null;

  return <>{children}</>;
}
