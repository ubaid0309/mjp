import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { Session } from "@supabase/supabase-js";
import { useQuery } from "@tanstack/react-query";
import { supabase, unwrap } from "./supabase";
import type { Profile } from "./types";

interface AuthState {
  session: Session | null;
  loading: boolean;
  profile: Profile | null;
  isAdmin: boolean;
}

const AuthContext = createContext<AuthState>({ session: null, loading: true, profile: null, isAdmin: false });

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setLoading(false);
    });
    const { data } = supabase.auth.onAuthStateChange((_e, s) => setSession(s));
    return () => data.subscription.unsubscribe();
  }, []);

  const userId = session?.user.id;
  const profile = useQuery({
    queryKey: ["profile", userId],
    enabled: Boolean(userId),
    queryFn: async () => unwrap(await supabase.from("profiles").select("*").eq("id", userId!).single()) as Profile,
  });

  return (
    <AuthContext.Provider value={{ session, loading, profile: profile.data ?? null, isAdmin: profile.data?.role === "admin" }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
