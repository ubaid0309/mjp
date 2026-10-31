import { useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router-dom";
import { supabase } from "@/lib/supabase";
import { useAuth } from "@/lib/auth";
import { Logo } from "@/components/Layout";
import { Button, ErrorNote, Field, Input, Notice } from "@/components/ui";

export default function AuthPage({ mode }: { mode: "login" | "register" }) {
  const { session } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [checkEmail, setCheckEmail] = useState(false);

  if (session) return <Navigate to={(location.state as { from?: string } | null)?.from ?? "/"} replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (mode === "login") {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw new Error(error.message);
        navigate("/");
      } else {
        if (password.length < 8) throw new Error("Use at least 8 characters for the password.");
        const { data, error } = await supabase.auth.signUp({ email, password, options: { data: { full_name: name } } });
        if (error) throw new Error(error.message);
        if (!data.session) setCheckEmail(true);
        else navigate("/");
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="grid min-h-screen lg:grid-cols-[1fr_520px]">
      <div className="hidden flex-col justify-between border-r border-line bg-ink-2 p-10 lg:flex">
        <Logo />
        <div className="max-w-md">
          <p className="text-2xl font-semibold leading-snug">
            Find what is wrong in your code, understand why it matters, and prove when it is fixed.
          </p>
          <ul className="mt-6 space-y-2 text-fg-muted">
            <li>Static analysis with Semgrep on every upload</li>
            <li>A security knowledge base of 100+ CWE weakness classes, searched with vector retrieval</li>
            <li>Findings tracked from detection to verified fix</li>
          </ul>
        </div>
        <p className="text-xs text-fg-faint">Vulnerability and threat management platform</p>
      </div>

      <div className="flex items-center justify-center px-4 py-10">
        <form onSubmit={submit} className="w-full max-w-sm space-y-5">
          <div className="lg:hidden"><Logo /></div>
          <div>
            <h1 className="text-xl font-semibold">{mode === "login" ? "Sign in" : "Create your account"}</h1>
            <p className="mt-1 text-fg-muted">
              {mode === "login" ? "Use the email and password you registered with." : "The first account on a new deployment becomes the administrator."}
            </p>
          </div>
          {checkEmail ? (
            <Notice>Check {email} for a confirmation link, then sign in.</Notice>
          ) : (
            <>
              {mode === "register" && (
                <Field label="Full name" htmlFor="name">
                  <Input id="name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" maxLength={120} />
                </Field>
              )}
              <Field label="Email" htmlFor="email">
                <Input id="email" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" />
              </Field>
              <Field label="Password" htmlFor="password" hint={mode === "register" ? "At least 8 characters." : undefined}>
                <Input id="password" type="password" required value={password} onChange={(e) => setPassword(e.target.value)}
                  autoComplete={mode === "login" ? "current-password" : "new-password"} />
              </Field>
              <ErrorNote error={error} title={mode === "login" ? "Could not sign in" : "Could not create the account"} />
              <Button type="submit" variant="primary" className="h-9 w-full" loading={busy}>
                {mode === "login" ? "Sign in" : "Create account"}
              </Button>
            </>
          )}
          <p className="text-center text-[13px] text-fg-muted">
            {mode === "login" ? <>No account yet? <Link to="/register">Create one</Link></> : <>Already registered? <Link to="/login">Sign in</Link></>}
          </p>
        </form>
      </div>
    </div>
  );
}
