import { useState, type ReactNode } from "react";
import { NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  BookOpenText, Bug, ClipboardCheck, FileText, FolderGit2, Gauge, History, LogOut, Menu, Settings,
  ShieldAlert, UploadCloud, Users, Wrench, X,
} from "lucide-react";
import { supabase } from "@/lib/supabase";
import { useAuth } from "@/lib/auth";
import { cx } from "./ui";

interface Item { to: string; label: string; icon: ReactNode; planned?: boolean }
const groups: { label: string; items: Item[] }[] = [
  { label: "Overview", items: [{ to: "/", label: "Dashboard", icon: <Gauge /> }] },
  {
    label: "Scanning", items: [
      { to: "/projects", label: "Projects", icon: <FolderGit2 /> },
      { to: "/scans/new", label: "New scan", icon: <UploadCloud /> },
      { to: "/scans", label: "Scan history", icon: <History /> },
    ],
  },
  {
    label: "Findings", items: [
      { to: "/findings", label: "Vulnerabilities", icon: <Bug /> },
      { to: "/threats", label: "Threat analysis", icon: <ShieldAlert />, planned: true },
      { to: "/remediation", label: "Remediation", icon: <Wrench />, planned: true },
      { to: "/verification", label: "Fix verification", icon: <ClipboardCheck />, planned: true },
      { to: "/reports", label: "Reports", icon: <FileText />, planned: true },
    ],
  },
  {
    label: "Knowledge", items: [{ to: "/knowledge", label: "Knowledge base", icon: <BookOpenText /> }],
  },
  {
    label: "Workspace", items: [
      { to: "/team", label: "Team", icon: <Users />, planned: true },
      { to: "/settings", label: "Settings", icon: <Settings /> },
    ],
  },
];

export function Logo() {
  return (
    <div className="flex items-center gap-2.5">
      <img src="/favicon.svg" alt="" className="h-7 w-7" />
      <span className="text-[15px] font-semibold tracking-tight">SecureMatrix</span>
    </div>
  );
}

export function Layout() {
  const { profile, session } = useAuth();
  const navigate = useNavigate();
  const [open, setOpen] = useState(false);

  const nav = (
    <nav className="flex-1 space-y-5 overflow-y-auto px-3 py-4" aria-label="Main">
      {groups.map((g) => (
        <div key={g.label}>
          <div className="px-2 pb-1.5 text-xs text-fg-faint">{g.label}</div>
          <ul className="space-y-0.5">
            {g.items.map((it) => (
              <li key={it.to}>
                <NavLink to={it.to} end={it.to === "/" || it.to === "/scans"} onClick={() => setOpen(false)}
                  className={({ isActive }) => cx(
                    "flex items-center gap-2.5 rounded-md px-2 py-1.5 text-[13px] [&_svg]:h-4 [&_svg]:w-4",
                    isActive ? "bg-panel-3 text-fg [&_svg]:text-accent" : "text-fg-muted hover:bg-panel-2 hover:text-fg",
                  )}>
                  {it.icon}
                  <span className="flex-1">{it.label}</span>
                  {it.planned && <span className="rounded border border-line px-1 text-[10px] text-fg-faint">Planned</span>}
                </NavLink>
              </li>
            ))}
          </ul>
        </div>
      ))}
    </nav>
  );

  const user = (
    <div className="border-t border-line px-4 py-3">
      <div className="truncate text-[13px]">{profile?.full_name || session?.user.email}</div>
      <div className="flex items-center justify-between">
        <span className="text-xs capitalize text-fg-faint">{profile?.role ?? ""}</span>
        <button className="flex items-center gap-1 text-xs text-fg-muted hover:text-fg"
          onClick={async () => { await supabase.auth.signOut(); navigate("/login"); }}>
          <LogOut className="h-3.5 w-3.5" /> Sign out
        </button>
      </div>
    </div>
  );

  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-line bg-ink-2 lg:flex">
        <div className="px-5 py-4"><Logo /></div>
        {nav}
        {user}
      </aside>

      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-64 flex-col border-r border-line bg-ink-2">
            <div className="flex items-center justify-between px-5 py-4">
              <Logo />
              <button onClick={() => setOpen(false)} aria-label="Close menu"><X className="h-5 w-5" /></button>
            </div>
            {nav}
            {user}
          </aside>
        </div>
      )}

      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-3 border-b border-line px-4 py-3 lg:hidden">
          <button onClick={() => setOpen(true)} aria-label="Open menu"><Menu className="h-5 w-5" /></button>
          <Logo />
        </div>
        <main className="mx-auto max-w-[1320px] px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
