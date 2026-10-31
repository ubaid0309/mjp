import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./index.css";
import { AuthProvider, useAuth } from "@/lib/auth";
import { supabaseConfigured } from "@/lib/supabase";
import { Layout } from "@/components/Layout";
import { Loading } from "@/components/ui";
import AuthPage from "@/pages/AuthPage";
import DashboardPage from "@/pages/DashboardPage";
import ProjectsPage from "@/pages/ProjectsPage";
import ProjectDetailPage from "@/pages/ProjectDetailPage";
import NewScanPage from "@/pages/NewScanPage";
import ScanPage from "@/pages/ScanPage";
import ScanHistoryPage from "@/pages/ScanHistoryPage";
import FindingsPage from "@/pages/FindingsPage";
import FindingDetailPage from "@/pages/FindingDetailPage";
import KnowledgePage from "@/pages/KnowledgePage";
import KnowledgeDocPage from "@/pages/KnowledgeDocPage";
import SettingsPage from "@/pages/SettingsPage";
import PlannedPage from "@/pages/PlannedPage";
import SetupPage from "@/pages/SetupPage";

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 15_000, retry: 1, refetchOnWindowFocus: false } },
});

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { session, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Loading label="Checking session" />;
  if (!session) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

function App() {
  if (!supabaseConfigured) return <SetupPage />;
  return (
    <Routes>
      <Route path="/login" element={<AuthPage mode="login" />} />
      <Route path="/register" element={<AuthPage mode="register" />} />
      <Route element={<RequireAuth><Layout /></RequireAuth>}>
        <Route index element={<DashboardPage />} />
        <Route path="projects" element={<ProjectsPage />} />
        <Route path="projects/:id" element={<ProjectDetailPage />} />
        <Route path="scans" element={<ScanHistoryPage />} />
        <Route path="scans/new" element={<NewScanPage />} />
        <Route path="scans/:id" element={<ScanPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/:id" element={<FindingDetailPage />} />
        <Route path="knowledge" element={<KnowledgePage />} />
        <Route path="knowledge/new" element={<KnowledgeDocPage />} />
        <Route path="knowledge/:id" element={<KnowledgeDocPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="threats" element={<PlannedPage module="threats" />} />
        <Route path="remediation" element={<PlannedPage module="remediation" />} />
        <Route path="verification" element={<PlannedPage module="verification" />} />
        <Route path="reports" element={<PlannedPage module="reports" />} />
        <Route path="team" element={<PlannedPage module="team" />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </AuthProvider>
    </QueryClientProvider>
  </React.StrictMode>,
);
