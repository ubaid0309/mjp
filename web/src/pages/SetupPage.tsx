import { Logo } from "@/components/Layout";

export default function SetupPage() {
  return (
    <div className="mx-auto max-w-2xl px-4 py-16">
      <Logo />
      <h1 className="mt-8 text-xl font-semibold">Supabase is not configured</h1>
      <p className="mt-2 text-fg-muted">
        The web app needs your Supabase project URL and anon (publishable) key. Nothing will be shown until it can
        reach a real database.
      </p>
      <ol className="mt-6 list-decimal space-y-2 pl-5 text-fg-muted">
        <li>Copy <code className="text-fg">web/.env.example</code> to <code className="text-fg">web/.env.local</code>.</li>
        <li>Fill in <code className="text-fg">VITE_SUPABASE_URL</code> and <code className="text-fg">VITE_SUPABASE_ANON_KEY</code> from Supabase project settings, API.</li>
        <li>Restart <code className="text-fg">npm run dev</code>.</li>
      </ol>
      <p className="mt-6 text-fg-muted">The README has the full setup, including the database migrations and the scan worker.</p>
    </div>
  );
}
