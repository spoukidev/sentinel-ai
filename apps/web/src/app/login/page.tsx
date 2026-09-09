"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import {
  ShieldCheck,
  ArrowRight,
  Activity,
  Fingerprint,
  Layers3,
} from "lucide-react";
import { api, setToken } from "@/lib/api";
import { Button } from "@/components/ui/button";
const schema = z.object({
  email: z.email(),
  password: z.string().min(1).max(128),
});
export default function Login() {
  const [error, setError] = useState("");
  const [registerMode, setRegisterMode] = useState(false);
  const router = useRouter();
  const form = useForm<z.infer<typeof schema>>({
    resolver: zodResolver(schema),
  });
  async function submit(data: z.infer<typeof schema>) {
    setError("");
    try {
      const result = await api<{ access_token: string }>("/auth/login", {
        method: "POST",
        body: JSON.stringify(data),
      });
      setToken(result.access_token);
      router.push("/");
    } catch (err) {
      setError((err as Error).message);
    }
  }
  return (
    <main className="login-page">
      <section className="login-story">
        <div className="brand">
          <ShieldCheck />
          <strong>
            Sentinel<span>AI</span>
          </strong>
          <small>SECURITY OPERATIONS</small>
        </div>
        <div>
          <div className="eyebrow">CLARITY IN EVERY SIGNAL</div>
          <h1>
            Your team.
            <br />A clearer picture.
            <br />
            <span>A stronger defense.</span>
          </h1>
          <p>
            Open-source intelligent SOC for small security teams. Turn security
            events into evidence you can investigate.
          </p>
          <div className="login-features">
            <span>
              <Activity /> Real event detection
            </span>
            <span>
              <Fingerprint /> Evidence-led investigations
            </span>
            <span>
              <Layers3 /> Tenant-isolated workspaces
            </span>
          </div>
        </div>
        <footer>
          Next.js · FastAPI · PostgreSQL <span>Built for defenders.</span>
        </footer>
      </section>
      <section className="login-form">
        <div className="eyebrow">WELCOME TO SENTINELAI</div>
        <h2>
          {registerMode ? "Create your workspace" : "Sign in to your workspace"}
        </h2>
        <p className="muted">Your security operations, in one place.</p>
        {registerMode ? (
          <Registration onDone={() => router.push("/")} />
        ) : (
          <form onSubmit={form.handleSubmit(submit)}>
            <label>
              Email address
              <input
                type="email"
                autoComplete="username"
                placeholder="analyst@sentinel.example"
                {...form.register("email")}
              />
            </label>
            <label>
              Password
              <input
                type="password"
                autoComplete="current-password"
                {...form.register("password")}
              />
            </label>
            {Object.keys(form.formState.errors).length > 0 && (
              <p role="alert">Enter a valid email and password.</p>
            )}
            {error && (
              <p role="alert" className="error">
                {error}
              </p>
            )}
            <Button disabled={form.formState.isSubmitting} type="submit">
              {form.formState.isSubmitting ? "Signing in…" : "Sign in"}
              <ArrowRight size={17} />
            </Button>
          </form>
        )}
        <button
          className="text-button"
          onClick={() => setRegisterMode(!registerMode)}
        >
          {registerMode
            ? "Already have an account? Sign in"
            : "Create a new workspace"}
        </button>
        <aside className="demo-card">
          <span className="live-dot" /> SYNTHETIC DEMO ENVIRONMENT
          <p>
            Use a seeded account and the development password you configured
            during setup. No real organizations, credentials, or threats are
            included.
          </p>
          <code>analyst@sentinel.example</code>
        </aside>
      </section>
    </main>
  );
}
function Registration({ onDone }: { onDone: () => void }) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        setBusy(true);
        setError("");
        const data = Object.fromEntries(new FormData(e.currentTarget));
        try {
          const result = await api<{ access_token: string }>("/auth/register", {
            method: "POST",
            body: JSON.stringify(data),
          });
          setToken(result.access_token);
          onDone();
        } catch (err) {
          setError((err as Error).message);
        } finally {
          setBusy(false);
        }
      }}
    >
      <label>
        Name
        <input name="name" required minLength={2} maxLength={120} />
      </label>
      <label>
        Organization
        <input name="organization" required minLength={2} maxLength={120} />
      </label>
      <label>
        Email
        <input name="email" type="email" required autoComplete="username" />
      </label>
      <label>
        Password · at least 12 characters
        <input
          name="password"
          type="password"
          required
          minLength={12}
          maxLength={128}
          autoComplete="new-password"
        />
      </label>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <Button disabled={busy}>{busy ? "Creating…" : "Create workspace"}</Button>
    </form>
  );
}
