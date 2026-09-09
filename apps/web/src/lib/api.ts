let accessToken = "";
let refreshing: Promise<boolean> | null = null;
export async function refreshSession(): Promise<boolean> {
  if (!refreshing)
    refreshing = fetch("/api/v1/auth/refresh", { method: "POST" })
      .then(async (response) => {
        if (!response.ok) {
          accessToken = "";
          return false;
        }
        accessToken = (await response.json()).access_token;
        return true;
      })
      .catch(() => false)
      .finally(() => {
        refreshing = null;
      });
  return refreshing;
}
export async function api<T>(
  path: string,
  options: RequestInit = {},
  retry = true,
): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(accessToken ? { Authorization: `Bearer ${accessToken}` } : {}),
      ...options.headers,
    },
  });
  if (response.status === 401 && retry && !path.startsWith("/auth/")) {
    if (await refreshSession()) return api(path, options, false);
    window.dispatchEvent(new Event("sentinel:session-expired"));
    throw new Error("Session expired. Please sign in again.");
  }
  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : `Request failed (${response.status})`,
    );
  }
  return response.status === 204 ? (undefined as T) : response.json();
}
export function setToken(value: string) {
  accessToken = value;
}
export type Row = { id: string; [key: string]: unknown };
export type Page = {
  items: Row[];
  total: number;
  page: number;
  page_size: number;
};
export type Member = { id: string; name: string; email: string; role: string };
export type Me = Member & { organization: { id: string; name: string } };
export type Alert = Row & {
  title: string;
  severity: string;
  status: string;
  hostname: string;
  risk_score: number;
  last_seen: string;
  source: string;
  description: string;
  technique: string;
  tactic: string;
  assignee: string | null;
  false_positive_reason: string;
  recommended_response: string;
  evidence: Row[];
  notes: Row[];
  history: Row[];
};
export type Dashboard = {
  active_alerts: number;
  critical_alerts: number;
  monitored_assets: number;
  events: number;
  mtta_minutes: number | null;
  mttr_minutes: number | null;
  by_severity: Record<string, number>;
  by_source: Record<string, number>;
  by_tactic: Record<string, number>;
  trend: { date: string; alerts: number }[];
  recent_alerts: Alert[];
  risky_assets: { hostname: string; risk: number; alerts: number }[];
};
