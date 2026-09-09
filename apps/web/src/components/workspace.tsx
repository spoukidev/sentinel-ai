"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  Bell,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Database,
  FileClock,
  LayoutDashboard,
  ListFilter,
  LogOut,
  Menu,
  Plus,
  Radar,
  Search,
  Server,
  Settings2,
  Shield,
  ShieldCheck,
  SlidersHorizontal,
  Target,
  X,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  api,
  type Alert,
  type Dashboard,
  type Me,
  type Member,
  type Page,
  type Row,
  refreshSession,
  setToken,
} from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";

const nav = [
  ["Overview", LayoutDashboard],
  ["Alerts", Bell],
  ["Events", Database],
  ["Assets", Server],
  ["Detection Rules", SlidersHorizontal],
  ["ATT&CK Coverage", Target],
  ["Audit Log", FileClock],
  ["Settings", Settings2],
] as const;
type Tab = (typeof nav)[number][0];
const endpoints: Partial<Record<Tab, string>> = {
  Alerts: "/alerts",
  Events: "/events",
  Assets: "/assets",
  "Detection Rules": "/rules",
  "Audit Log": "/audit-logs",
};
const str = (value: unknown) =>
  value === null || value === undefined ? "—" : String(value);
const date = (value: unknown) =>
  value
    ? new Date(
        String(value).endsWith("Z") ? String(value) : `${value}Z`,
      ).toLocaleString([], {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      })
    : "Not observed";
function Badge({ value }: { value: unknown }) {
  return (
    <span className={`badge ${str(value)}`}>
      {str(value).replaceAll("_", " ")}
    </span>
  );
}

export function Workspace() {
  const router = useRouter();
  const client = useQueryClient();
  const [ready, setReady] = useState(false);
  const [tab, setTab] = useState<Tab>("Overview");
  const [collapsed, setCollapsed] = useState(false);
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState("");
  const [status, setStatus] = useState("");
  const [sort, setSort] = useState("newest");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const [modal, setModal] = useState<"asset" | "ingest" | "csv" | null>(null);
  const [toast, setToast] = useState("");
  useEffect(() => {
    const expired = () => {
      client.clear();
      router.replace("/login");
    };
    window.addEventListener("sentinel:session-expired", expired);
    return () =>
      window.removeEventListener("sentinel:session-expired", expired);
  }, [client, router]);
  useEffect(() => {
    refreshSession().then((ok) => {
      if (ok) setReady(true);
      else router.replace("/login");
    });
  }, [router]);
  useEffect(() => {
    if (toast) {
      const timer = setTimeout(() => setToast(""), 5000);
      return () => clearTimeout(timer);
    }
  }, [toast]);
  const me = useQuery({
    queryKey: ["me"],
    queryFn: () => api<Me>("/auth/me"),
    enabled: ready,
  });
  const dashboard = useQuery({
    queryKey: ["dashboard"],
    queryFn: () => api<Dashboard>("/dashboard"),
    enabled: ready,
  });
  const endpoint = endpoints[tab];
  const listing = useQuery({
    queryKey: ["list", tab, search, filter, status, sort, page],
    queryFn: () =>
      api<Page>(
        `${endpoint}?q=${encodeURIComponent(search)}&severity=${filter}&source=${filter}&status=${status}&sort=${sort}&page_number=${page}`,
      ),
    enabled: ready && !!endpoint,
  });
  function navigate(next: Tab) {
    setTab(next);
    setSearch("");
    setFilter("");
    setStatus("");
    setPage(1);
    setSelected(null);
  }
  async function changed(message: string) {
    setToast(message);
    await client.invalidateQueries();
  }
  if (!ready || me.isPending)
    return (
      <main className="boot">
        <ShieldCheck size={42} />
        <h1>Opening your workspace</h1>
        <div className="skeleton" />
      </main>
    );
  if (me.isError)
    return (
      <main className="boot">
        <h1>Workspace unavailable</h1>
        <p>{me.error.message}</p>
        <Button onClick={() => me.refetch()}>Retry</Button>
      </main>
    );
  const writable = me.data.role !== "viewer";
  return (
    <div className={`workspace ${collapsed ? "collapsed" : ""}`}>
      <aside className="sidebar">
        <Link href="/" className="brand" aria-label="SentinelAI home">
          <ShieldCheck />
          <strong>
            Sentinel<span>AI</span>
          </strong>
        </Link>
        <div className="workspace-label">
          <span className="workspace-icon">S</span>
          <div>
            <b>{me.data.organization.name}</b>
            <small>Security workspace</small>
          </div>
          <span className="live-dot" />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {nav.slice(0, 6).map(([name, Icon]) => (
            <button
              key={name}
              className={tab === name ? "active" : ""}
              onClick={() => navigate(name)}
            >
              <Icon size={18} />
              <span>{name}</span>
              {name === "Alerts" && (
                <b className="nav-count">
                  {dashboard.data?.active_alerts ?? "…"}
                </b>
              )}
            </button>
          ))}
        </nav>
        <div className="nav-label management">MANAGEMENT</div>
        <nav>
          {nav.slice(6).map(([name, Icon]) => (
            <button
              key={name}
              className={tab === name ? "active" : ""}
              onClick={() => navigate(name)}
            >
              <Icon size={18} />
              <span>{name}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="demo-indicator">
            <Shield size={17} />
            <div>
              <b>Safe by design</b>
              <small>Synthetic demonstration data</small>
            </div>
          </div>
          <div className="user">
            <span className="avatar">
              {me.data.name.slice(0, 2).toUpperCase()}
            </span>
            <div>
              <b>{me.data.name}</b>
              <small>{me.data.role}</small>
            </div>
            <button
              aria-label="Sign out"
              onClick={async () => {
                try {
                  await api("/auth/logout", { method: "POST" });
                  setToken("");
                  client.clear();
                  router.replace("/login");
                } catch (e) {
                  setToast((e as Error).message);
                }
              }}
            >
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div>
            <button
              aria-label="Toggle sidebar"
              onClick={() => setCollapsed(!collapsed)}
            >
              <Menu size={19} />
            </button>
            <span className="muted">Workspace</span>
            <ChevronRight size={14} />
            <span>{tab}</span>
          </div>
          <div>
            <span className="environment">
              <span className="live-dot" /> Synthetic data
            </span>
            <a
              href="http://localhost:8000/docs"
              target="_blank"
              rel="noreferrer"
              aria-label="API documentation"
            >
              <CircleHelp size={19} />
            </a>
            <span className="avatar small">
              {me.data.name.slice(0, 2).toUpperCase()}
            </span>
          </div>
        </header>
        <main className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
              <h1>{tab === "Overview" ? "Security overview" : tab}</h1>
              <p className="muted">
                {tab === "Overview"
                  ? "Your environment at a glance. Every signal, in context."
                  : descriptions[tab]}
              </p>
            </div>
            <div className="heading-actions">
              {tab === "Overview" && (
                <Button
                  variant="outline"
                  onClick={() => {
                    const blob = new Blob(
                      [JSON.stringify(dashboard.data, null, 2)],
                      { type: "application/json" },
                    );
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = "sentinelai-overview.json";
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  <ArrowDownToLine size={16} /> Export overview
                </Button>
              )}
              {tab === "Assets" && writable && (
                <>
                  <Button variant="outline" onClick={() => setModal("csv")}>
                    Import CSV
                  </Button>
                  <Button onClick={() => setModal("asset")}>
                    <Plus size={16} /> Add asset
                  </Button>
                </>
              )}
              {tab === "Events" && writable && (
                <Button onClick={() => setModal("ingest")}>
                  <Plus size={16} /> Ingest events
                </Button>
              )}
            </div>
          </div>
          {tab === "Overview" &&
            (dashboard.isError ? (
              <ErrorState
                message={dashboard.error.message}
                retry={() => dashboard.refetch()}
              />
            ) : dashboard.data ? (
              <Overview
                data={dashboard.data}
                investigate={setSelected}
                navigate={navigate}
              />
            ) : (
              <Loading />
            ))}
          {endpoint && (
            <section className="panel">
              <div className="table-toolbar">
                <div className="search">
                  <Search size={17} />
                  <input
                    aria-label="Search records"
                    placeholder={`Search ${tab.toLowerCase()}…`}
                    value={search}
                    onChange={(e) => {
                      setSearch(e.target.value);
                      setPage(1);
                    }}
                  />
                </div>
                <div className="filters">
                  <ListFilter size={16} />
                  {tab === "Alerts" && (
                    <>
                      <select
                        aria-label="Severity filter"
                        value={filter}
                        onChange={(e) => {
                          setFilter(e.target.value);
                          setPage(1);
                        }}
                      >
                        <option value="">All severities</option>
                        {[
                          "critical",
                          "high",
                          "medium",
                          "low",
                          "informational",
                        ].map((x) => (
                          <option key={x}>{x}</option>
                        ))}
                      </select>
                      <select
                        aria-label="Status filter"
                        value={status}
                        onChange={(e) => {
                          setStatus(e.target.value);
                          setPage(1);
                        }}
                      >
                        <option value="">All statuses</option>
                        {[
                          "new",
                          "investigating",
                          "resolved",
                          "false_positive",
                        ].map((x) => (
                          <option key={x}>{x}</option>
                        ))}
                      </select>
                      <select
                        aria-label="Sort alerts"
                        value={sort}
                        onChange={(e) => setSort(e.target.value)}
                      >
                        <option value="newest">Newest first</option>
                        <option value="risk">Highest risk</option>
                      </select>
                    </>
                  )}
                  {tab === "Events" && (
                    <select
                      aria-label="Source filter"
                      value={filter}
                      onChange={(e) => {
                        setFilter(e.target.value);
                        setPage(1);
                      }}
                    >
                      <option value="">All sources</option>
                      {[
                        "windows",
                        "linux",
                        "web",
                        "firewall",
                        "dns",
                        "cloud",
                      ].map((x) => (
                        <option key={x}>{x}</option>
                      ))}
                    </select>
                  )}
                </div>
              </div>
              {listing.isPending ? (
                <Loading />
              ) : listing.isError ? (
                <ErrorState
                  message={listing.error.message}
                  retry={() => listing.refetch()}
                />
              ) : (
                <>
                  <Records
                    tab={tab}
                    rows={listing.data.items.filter(
                      (row) =>
                        !["Detection Rules", "Audit Log"].includes(tab) ||
                        JSON.stringify(row)
                          .toLowerCase()
                          .includes(search.toLowerCase()),
                    )}
                    onSelect={setSelected}
                    me={me.data}
                    changed={changed}
                  />
                  <div className="pagination">
                    <span>
                      {listing.data.total} records · Page {page}
                    </span>
                    <div>
                      <button
                        aria-label="Previous page"
                        disabled={page === 1}
                        onClick={() => setPage(page - 1)}
                      >
                        <ChevronLeft size={18} />
                      </button>
                      <button
                        aria-label="Next page"
                        disabled={
                          page * listing.data.page_size >= listing.data.total
                        }
                        onClick={() => setPage(page + 1)}
                      >
                        <ChevronRight size={18} />
                      </button>
                    </div>
                  </div>
                </>
              )}
            </section>
          )}
          {tab === "ATT&CK Coverage" && <Coverage />}
          {tab === "Settings" && <Settings me={me.data} changed={changed} />}
          <footer className="content-footer">
            <span>
              <ShieldCheck size={14} /> SentinelAI · Functional foundation v0.1
            </span>
            <span>Detection signals require analyst verification</span>
          </footer>
        </main>
      </div>
      {selected && (
        <AlertDrawer
          id={selected}
          close={() => setSelected(null)}
          writable={writable}
          changed={changed}
        />
      )}
      {modal && (
        <DataModal
          kind={modal}
          close={() => setModal(null)}
          changed={changed}
        />
      )}
      {toast && (
        <div className="toast" role="status">
          {toast}
          <button
            aria-label="Dismiss notification"
            onClick={() => setToast("")}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}

const descriptions: Record<Tab, string> = {
  Overview: "",
  Alerts: "Prioritize signals, inspect evidence, and document your decisions.",
  Events: "Normalized telemetry from your connected synthetic sources.",
  Assets: "Know what you protect. Understand where risk is concentrated.",
  "Detection Rules":
    "Transparent, structured logic. Every match has an explanation.",
  "ATT&CK Coverage": "Explore the behaviors your active detection rules cover.",
  "Audit Log": "A traceable record of security and analyst activity.",
  Settings: "Your organization, team, and workspace access.",
};
function Loading() {
  return (
    <div className="loading" role="status" aria-label="Loading records">
      {[1, 2, 3, 4].map((n) => (
        <div key={n} className="skeleton" />
      ))}
    </div>
  );
}
function ErrorState({
  message,
  retry,
}: {
  message: string;
  retry: () => void;
}) {
  return (
    <div className="empty">
      <h3>Unable to load data</h3>
      <p role="alert">{message}</p>
      <Button variant="outline" onClick={retry}>
        Try again
      </Button>
    </div>
  );
}
function Overview({
  data,
  investigate,
  navigate,
}: {
  data: Dashboard;
  investigate: (id: string) => void;
  navigate: (tab: Tab) => void;
}) {
  const stats = [
    [
      "Active alerts",
      data.active_alerts,
      Bell,
      "Awaiting analyst review",
      "cyan",
    ],
    [
      "Critical alerts",
      data.critical_alerts,
      Shield,
      "Highest priority signals",
      "red",
    ],
    [
      "Monitored assets",
      data.monitored_assets,
      Server,
      "Across your workspace",
      "violet",
    ],
    [
      "Events ingested",
      data.events,
      Activity,
      "Normalized and evaluated",
      "green",
    ],
  ] as const;
  return (
    <>
      <div className="status-strip">
        <span>
          <span className="live-dot" /> Workspace connected
        </span>
        <span>
          Rule-based detection <span className="separator">/</span> All time{" "}
          <span className="separator">/</span> Synthetic environment
        </span>
      </div>
      <div className="stats">
        {stats.map(([label, value, Icon, caption, color]) => (
          <section className="panel stat" key={label}>
            <div>
              <span>{label}</span>
              <span className={`stat-icon ${color}`}>
                <Icon size={18} />
              </span>
            </div>
            <strong>{value.toLocaleString()}</strong>
            <small>{caption}</small>
          </section>
        ))}
      </div>
      <div className="chart-grid">
        <section className="panel chart-panel">
          <div className="panel-heading">
            <div>
              <h2>Alert activity</h2>
              <p>Detection volume across your environment</p>
            </div>
            <span className="chart-legend">
              <i /> Alerts
            </span>
          </div>
          <div className="chart">
            {data.trend.length ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart
                  data={data.trend}
                  margin={{ left: -22, right: 18, top: 12, bottom: 0 }}
                >
                  <defs>
                    <linearGradient id="chartFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#42c9d5" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#42c9d5" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid
                    stroke="#23303d"
                    vertical={false}
                    strokeDasharray="3 5"
                  />
                  <XAxis
                    dataKey="date"
                    tickFormatter={(v) => String(v).slice(5)}
                    tick={{ fill: "#8694a7", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "#8694a7", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#17222f",
                      border: "1px solid #334455",
                      borderRadius: 8,
                      color: "#e7edf4",
                    }}
                  />
                  <Area
                    isAnimationActive={false}
                    type="monotone"
                    dataKey="alerts"
                    stroke="#45d0d6"
                    strokeWidth={2.5}
                    fill="url(#chartFill)"
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty">Ingest events to see alert activity.</div>
            )}
          </div>
          <div className="chart-bottom">
            <span>
              Mean time to acknowledge{" "}
              <b>
                {data.mtta_minutes === null
                  ? "No acknowledgments yet"
                  : `${data.mtta_minutes} min`}
              </b>
            </span>
            <span>
              Mean time to resolve{" "}
              <b>
                {data.mttr_minutes === null
                  ? "No resolutions yet"
                  : `${data.mttr_minutes} min`}
              </b>
            </span>
          </div>
        </section>
        <section className="panel severity-panel">
          <div className="panel-heading">
            <div>
              <h2>Alert severity</h2>
              <p>Active signals by priority</p>
            </div>
            <Radar size={20} className="muted" />
          </div>
          <div className="severity-total">
            <strong>{data.active_alerts}</strong>
            <span>active alerts</span>
          </div>
          <div className="severity-stack">
            {Object.entries(data.by_severity).map(([key, value]) => (
              <div
                key={key}
                className={key}
                style={{ flex: value }}
                title={`${key}: ${value}`}
              />
            ))}
          </div>
          {["critical", "high", "medium", "low", "informational"].map((key) => (
            <div className="severity-row" key={key}>
              <span>
                <i className={key} />
                {key}
              </span>
              <b>{data.by_severity[key] || 0}</b>
            </div>
          ))}
        </section>
      </div>
      <div className="lower-grid">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Priority alerts</h2>
              <p>Start with the signals that matter most</p>
            </div>
            <button className="text-button" onClick={() => navigate("Alerts")}>
              View all <ArrowRight size={14} />
            </button>
          </div>
          <AlertTable rows={data.recent_alerts} onSelect={investigate} />
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Highest-risk assets</h2>
              <p>Based on active detections</p>
            </div>
            <Server size={18} className="muted" />
          </div>
          <div className="risk-list">
            {data.risky_assets.length === 0 && (
              <p className="muted">No active asset risk.</p>
            )}
            {data.risky_assets.map((asset) => (
              <div key={asset.hostname}>
                <span className="asset-icon">
                  <Server size={17} />
                </span>
                <span>
                  <b>{asset.hostname}</b>
                  <small>{asset.alerts} active alerts</small>
                </span>
                <strong
                  className={asset.risk >= 90 ? "risk-critical" : "risk-high"}
                >
                  {asset.risk}
                  <small>/100</small>
                </strong>
              </div>
            ))}
          </div>
          <button className="panel-link" onClick={() => navigate("Assets")}>
            Explore asset inventory <ArrowRight size={15} />
          </button>
        </section>
      </div>
      <div className="lower-grid bottom-panels">
        <section className="panel">
          <div className="panel-heading">
            <h2>Observed tactics</h2>
            <span className="muted">ATT&CK</span>
          </div>
          <div className="tactic-chips">
            {Object.entries(data.by_tactic).map(([key, value]) => (
              <button key={key} onClick={() => navigate("ATT&CK Coverage")}>
                <Target size={14} />
                {key}
                <b>{value}</b>
              </button>
            ))}
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>Alert sources</h2>
            <Database size={17} className="muted" />
          </div>
          <div className="sources">
            {Object.entries(data.by_source).map(([key, value]) => (
              <div key={key}>
                <span>{key}</span>
                <meter
                  value={value}
                  max={Math.max(...Object.values(data.by_source))}
                />
                <b>{value}</b>
              </div>
            ))}
          </div>
        </section>
      </div>
    </>
  );
}
function AlertTable({
  rows,
  onSelect,
}: {
  rows: Row[];
  onSelect: (id: string) => void;
}) {
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>Alert / asset</th>
            <th>Severity</th>
            <th>Status</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              <td>
                <button className="row-title" onClick={() => onSelect(row.id)}>
                  {str(row.title)}
                </button>
                <small className="mono">{str(row.hostname)}</small>
              </td>
              <td>
                <Badge value={row.severity} />
              </td>
              <td>
                <Badge value={row.status} />
              </td>
              <td className="muted nowrap">{date(row.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!rows.length && (
        <div className="empty">
          <ShieldCheck size={28} />
          <h3>No matching alerts</h3>
          <p>Try different filters or ingest a sample event.</p>
        </div>
      )}
    </div>
  );
}
function Records({
  tab,
  rows,
  onSelect,
  me,
  changed,
}: {
  tab: Tab;
  rows: Row[];
  onSelect: (id: string) => void;
  me: Me;
  changed: (message: string) => Promise<void>;
}) {
  const [expanded, setExpanded] = useState<string | null>(null);
  if (tab === "Alerts") return <AlertTable rows={rows} onSelect={onSelect} />;
  const columns: Record<string, string[]> = {
    Events: ["event_type", "hostname", "source", "outcome", "timestamp"],
    Assets: [
      "hostname",
      "ip_address",
      "asset_type",
      "criticality",
      "risk_score",
      "last_seen",
    ],
    "Detection Rules": [
      "name",
      "severity",
      "source",
      "technique",
      "threshold",
      "enabled",
    ],
    "Audit Log": ["action", "target_type", "target_id", "created_at"],
  };
  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            {columns[tab].map((col) => (
              <th key={col}>{col.replaceAll("_", " ")}</th>
            ))}
            <th>Details</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.id}>
              {columns[tab].map((col, i) => (
                <td key={col}>
                  {["severity", "criticality", "outcome"].includes(col) ? (
                    <Badge value={row[col]} />
                  ) : col.includes("_at") ||
                    col === "timestamp" ||
                    col === "last_seen" ? (
                    date(row[col])
                  ) : col === "enabled" ? (
                    <Badge value={row[col] ? "enabled" : "disabled"} />
                  ) : (
                    <span className={i === 0 ? "record-primary" : "muted"}>
                      {str(row[col])}
                    </span>
                  )}
                </td>
              ))}
              <td>
                <button
                  className="text-button"
                  onClick={() => setExpanded(row.id)}
                >
                  Inspect <ChevronRight size={14} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {!rows.length && (
        <div className="empty">
          <Database size={28} />
          <h3>No records found</h3>
          <p>Try another search or add data to this workspace.</p>
        </div>
      )}
      {expanded && (
        <Dialog
          className="modal-overlay"
          label="Record details"
          onClose={() => setExpanded(null)}
        >
          <div className="modal">
            <div className="panel-heading">
              <h2>Record details</h2>
              <button
                aria-label="Close details"
                onClick={() => setExpanded(null)}
              >
                <X />
              </button>
            </div>
            <RecordDetails
              row={rows.find((r) => r.id === expanded)!}
              tab={tab}
              me={me}
              changed={changed}
              close={() => setExpanded(null)}
            />
          </div>
        </Dialog>
      )}
    </div>
  );
}
function RecordDetails({
  row,
  tab,
  me,
  changed,
  close,
}: {
  row: Row;
  tab: Tab;
  me: Me;
  changed: (m: string) => Promise<void>;
  close: () => void;
}) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function toggleRule() {
    setBusy(true);
    try {
      const { id, created_at, updated_at, organization_id, ...data } = row;
      void id;
      void created_at;
      void updated_at;
      void organization_id;
      await api(`/rules/${row.id}`, {
        method: "PUT",
        body: JSON.stringify({ ...data, enabled: !data.enabled }),
      });
      await changed("Rule updated");
      close();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="modal-body">
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <pre>{JSON.stringify(row, null, 2)}</pre>
      {tab === "Detection Rules" && me.role === "administrator" && (
        <Button disabled={busy} onClick={toggleRule}>
          {row.enabled ? "Disable rule" : "Enable rule"}
        </Button>
      )}
      {tab === "Assets" && me.role !== "viewer" && (
        <AssetForm
          initial={row}
          onSuccess={async () => {
            await changed("Asset updated");
            close();
          }}
        />
      )}
      {tab === "Assets" && me.role === "administrator" && (
        <Button
          variant="outline"
          onClick={async () => {
            if (
              !window.confirm(
                "Delete this asset? Historical alerts are preserved.",
              )
            )
              return;
            try {
              await api(`/assets/${row.id}`, { method: "DELETE" });
              await changed("Asset deleted");
              close();
            } catch (e) {
              setError((e as Error).message);
            }
          }}
        >
          Delete asset
        </Button>
      )}
    </div>
  );
}
function AlertDrawer({
  id,
  close,
  writable,
  changed,
}: {
  id: string;
  close: () => void;
  writable: boolean;
  changed: (message: string) => Promise<void>;
}) {
  const detail = useQuery({
    queryKey: ["alert", id],
    queryFn: () => api<Alert>(`/alerts/${id}`),
  });
  const members = useQuery({
    queryKey: ["members"],
    queryFn: () => api<Member[]>("/organizations/members"),
  });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    const escape = (e: KeyboardEvent) => {
      if (e.key === "Escape") close();
    };
    document.addEventListener("keydown", escape);
    return () => document.removeEventListener("keydown", escape);
  }, [close]);
  async function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setBusy(true);
    const form = e.currentTarget;
    const data = Object.fromEntries(new FormData(form));
    try {
      await api(`/alerts/${id}`, {
        method: "PATCH",
        body: JSON.stringify({ ...data, assignee: data.assignee || null }),
      });
      await changed("Investigation updated");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Dialog
      className="drawer-overlay"
      label="Alert investigation"
      onClose={close}
    >
      <section className="drawer">
        <div className="drawer-header">
          <span className="eyebrow">ALERT INVESTIGATION</span>
          <button autoFocus aria-label="Close investigation" onClick={close}>
            <X />
          </button>
        </div>
        {detail.isPending ? (
          <Loading />
        ) : detail.isError ? (
          <ErrorState
            message={detail.error.message}
            retry={() => detail.refetch()}
          />
        ) : (
          <>
            <div className="drawer-title">
              <Badge value={detail.data.severity} />
              <Badge value={detail.data.status} />
              <h2>{detail.data.title}</h2>
              <p className="mono muted">
                {detail.data.hostname} · {detail.data.source}
              </p>
            </div>
            <section>
              <h3>Why this matched</h3>
              <p>{detail.data.description}</p>
              <div className="evidence-meta">
                <span>
                  Risk score <b>{detail.data.risk_score}/100</b>
                </span>
                <span>
                  ATT&CK{" "}
                  <a
                    href={`https://attack.mitre.org/techniques/${detail.data.technique.replace(".", "/")}/`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {detail.data.technique}
                  </a>
                </span>
              </div>
              <h3>Recommended investigation</h3>
              <p>{detail.data.recommended_response}</p>
            </section>
            {writable && (
              <section>
                <h3>Analyst decision</h3>
                <form
                  key={`${detail.data.status}-${detail.data.assignee}`}
                  onSubmit={submit}
                >
                  <div className="form-grid">
                    <label>
                      Status
                      <select
                        name="status"
                        aria-label="Status"
                        defaultValue={detail.data.status}
                      >
                        {[
                          "new",
                          "investigating",
                          "resolved",
                          "false_positive",
                        ].map((x) => (
                          <option key={x} value={x}>
                            {x.replaceAll("_", " ")}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label>
                      Assignee
                      <select
                        name="assignee"
                        defaultValue={detail.data.assignee || ""}
                      >
                        <option value="">Unassigned</option>
                        {members.data?.map((m) => (
                          <option value={m.id} key={m.id}>
                            {m.name}
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>
                  <label>
                    False-positive reason
                    <textarea
                      name="false_positive_reason"
                      maxLength={2000}
                      defaultValue={detail.data.false_positive_reason}
                      placeholder="Required when marking as false positive"
                    />
                  </label>
                  {error && (
                    <p role="alert" className="error">
                      {error}
                    </p>
                  )}
                  <Button disabled={busy}>
                    {busy ? "Saving…" : "Save decision"}
                  </Button>
                </form>
              </section>
            )}
            <section>
              <h3>
                Evidence timeline{" "}
                <span className="count">{detail.data.evidence.length}</span>
              </h3>
              {detail.data.evidence.map((event) => (
                <details className="evidence" key={event.id}>
                  <summary>
                    <span className="live-dot" />
                    <b>{str(event.event_type)}</b>
                    <span className="muted">{date(event.timestamp)}</span>
                  </summary>
                  <pre>{JSON.stringify(event, null, 2)}</pre>
                </details>
              ))}
            </section>
            <section>
              <h3>Analyst notes</h3>
              {detail.data.notes.map((note) => (
                <article className="note" key={note.id}>
                  <p>{str(note.body)}</p>
                  <small className="muted">{date(note.created_at)}</small>
                </article>
              ))}
              {!detail.data.notes.length && (
                <p className="muted">
                  No notes yet. Record the context behind your investigation.
                </p>
              )}
              {writable && (
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    const form = e.currentTarget;
                    const body = new FormData(form).get("body");
                    setBusy(true);
                    try {
                      await api(`/alerts/${id}/notes`, {
                        method: "POST",
                        body: JSON.stringify({ body }),
                      });
                      form.reset();
                      await changed("Note added");
                    } catch (err) {
                      setError((err as Error).message);
                    } finally {
                      setBusy(false);
                    }
                  }}
                >
                  <label className="sr-only" htmlFor="note">
                    Analyst note
                  </label>
                  <textarea
                    id="note"
                    name="body"
                    required
                    maxLength={4000}
                    placeholder="Add an investigation note…"
                  />
                  <Button variant="outline" disabled={busy}>
                    Add note
                  </Button>
                </form>
              )}
            </section>
            <section>
              <h3>Status history</h3>
              {detail.data.history.length === 0 && (
                <p className="muted">No status changes recorded.</p>
              )}
              {detail.data.history.map((h) => (
                <p key={h.id}>
                  <Badge value={h.previous} /> → <Badge value={h.status} />
                  <small className="muted"> {date(h.created_at)}</small>
                </p>
              ))}
            </section>
          </>
        )}
      </section>
    </Dialog>
  );
}
function AssetForm({
  initial,
  onSuccess,
}: {
  initial?: Row;
  onSuccess: () => Promise<void>;
}) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  return (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        setError("");
        setBusy(true);
        const data = Object.fromEntries(new FormData(e.currentTarget));
        try {
          await api(initial ? `/assets/${initial.id}` : "/assets", {
            method: initial ? "PUT" : "POST",
            body: JSON.stringify({ ...data, tags: initial?.tags || [] }),
          });
          await onSuccess();
        } catch (err) {
          setError((err as Error).message);
        } finally {
          setBusy(false);
        }
      }}
    >
      <div className="form-grid">
        {[
          "hostname",
          "ip_address",
          "operating_system",
          "owner",
          "department",
        ].map((field) => (
          <label key={field}>
            {field.replaceAll("_", " ")}
            <input
              name={field}
              required
              maxLength={80}
              defaultValue={initial ? str(initial[field]) : ""}
            />
          </label>
        ))}
        <label>
          Asset type
          <select
            name="asset_type"
            defaultValue={str(initial?.asset_type || "workstation")}
          >
            {["workstation", "server", "network", "cloud", "application"].map(
              (x) => (
                <option key={x}>{x}</option>
              ),
            )}
          </select>
        </label>
        <label>
          Criticality
          <select
            name="criticality"
            defaultValue={str(initial?.criticality || "medium")}
          >
            {["informational", "low", "medium", "high", "critical"].map((x) => (
              <option key={x}>{x}</option>
            ))}
          </select>
        </label>
        <label>
          Status
          <select name="status" defaultValue={str(initial?.status || "active")}>
            <option>active</option>
            <option>inactive</option>
          </select>
        </label>
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <Button disabled={busy}>
        {busy ? "Saving…" : initial ? "Save asset" : "Create asset"}
      </Button>
    </form>
  );
}
function DataModal({
  kind,
  close,
  changed,
}: {
  kind: "asset" | "ingest" | "csv";
  close: () => void;
  changed: (message: string) => Promise<void>;
}) {
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sample] = useState(() =>
    kind === "csv"
      ? "hostname,ip_address,operating_system,asset_type,owner,department,criticality,status\nlab-new,192.0.2.99,Linux,server,Demo Analyst,Security,medium,active"
      : JSON.stringify(
          {
            events: [
              {
                timestamp: new Date(Date.now() - 60000).toISOString(),
                source: "dns",
                category: "network",
                event_type: "dns_query",
                hostname: "edge-01",
                username: "demo-user",
                action: "query",
                outcome: "success",
                parsed_metadata: { domain: "blocked.example" },
                raw_event: "Synthetic DNS query; no network request is made.",
              },
            ],
          },
          null,
          2,
        ),
  );
  return (
    <Dialog
      className="modal-overlay"
      label={kind === "asset" ? "Add asset" : "Import data"}
      onClose={close}
    >
      <div className="modal">
        <div className="panel-heading">
          <h2>
            {kind === "asset"
              ? "Add asset"
              : kind === "csv"
                ? "Import assets"
                : "Ingest synthetic events"}
          </h2>
          <button aria-label="Close form" onClick={close}>
            <X />
          </button>
        </div>
        <div className="modal-body">
          {kind === "asset" ? (
            <AssetForm
              onSuccess={async () => {
                await changed("Asset created");
                close();
              }}
            />
          ) : (
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                setBusy(true);
                setError("");
                const content = String(
                  new FormData(e.currentTarget).get("content"),
                );
                try {
                  const result = await api<Record<string, number>>(
                    kind === "csv" ? "/assets/import" : "/events/batch",
                    {
                      method: "POST",
                      body:
                        kind === "csv"
                          ? JSON.stringify({ content })
                          : JSON.stringify(JSON.parse(content)),
                    },
                  );
                  await changed(
                    kind === "csv"
                      ? `${result.imported} assets imported`
                      : `${result.accepted} events accepted, ${result.duplicates} duplicates`,
                  );
                  close();
                } catch (err) {
                  setError((err as Error).message);
                } finally {
                  setBusy(false);
                }
              }}
            >
              <p className="muted">
                {kind === "csv"
                  ? "Up to 100 validated rows. Import is atomic."
                  : "Up to 100 events. Duplicate events are ignored; matching rules create alerts."}
              </p>
              <label>
                {kind === "csv" ? "CSV content" : "JSON batch"}
                <textarea
                  className="code-input"
                  name="content"
                  defaultValue={sample}
                  required
                  maxLength={100000}
                />
              </label>
              {error && (
                <p role="alert" className="error">
                  {error}
                </p>
              )}
              <Button disabled={busy}>
                {busy ? "Processing…" : "Submit data"}
              </Button>
            </form>
          )}
        </div>
      </div>
    </Dialog>
  );
}
function Coverage() {
  const rules = useQuery({
    queryKey: ["coverage"],
    queryFn: () => api<Page>("/rules"),
  });
  if (rules.isPending) return <Loading />;
  if (rules.isError)
    return (
      <ErrorState message={rules.error.message} retry={() => rules.refetch()} />
    );
  return (
    <>
      <div className="info-banner">
        <Target size={20} />
        <p>
          {rules.data.items.filter((r) => r.enabled).length} enabled rules
          across{" "}
          {
            new Set(
              rules.data.items.filter((r) => r.enabled).map((r) => r.technique),
            ).size
          }{" "}
          techniques. This is coverage of the included rule catalog, not the
          full ATT&CK matrix or confirmed attacks.
        </p>
      </div>
      <div className="coverage-grid">
        {rules.data.items.map((rule) => (
          <section className="panel coverage-card" key={rule.id}>
            <div>
              <Badge value={rule.enabled ? "enabled" : "disabled"} />
              <span className="muted">{str(rule.source)}</span>
            </div>
            <h2>{str(rule.name)}</h2>
            <p>{str(rule.description)}</p>
            <small className="muted">{str(rule.tactic)}</small>
            <a
              href={`https://attack.mitre.org/techniques/${str(rule.technique).replace(".", "/")}/`}
              target="_blank"
              rel="noreferrer"
            >
              {str(rule.technique)} · MITRE ATT&CK <ArrowRight size={14} />
            </a>
          </section>
        ))}
      </div>
    </>
  );
}
function Settings({
  me,
  changed,
}: {
  me: Me;
  changed: (message: string) => Promise<void>;
}) {
  const members = useQuery({
    queryKey: ["members"],
    queryFn: () => api<Member[]>("/organizations/members"),
  });
  const [error, setError] = useState("");
  return (
    <section className="panel settings">
      <h2>{me.organization.name}</h2>
      <p className="muted">
        Access is scoped to this organization. Role changes take effect on the
        next API request.
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {members.isPending ? (
        <Loading />
      ) : members.isError ? (
        <ErrorState
          message={members.error.message}
          retry={() => members.refetch()}
        />
      ) : (
        members.data.map((member) => (
          <div className="member" key={member.id}>
            <span className="avatar">
              {member.name.slice(0, 2).toUpperCase()}
            </span>
            <div>
              <b>{member.name}</b>
              <small>{member.email}</small>
            </div>
            {me.role === "administrator" && me.id !== member.id ? (
              <select
                aria-label={`Role for ${member.name}`}
                value={member.role}
                onChange={async (e) => {
                  const role = e.target.value;
                  if (
                    !window.confirm(`Change ${member.name}'s role to ${role}?`)
                  )
                    return;
                  try {
                    await api(`/organizations/members/${member.id}`, {
                      method: "PATCH",
                      body: JSON.stringify({ role }),
                    });
                    await changed("Member role updated");
                  } catch (err) {
                    setError((err as Error).message);
                  }
                }}
              >
                {["administrator", "analyst", "viewer"].map((x) => (
                  <option key={x}>{x}</option>
                ))}
              </select>
            ) : (
              <Badge value={member.role} />
            )}
          </div>
        ))
      )}
      <div className="info-banner">
        <ShieldCheck size={22} />
        <p>
          Phase 1 includes the operational foundation. Incident workspaces, AI
          assistance, phishing analysis, and anomaly detection are planned in
          the documented roadmap.
        </p>
      </div>
    </section>
  );
}
