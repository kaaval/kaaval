"use client";
import { useEffect, useState } from "react";
import { useAuth } from "../../components/AuthContext";

const API = "http://localhost:8000";

const SEV_STYLE: Record<string, string> = {
    CRITICAL: "bg-red-900/50 text-red-400 border border-red-700/50",
    HIGH:     "bg-orange-900/40 text-orange-400 border border-orange-700/50",
    MEDIUM:   "bg-yellow-900/40 text-yellow-400 border border-yellow-700/50",
    LOW:      "bg-blue-900/40 text-blue-400 border border-blue-700/50",
    UNKNOWN:  "bg-gray-800 text-gray-400 border border-gray-700",
};

const SEV_DOT: Record<string, string> = {
    CRITICAL: "bg-red-500",
    HIGH:     "bg-orange-500",
    MEDIUM:   "bg-yellow-500",
    LOW:      "bg-blue-400",
    UNKNOWN:  "bg-gray-500",
};

interface Feed {
    id: string; name: string; url: string; feed_type: string;
    description: string | null; enabled: boolean;
    last_fetched: string | null; entry_count: number;
}
interface Finding {
    cve_id: string; title: string; severity: string; cvss_score: number | null;
    affected_cluster_versions: string[]; fixed_in: string[] | null;
    description: string; references: { url: string; type: string }[];
}
interface ScanResult {
    scanned_at: string; cluster_version: string; node_versions: string[];
    total_cves_checked: number; affected_count: number;
    severity_breakdown: Record<string, number>; findings: Finding[];
}
interface Summary {
    feeds: number; total_cves: number;
    severity_breakdown: Record<string, number>;
    latest_scan: ScanResult | null;
}

function SeverityBadge({ sev }: { sev: string }) {
    return (
        <span className={`px-2 py-0.5 rounded text-[11px] font-mono font-bold uppercase ${SEV_STYLE[sev] ?? SEV_STYLE.UNKNOWN}`}>
            {sev}
        </span>
    );
}

function StatCard({ label, value, sub, color }: { label: string; value: number | string; sub?: string; color: string }) {
    return (
        <div className={`bg-gray-900/80 border ${color} rounded p-4`}>
            <div className="text-2xl font-bold font-mono text-white">{value}</div>
            <div className="text-xs font-mono text-gray-400 uppercase tracking-widest mt-1">{label}</div>
            {sub && <div className="text-[10px] text-gray-600 mt-0.5">{sub}</div>}
        </div>
    );
}

export default function CVEPage() {
    const { token } = useAuth();
    const [summary, setSummary] = useState<Summary | null>(null);
    const [feeds, setFeeds] = useState<Feed[]>([]);
    const [scan, setScan] = useState<ScanResult | null>(null);
    const [entries, setEntries] = useState<any[]>([]);
    const [totalEntries, setTotalEntries] = useState(0);
    const [loading, setLoading] = useState(true);
    const [scanning, setScanning] = useState(false);
    const [refreshingFeed, setRefreshingFeed] = useState<string | null>(null);
    const [refreshingAll, setRefreshingAll] = useState(false);
    const [showAddFeed, setShowAddFeed] = useState(false);
    const [newFeed, setNewFeed] = useState({ name: "", url: "", feed_type: "auto", description: "" });
    const [sevFilter, setSevFilter] = useState("ALL");
    const [searchTerm, setSearchTerm] = useState("");
    const [activeTab, setActiveTab] = useState<"scan" | "browse">("scan");

    const headers = { Authorization: `Bearer ${token}`, "Content-Type": "application/json" };

    const fetchAll = async () => {
        if (!token) return;
        setLoading(true);
        try {
            const [sumRes, feedRes, scanRes, entRes] = await Promise.all([
                fetch(`${API}/cve/summary`, { headers }),
                fetch(`${API}/cve/feeds`, { headers }),
                fetch(`${API}/cve/scan/latest`, { headers }),
                fetch(`${API}/cve/entries?limit=50`, { headers }),
            ]);
            if (sumRes.ok) setSummary(await sumRes.json());
            if (feedRes.ok) setFeeds(await feedRes.json());
            if (scanRes.ok) { const d = await scanRes.json(); if (d.findings) setScan(d); }
            if (entRes.ok) { const d = await entRes.json(); setEntries(d.entries ?? []); setTotalEntries(d.total ?? 0); }
        } catch (e) { console.error(e); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchAll(); }, [token]);

    const fetchEntries = async (sev = sevFilter, q = searchTerm) => {
        if (!token) return;
        const params = new URLSearchParams({ limit: "50" });
        if (sev !== "ALL") params.set("severity", sev);
        if (q) params.set("search", q);
        const res = await fetch(`${API}/cve/entries?${params}`, { headers });
        if (res.ok) { const d = await res.json(); setEntries(d.entries ?? []); setTotalEntries(d.total ?? 0); }
    };

    const runScan = async () => {
        setScanning(true);
        try {
            const res = await fetch(`${API}/cve/scan`, { method: "POST", headers });
            if (res.ok) { setScan(await res.json()); await fetchAll(); }
        } finally { setScanning(false); }
    };

    const refreshFeed = async (id: string) => {
        setRefreshingFeed(id);
        try {
            await fetch(`${API}/cve/feeds/${id}/refresh`, { method: "POST", headers });
            await fetchAll();
        } finally { setRefreshingFeed(null); }
    };

    const refreshAll = async () => {
        setRefreshingAll(true);
        try {
            await fetch(`${API}/cve/feeds/refresh-all`, { method: "POST", headers });
            await fetchAll();
        } finally { setRefreshingAll(false); }
    };

    const toggleFeed = async (id: string) => {
        await fetch(`${API}/cve/feeds/${id}/toggle`, { method: "PATCH", headers });
        await fetchAll();
    };

    const deleteFeed = async (id: string, name: string) => {
        if (!confirm(`Delete feed "${name}" and all its CVE entries?`)) return;
        await fetch(`${API}/cve/feeds/${id}`, { method: "DELETE", headers });
        await fetchAll();
    };

    const addFeed = async () => {
        if (!newFeed.name || !newFeed.url) return;
        const res = await fetch(`${API}/cve/feeds`, {
            method: "POST", headers,
            body: JSON.stringify(newFeed),
        });
        if (res.ok) {
            setNewFeed({ name: "", url: "", feed_type: "auto", description: "" });
            setShowAddFeed(false);
            await fetchAll();
        } else {
            const err = await res.json();
            alert(err.detail ?? "Failed to add feed");
        }
    };

    const latestScan = scan ?? summary?.latest_scan ?? null;
    const breakdown = latestScan?.severity_breakdown ?? summary?.severity_breakdown ?? {};

    return (
        <div className="p-8 space-y-8">
            {/* Header */}
            <div className="flex items-start justify-between">
                <div>
                    <h1 className="text-3xl font-bold font-mono tracking-tight text-white">CVE Scanner</h1>
                    <p className="text-gray-500 text-sm mt-1 font-mono">
                        Kubernetes cluster vulnerability detection · {summary?.total_cves ?? 0} CVEs across {summary?.feeds ?? 0} feeds
                    </p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={refreshAll}
                        disabled={refreshingAll}
                        className="px-4 py-2 text-xs font-mono uppercase tracking-widest border border-gray-700 text-gray-400 hover:text-white hover:border-gray-500 rounded transition-colors disabled:opacity-50"
                    >
                        {refreshingAll ? "Refreshing..." : "Refresh All Feeds"}
                    </button>
                    <button
                        onClick={runScan}
                        disabled={scanning}
                        className="px-4 py-2 text-xs font-mono uppercase tracking-widest bg-neon-blue/10 border border-neon-blue/40 text-neon-blue hover:bg-neon-blue/20 rounded transition-colors disabled:opacity-50"
                    >
                        {scanning ? "Scanning..." : "Run Cluster Scan"}
                    </button>
                </div>
            </div>

            {loading ? (
                <div className="text-center text-gray-500 py-20 font-mono animate-pulse">Loading CVE data...</div>
            ) : (
                <>
                    {/* Summary cards */}
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
                        <StatCard label="Total CVEs" value={summary?.total_cves ?? 0} color="border-gray-700/50" />
                        <StatCard label="Critical" value={breakdown.CRITICAL ?? 0} color="border-red-800/50" />
                        <StatCard label="High" value={breakdown.HIGH ?? 0} color="border-orange-800/50" />
                        <StatCard label="Medium" value={breakdown.MEDIUM ?? 0} color="border-yellow-800/50" />
                        <StatCard label="Low" value={breakdown.LOW ?? 0} color="border-blue-800/50" />
                        <StatCard
                            label="Affected (latest)"
                            value={latestScan?.affected_count ?? "—"}
                            sub={latestScan ? `of ${latestScan.total_cves_checked} checked` : "No scan yet"}
                            color="border-neon-blue/30"
                        />
                    </div>

                    {/* Latest scan cluster info */}
                    {latestScan && (
                        <div className="bg-gray-900/60 border border-gray-700/50 rounded p-4 flex flex-wrap gap-6 text-sm font-mono">
                            <div>
                                <span className="text-gray-500 uppercase text-[10px] tracking-widest block">Cluster Version</span>
                                <span className="text-neon-blue">{latestScan.cluster_version}</span>
                            </div>
                            {latestScan.node_versions?.length > 0 && (
                                <div>
                                    <span className="text-gray-500 uppercase text-[10px] tracking-widest block">Node Versions</span>
                                    <span className="text-gray-300">{latestScan.node_versions.join(", ")}</span>
                                </div>
                            )}
                            <div>
                                <span className="text-gray-500 uppercase text-[10px] tracking-widest block">Last Scanned</span>
                                <span className="text-gray-300">{new Date(latestScan.scanned_at).toLocaleString()}</span>
                            </div>
                        </div>
                    )}

                    {/* Tabs */}
                    <div className="flex gap-1 border-b border-gray-800">
                        {(["scan", "browse"] as const).map((t) => (
                            <button
                                key={t}
                                onClick={() => setActiveTab(t)}
                                className={`px-5 py-2.5 text-xs font-mono uppercase tracking-widest border-b-2 transition-colors ${activeTab === t
                                    ? "border-neon-blue text-neon-blue"
                                    : "border-transparent text-gray-500 hover:text-gray-300"
                                    }`}
                            >
                                {t === "scan" ? "Cluster Findings" : "CVE Database"}
                            </button>
                        ))}
                    </div>

                    {/* Tab: Cluster Findings */}
                    {activeTab === "scan" && (
                        <div className="space-y-4">
                            {!latestScan ? (
                                <div className="text-center py-16 text-gray-600 font-mono">
                                    No scan results yet. Click <span className="text-neon-blue">Run Cluster Scan</span> to check your cluster.
                                </div>
                            ) : latestScan.findings.length === 0 ? (
                                <div className="text-center py-16 font-mono">
                                    <div className="text-3xl mb-3">✓</div>
                                    <div className="text-neon-green font-bold">No matching CVEs found for cluster version {latestScan.cluster_version}</div>
                                    <div className="text-gray-500 text-sm mt-2">{latestScan.total_cves_checked} CVEs checked</div>
                                </div>
                            ) : (
                                <div className="overflow-x-auto rounded border border-gray-800">
                                    <table className="w-full text-sm font-mono">
                                        <thead className="bg-gray-900 text-gray-500 text-[11px] uppercase tracking-widest">
                                            <tr>
                                                <th className="px-4 py-3 text-left">CVE ID</th>
                                                <th className="px-4 py-3 text-left">Severity</th>
                                                <th className="px-4 py-3 text-left">CVSS</th>
                                                <th className="px-4 py-3 text-left">Title</th>
                                                <th className="px-4 py-3 text-left">Affected Versions</th>
                                                <th className="px-4 py-3 text-left">Fixed In</th>
                                                <th className="px-4 py-3 text-left">Ref</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-gray-800/50">
                                            {latestScan.findings.map((f) => (
                                                <tr key={f.cve_id} className="hover:bg-white/[0.02] transition-colors">
                                                    <td className="px-4 py-3 text-neon-blue whitespace-nowrap">{f.cve_id}</td>
                                                    <td className="px-4 py-3"><SeverityBadge sev={f.severity} /></td>
                                                    <td className="px-4 py-3 text-gray-300">{f.cvss_score?.toFixed(1) ?? "—"}</td>
                                                    <td className="px-4 py-3 text-gray-300 max-w-xs truncate" title={f.title}>{f.title}</td>
                                                    <td className="px-4 py-3">
                                                        {f.affected_cluster_versions.map((v) => (
                                                            <span key={v} className="inline-block mr-1 px-1.5 py-0.5 bg-red-900/30 border border-red-800/40 text-red-400 text-[10px] rounded">{v}</span>
                                                        ))}
                                                    </td>
                                                    <td className="px-4 py-3 text-gray-500 text-[11px]">
                                                        {f.fixed_in?.join(", ") ?? <span className="text-gray-600">N/A</span>}
                                                    </td>
                                                    <td className="px-4 py-3">
                                                        {f.references[0]?.url && (
                                                            <a href={f.references[0].url} target="_blank" rel="noreferrer"
                                                                className="text-neon-blue/60 hover:text-neon-blue text-[11px] underline">
                                                                Advisory
                                                            </a>
                                                        )}
                                                    </td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </div>
                    )}

                    {/* Tab: CVE Database Browser */}
                    {activeTab === "browse" && (
                        <div className="space-y-4">
                            <div className="flex flex-wrap gap-3 items-center">
                                <input
                                    type="text"
                                    placeholder="Search CVE ID or title..."
                                    value={searchTerm}
                                    onChange={(e) => { setSearchTerm(e.target.value); fetchEntries(sevFilter, e.target.value); }}
                                    className="bg-gray-900 border border-gray-700 text-sm font-mono text-gray-200 rounded px-3 py-2 placeholder-gray-600 focus:outline-none focus:border-neon-blue/60 w-64"
                                />
                                <div className="flex gap-1">
                                    {["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"].map((s) => (
                                        <button
                                            key={s}
                                            onClick={() => { setSevFilter(s); fetchEntries(s, searchTerm); }}
                                            className={`px-3 py-1.5 text-[11px] font-mono uppercase tracking-wider rounded transition-colors border ${sevFilter === s
                                                ? (SEV_STYLE[s] ?? "bg-gray-700 text-white border-gray-500")
                                                : "bg-transparent text-gray-500 border-gray-700 hover:border-gray-500"
                                                }`}
                                        >
                                            {s}
                                        </button>
                                    ))}
                                </div>
                                <span className="text-gray-600 text-xs font-mono ml-auto">{totalEntries} total</span>
                            </div>

                            <div className="overflow-x-auto rounded border border-gray-800">
                                <table className="w-full text-sm font-mono">
                                    <thead className="bg-gray-900 text-gray-500 text-[11px] uppercase tracking-widest">
                                        <tr>
                                            <th className="px-4 py-3 text-left">CVE ID</th>
                                            <th className="px-4 py-3 text-left">Severity</th>
                                            <th className="px-4 py-3 text-left">CVSS</th>
                                            <th className="px-4 py-3 text-left">Title</th>
                                            <th className="px-4 py-3 text-left">Published</th>
                                            <th className="px-4 py-3 text-left">Fixed In</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-gray-800/50">
                                        {entries.length === 0 ? (
                                            <tr><td colSpan={6} className="text-center py-12 text-gray-600">No CVE entries found. Refresh feeds to load data.</td></tr>
                                        ) : entries.map((e) => (
                                            <tr key={e.id} className="hover:bg-white/[0.02] transition-colors">
                                                <td className="px-4 py-3 text-neon-blue whitespace-nowrap">{e.cve_id}</td>
                                                <td className="px-4 py-3"><SeverityBadge sev={e.severity} /></td>
                                                <td className="px-4 py-3 text-gray-300">{e.cvss_score?.toFixed(1) ?? "—"}</td>
                                                <td className="px-4 py-3 text-gray-300 max-w-sm truncate" title={e.title}>{e.title}</td>
                                                <td className="px-4 py-3 text-gray-500 text-[11px]">
                                                    {e.published_date ? new Date(e.published_date).toLocaleDateString() : "—"}
                                                </td>
                                                <td className="px-4 py-3 text-gray-500 text-[11px]">
                                                    {e.fixed_in?.join(", ") ?? "—"}
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}

                    {/* Feed Management */}
                    <div className="space-y-3">
                        <div className="flex items-center justify-between">
                            <h2 className="text-sm font-mono uppercase tracking-widest text-gray-400">CVE Feeds</h2>
                            <button
                                onClick={() => setShowAddFeed(!showAddFeed)}
                                className="text-xs font-mono uppercase tracking-widest text-neon-blue/70 hover:text-neon-blue border border-neon-blue/20 hover:border-neon-blue/50 px-3 py-1.5 rounded transition-colors"
                            >
                                {showAddFeed ? "Cancel" : "+ Add Feed"}
                            </button>
                        </div>

                        {/* Add feed form */}
                        {showAddFeed && (
                            <div className="bg-gray-900/80 border border-gray-700/60 rounded p-4 space-y-3">
                                <p className="text-xs text-gray-500 font-mono">
                                    Supports: JSON Feed 1.0 (Kubernetes official), OSV (osv.dev), NVD JSON 2.0 (nvd.nist.gov)
                                </p>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                    <input
                                        placeholder="Feed name *"
                                        value={newFeed.name}
                                        onChange={(e) => setNewFeed({ ...newFeed, name: e.target.value })}
                                        className="bg-black/40 border border-gray-700 text-sm font-mono text-gray-200 rounded px-3 py-2 placeholder-gray-600 focus:outline-none focus:border-neon-blue/50"
                                    />
                                    <input
                                        placeholder="Feed URL *"
                                        value={newFeed.url}
                                        onChange={(e) => setNewFeed({ ...newFeed, url: e.target.value })}
                                        className="bg-black/40 border border-gray-700 text-sm font-mono text-gray-200 rounded px-3 py-2 placeholder-gray-600 focus:outline-none focus:border-neon-blue/50"
                                    />
                                    <select
                                        value={newFeed.feed_type}
                                        onChange={(e) => setNewFeed({ ...newFeed, feed_type: e.target.value })}
                                        className="bg-black/40 border border-gray-700 text-sm font-mono text-gray-200 rounded px-3 py-2 focus:outline-none focus:border-neon-blue/50"
                                    >
                                        <option value="auto">Auto-detect format</option>
                                        <option value="json_feed">JSON Feed 1.0 (k8s official)</option>
                                        <option value="osv">OSV (osv.dev)</option>
                                        <option value="nvd">NVD JSON 2.0</option>
                                    </select>
                                    <input
                                        placeholder="Description (optional)"
                                        value={newFeed.description}
                                        onChange={(e) => setNewFeed({ ...newFeed, description: e.target.value })}
                                        className="bg-black/40 border border-gray-700 text-sm font-mono text-gray-200 rounded px-3 py-2 placeholder-gray-600 focus:outline-none focus:border-neon-blue/50"
                                    />
                                </div>
                                <button
                                    onClick={addFeed}
                                    className="px-4 py-2 text-xs font-mono uppercase tracking-widest bg-neon-blue/10 border border-neon-blue/40 text-neon-blue hover:bg-neon-blue/20 rounded transition-colors"
                                >
                                    Add Feed
                                </button>
                            </div>
                        )}

                        {/* Feed list */}
                        <div className="overflow-x-auto rounded border border-gray-800">
                            <table className="w-full text-sm font-mono">
                                <thead className="bg-gray-900 text-gray-500 text-[11px] uppercase tracking-widest">
                                    <tr>
                                        <th className="px-4 py-3 text-left">Feed Name</th>
                                        <th className="px-4 py-3 text-left">Type</th>
                                        <th className="px-4 py-3 text-left">CVEs Loaded</th>
                                        <th className="px-4 py-3 text-left">Last Refreshed</th>
                                        <th className="px-4 py-3 text-left">Status</th>
                                        <th className="px-4 py-3 text-left">Actions</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-gray-800/50">
                                    {feeds.map((f) => (
                                        <tr key={f.id} className="hover:bg-white/[0.02] transition-colors">
                                            <td className="px-4 py-3">
                                                <div className="text-gray-200">{f.name}</div>
                                                <div className="text-gray-600 text-[10px] truncate max-w-xs" title={f.url}>{f.url}</div>
                                            </td>
                                            <td className="px-4 py-3 text-gray-400 text-[11px] uppercase">{f.feed_type}</td>
                                            <td className="px-4 py-3 text-gray-300">{f.entry_count}</td>
                                            <td className="px-4 py-3 text-gray-500 text-[11px]">
                                                {f.last_fetched ? new Date(f.last_fetched).toLocaleString() : "Never"}
                                            </td>
                                            <td className="px-4 py-3">
                                                <span className={`inline-flex items-center gap-1.5 text-[11px] ${f.enabled ? "text-neon-green" : "text-gray-600"}`}>
                                                    <span className={`w-1.5 h-1.5 rounded-full ${f.enabled ? "bg-neon-green" : "bg-gray-600"}`} />
                                                    {f.enabled ? "Active" : "Disabled"}
                                                </span>
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex gap-2">
                                                    <button
                                                        onClick={() => refreshFeed(f.id)}
                                                        disabled={refreshingFeed === f.id}
                                                        className="text-[11px] text-neon-blue/70 hover:text-neon-blue disabled:opacity-40 transition-colors"
                                                    >
                                                        {refreshingFeed === f.id ? "..." : "Refresh"}
                                                    </button>
                                                    <button
                                                        onClick={() => toggleFeed(f.id)}
                                                        className="text-[11px] text-gray-500 hover:text-yellow-400 transition-colors"
                                                    >
                                                        {f.enabled ? "Disable" : "Enable"}
                                                    </button>
                                                    <button
                                                        onClick={() => deleteFeed(f.id, f.name)}
                                                        className="text-[11px] text-gray-600 hover:text-red-400 transition-colors"
                                                    >
                                                        Delete
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}
