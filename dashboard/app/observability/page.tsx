"use client";

import { useEffect, useState, FormEvent } from 'react';
import { useAuth } from '../../components/AuthContext';
import {
    Network, Bot, Search, GitCommit, DollarSign,
    HardDrive, Activity, CloudLightning, Zap, ShieldAlert,
} from 'lucide-react';
import {
    AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts';

// ── Static mock data for topology & cost/perf chart ──────────────────────────
const TOPOLOGY_NODES = [
    { id: 'frontend',    name: 'Frontend Web',               type: 'Pod',      status: 'healthy', x: 180, y: 130 },
    { id: 'api-gateway', name: 'API Gateway',                type: 'Service',  status: 'healthy', x: 380, y: 130 },
    { id: 'auth',        name: 'Auth Service',               type: 'Pod',      status: 'healthy', x: 560, y: 50  },
    { id: 'payment',     name: 'Payment Processor',          type: 'Pod',      status: 'danger',  x: 560, y: 210 },
    { id: 'ext-db',      name: 'External DB (192.168.1.5)',  type: 'External', status: 'warning', x: 740, y: 210 },
];
const TOPOLOGY_EDGES = [
    { source: 'frontend',    target: 'api-gateway' },
    { source: 'api-gateway', target: 'auth'        },
    { source: 'api-gateway', target: 'payment'     },
    { source: 'payment',     target: 'ext-db'      },
];
const METRICS_DATA = [
    { time: '10:00', latency: 45, cost: 2.5 },
    { time: '10:15', latency: 52, cost: 2.8 },
    { time: '10:30', latency: 38, cost: 2.1 },
    { time: '10:45', latency: 65, cost: 3.5 },
    { time: '11:00', latency: 48, cost: 2.6 },
    { time: '11:15', latency: 42, cost: 2.4 },
];

const BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:8000';

// ── Component ─────────────────────────────────────────────────────────────────
export default function ObservabilityPage() {
    const { token } = useAuth();

    const [driftStatus, setDriftStatus] = useState<{ drift_detected: boolean; details: string } | null>(null);
    const [whySummary, setWhySummary] = useState('');
    const [whyLoading, setWhyLoading] = useState(false);

    const [nlQuery, setNlQuery] = useState('');
    const [nlLoading, setNlLoading] = useState(false);
    const [nlResult, setNlResult] = useState<{ sql: string; columns: string[]; data: unknown[][] } | null>(null);
    const [nlError, setNlError] = useState('');

    useEffect(() => {
        if (!token) return;
        fetchDrift();
        fetchWhyEngine();
    }, [token]);

    async function fetchDrift() {
        try {
            const res = await fetch(`${BACKEND_URL}/api/drift`, {
                headers: { Authorization: `Bearer ${token}` },
            });
            const data = await res.json();
            setDriftStatus(data);
        } catch {
            setDriftStatus({
                drift_detected: true,
                details: "ConfigMap 'payment-config' was modified outside of GitOps!",
            });
        }
    }

    async function fetchWhyEngine() {
        setWhyLoading(true);
        try {
            const res = await fetch(`${BACKEND_URL}/api/why`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({
                    alert_context:
                        'High latency on payment-processor pod with anomalous TCP connections to external IP.',
                }),
            });
            const data = await res.json();
            setWhySummary(data.root_cause);
        } catch {
            setWhySummary(
                "Service 'Payment Processor' is failing because an unpatched CVE is being exploited " +
                'to exfiltrate data to an external IP, causing high latency.',
            );
        } finally {
            setWhyLoading(false);
        }
    }

    async function handleNLQuery(e: FormEvent) {
        e.preventDefault();
        if (!nlQuery.trim()) return;
        setNlLoading(true);
        setNlError('');
        setNlResult(null);
        try {
            const res = await fetch(`${BACKEND_URL}/api/query/nl`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
                body: JSON.stringify({ query: nlQuery }),
            });
            const data = await res.json();
            if (!res.ok) throw new Error(data.detail || 'Query failed');
            setNlResult(data);
        } catch (err: unknown) {
            setNlError(err instanceof Error ? err.message : 'Failed to execute query');
        } finally {
            setNlLoading(false);
        }
    }

    // ── Topology helpers ──────────────────────────────────────────────────────
    function nodeIcon(type: string, status: string) {
        const cls = status === 'danger' ? 'text-red-400' : status === 'warning' ? 'text-yellow-400' : 'text-gray-300';
        if (type === 'External') return <CloudLightning className={`w-5 h-5 ${cls}`} />;
        if (type === 'Service')  return <Activity       className={`w-5 h-5 ${cls}`} />;
        return                          <HardDrive      className={`w-5 h-5 ${cls}`} />;
    }

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white font-mono tracking-tight">
                        Observability
                    </h1>
                    <p className="text-sm text-gray-500 mt-1">
                        Live eBPF telemetry · Service topology · Agentic root-cause analysis
                    </p>
                </div>
                {driftStatus && (
                    <div className={`flex items-center gap-2 px-4 py-2 rounded border text-sm font-mono ${
                        driftStatus.drift_detected
                            ? 'bg-red-500/10 border-red-500/30 text-red-400'
                            : 'bg-green-500/10 border-green-500/30 text-green-400'
                    }`}>
                        <GitCommit className="w-4 h-4" />
                        {driftStatus.drift_detected ? 'GitOps Drift Detected' : 'Cluster Sync OK'}
                    </div>
                )}
            </div>

            {/* Service Topology */}
            <div className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-6">
                <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-5">
                    <Network className="w-4 h-4 text-cyan-400" />
                    Service Topology &amp; Security Mapping
                </h2>
                <div className="relative w-full overflow-x-auto" style={{ height: 280 }}>
                    {/* Edges */}
                    <svg className="absolute inset-0 w-full h-full pointer-events-none">
                        {TOPOLOGY_EDGES.map((edge, i) => {
                            const src = TOPOLOGY_NODES.find(n => n.id === edge.source);
                            const tgt = TOPOLOGY_NODES.find(n => n.id === edge.target);
                            if (!src || !tgt) return null;
                            const isDanger = src.status === 'danger' || tgt.status === 'danger';
                            return (
                                <line
                                    key={i}
                                    x1={src.x} y1={src.y} x2={tgt.x} y2={tgt.y}
                                    stroke={isDanger ? '#ef4444' : '#334155'}
                                    strokeWidth={2}
                                    strokeDasharray={isDanger ? '5,5' : undefined}
                                />
                            );
                        })}
                    </svg>
                    {/* Nodes */}
                    {TOPOLOGY_NODES.map(node => (
                        <div
                            key={node.id}
                            className="absolute -translate-x-1/2 -translate-y-1/2 flex flex-col items-center gap-1.5"
                            style={{ left: node.x, top: node.y }}
                        >
                            <div className={`w-12 h-12 rounded-xl border-2 flex items-center justify-center backdrop-blur
                                ${node.status === 'danger'  ? 'border-red-500    bg-red-500/20'    :
                                  node.status === 'warning' ? 'border-yellow-500 bg-yellow-500/20' :
                                                              'border-gray-700   bg-gray-800/60'}`}>
                                {nodeIcon(node.type, node.status)}
                            </div>
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded bg-black/60 border
                                ${node.status === 'danger' ? 'border-red-500/50 text-red-400' : 'border-gray-800 text-gray-400'}`}>
                                {node.name}
                            </span>
                        </div>
                    ))}
                </div>
            </div>

            {/* Cost & Perf chart + Why Engine side-by-side */}
            <div className="grid grid-cols-2 gap-6">
                {/* Cost / Latency chart */}
                <div className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-6">
                    <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-4">
                        <DollarSign className="w-4 h-4 text-green-400" />
                        Cost &amp; Performance
                    </h2>
                    <div className="h-48">
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={METRICS_DATA}>
                                <defs>
                                    <linearGradient id="gCost"    x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%"  stopColor="#22c55e" stopOpacity={0.4} />
                                        <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                                    </linearGradient>
                                    <linearGradient id="gLatency" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%"  stopColor="#3b82f6" stopOpacity={0.4} />
                                        <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <XAxis dataKey="time" stroke="#475569" fontSize={11} tickLine={false} axisLine={false} />
                                <YAxis yAxisId="l" stroke="#3b82f6" fontSize={11} tickLine={false} axisLine={false} />
                                <YAxis yAxisId="r" orientation="right" stroke="#22c55e" fontSize={11} tickLine={false} axisLine={false} />
                                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid #1e293b', borderRadius: 8, fontSize: 12 }} />
                                <Area yAxisId="l" type="monotone" dataKey="latency" stroke="#3b82f6" fill="url(#gLatency)" />
                                <Area yAxisId="r" type="monotone" dataKey="cost"    stroke="#22c55e" fill="url(#gCost)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                    <div className="flex gap-4 mt-3 text-xs text-gray-500 font-mono">
                        <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-blue-500 inline-block" /> Latency (ms)</span>
                        <span className="flex items-center gap-1"><span className="w-3 h-0.5 bg-green-500 inline-block" /> Cost ($)</span>
                    </div>
                </div>

                {/* Why Engine */}
                <div className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-6 flex flex-col">
                    <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-4">
                        <Bot className="w-4 h-4 text-purple-400" />
                        Contextual Root Cause
                        <span className="ml-auto text-xs text-gray-600 font-normal">The &quot;Why&quot; Engine</span>
                    </h2>
                    <div className="flex-1 bg-black/30 rounded-lg border border-gray-800 p-4 flex flex-col justify-center">
                        {whyLoading ? (
                            <div className="flex items-center gap-2 text-gray-500 text-sm">
                                <span className="w-4 h-4 rounded-full border-2 border-gray-500 border-t-transparent animate-spin" />
                                Analyzing eBPF traces...
                            </div>
                        ) : whySummary ? (
                            <div className="flex items-start gap-3">
                                <div className="p-2 bg-red-500/20 rounded-lg text-red-400 shrink-0">
                                    <Zap className="w-5 h-5" />
                                </div>
                                <p className="text-sm text-gray-300 leading-relaxed">
                                    <strong className="text-white block mb-1">Analysis Complete</strong>
                                    {whySummary}
                                </p>
                            </div>
                        ) : (
                            <p className="text-sm text-gray-600 italic">No active alerts.</p>
                        )}
                    </div>
                    <button
                        onClick={fetchWhyEngine}
                        className="mt-3 text-xs text-purple-400 hover:text-purple-300 transition-colors font-mono self-end"
                    >
                        Re-analyze →
                    </button>
                </div>
            </div>

            {/* Natural Language Query */}
            <div className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-6">
                <h2 className="text-base font-semibold text-white flex items-center gap-2 mb-4">
                    <Search className="w-4 h-4 text-cyan-400" />
                    Natural Language Query
                    <span className="ml-2 text-xs text-gray-600 font-normal">Queries eBPF ClickHouse traces</span>
                </h2>
                <form onSubmit={handleNLQuery} className="flex gap-2 mb-4">
                    <input
                        type="text"
                        value={nlQuery}
                        onChange={e => setNlQuery(e.target.value)}
                        placeholder="e.g. Show pods with the most TCP connections in the last hour"
                        className="flex-1 bg-black/40 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-cyan-500 font-mono"
                    />
                    <button
                        type="submit"
                        disabled={nlLoading}
                        className="px-5 py-2.5 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-400 text-sm font-mono rounded-lg transition-colors disabled:opacity-50"
                    >
                        {nlLoading ? 'Running…' : 'Run'}
                    </button>
                </form>

                {nlError && (
                    <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                        <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5" />
                        <span>{nlError}</span>
                    </div>
                )}

                {nlResult && (
                    <div className="space-y-3">
                        <div>
                            <p className="text-[10px] uppercase text-gray-600 font-mono tracking-wider mb-1">Generated SQL</p>
                            <pre className="bg-black/50 border border-gray-800 rounded-lg p-3 text-xs text-cyan-300 font-mono overflow-x-auto whitespace-pre-wrap">
                                {nlResult.sql}
                            </pre>
                        </div>
                        {nlResult.data.length > 0 && (
                            <div>
                                <p className="text-[10px] uppercase text-gray-600 font-mono tracking-wider mb-1">
                                    Results ({nlResult.data.length} rows)
                                </p>
                                <div className="bg-black/50 border border-gray-800 rounded-lg overflow-hidden">
                                    <table className="w-full text-xs font-mono">
                                        <thead>
                                            <tr className="border-b border-gray-800 bg-gray-900/60">
                                                {nlResult.columns.map(col => (
                                                    <th key={col} className="px-3 py-2 text-left text-gray-500 uppercase tracking-wider">
                                                        {col}
                                                    </th>
                                                ))}
                                            </tr>
                                        </thead>
                                        <tbody>
                                            {nlResult.data.slice(0, 10).map((row, i) => (
                                                <tr key={i} className="border-b border-gray-900 hover:bg-gray-800/30">
                                                    {(row as unknown[]).map((val, j) => (
                                                        <td key={j} className="px-3 py-2 text-gray-300">
                                                            {String(val)}
                                                        </td>
                                                    ))}
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        )}
                    </div>
                )}

                {!nlResult && !nlError && (
                    <p className="text-sm text-gray-600 italic">
                        Ask anything about cluster security, performance, or connections.
                    </p>
                )}
            </div>
        </div>
    );
}
