"use client";

import { useEffect, useState, FormEvent } from 'react';
import { useAuth } from '../../components/AuthContext';
import { Server, Plus, Trash2, RefreshCw, CheckCircle, XCircle, AlertCircle } from 'lucide-react';

const CP_URL = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL || 'http://localhost:8001';

interface Cluster {
    id: string;
    name: string;
    api_server_url: string;
    environment: string;
    active: boolean;
    last_seen: string | null;
    created_at: string;
}

interface ClusterHealth {
    cluster_id: string;
    name: string;
    reachable: boolean;
    node_count: number | null;
    server_version: string | null;
    error: string | null;
}

const ENV_COLOR: Record<string, string> = {
    production: 'text-red-400 border-red-500/30 bg-red-500/10',
    staging:    'text-yellow-400 border-yellow-500/30 bg-yellow-500/10',
    dev:        'text-blue-400 border-blue-500/30 bg-blue-500/10',
};

export default function MultiClusterPage() {
    const { token } = useAuth();
    const [clusters, setClusters] = useState<Cluster[]>([]);
    const [health, setHealth] = useState<Record<string, ClusterHealth>>({});
    const [loading, setLoading] = useState(true);
    const [showForm, setShowForm] = useState(false);
    const [probing, setProbing] = useState<string | null>(null);

    const [form, setForm] = useState({
        name: '',
        api_server_url: '',
        bearer_token: '',
        ca_cert_pem: '',
        environment: 'production',
    });

    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    async function fetchClusters() {
        setLoading(true);
        try {
            const res = await fetch(`${CP_URL}/clusters`, { headers });
            if (res.status === 402) { setClusters([]); return; }
            setClusters(await res.json());
        } catch { setClusters([]); }
        finally { setLoading(false); }
    }

    async function probeHealth(id: string) {
        setProbing(id);
        try {
            const res = await fetch(`${CP_URL}/clusters/${id}/health`, { headers });
            const data: ClusterHealth = await res.json();
            setHealth(prev => ({ ...prev, [id]: data }));
        } finally { setProbing(null); }
    }

    async function probeAll(list: Cluster[]) {
        await Promise.all(list.filter(c => c.active).map(c => probeHealth(c.id)));
    }

    useEffect(() => {
        if (!token) return;
        fetchClusters().then(async () => {
            // probe health after loading list
        });
    }, [token]);

    useEffect(() => {
        if (clusters.length > 0) probeAll(clusters);
    }, [clusters]);

    async function handleRegister(e: FormEvent) {
        e.preventDefault();
        const body = { ...form, ca_cert_pem: form.ca_cert_pem || undefined };
        try {
            const res = await fetch(`${CP_URL}/clusters`, {
                method: 'POST',
                headers,
                body: JSON.stringify(body),
            });
            if (!res.ok) {
                const err = await res.json();
                alert(err.detail || 'Registration failed');
                return;
            }
            setShowForm(false);
            setForm({ name: '', api_server_url: '', bearer_token: '', ca_cert_pem: '', environment: 'production' });
            fetchClusters();
        } catch { alert('Failed to register cluster'); }
    }

    async function handleDeregister(id: string, name: string) {
        if (!confirm(`Deregister cluster "${name}"?`)) return;
        await fetch(`${CP_URL}/clusters/${id}`, { method: 'DELETE', headers });
        fetchClusters();
    }

    function HealthBadge({ id }: { id: string }) {
        const h = health[id];
        if (probing === id) return (
            <span className="flex items-center gap-1 text-xs text-gray-500">
                <RefreshCw className="w-3 h-3 animate-spin" /> Probing…
            </span>
        );
        if (!h) return <span className="text-xs text-gray-600">—</span>;
        if (h.reachable) return (
            <span className="flex items-center gap-1 text-xs text-green-400">
                <CheckCircle className="w-3 h-3" />
                {h.node_count} nodes · v{h.server_version}
            </span>
        );
        return (
            <span className="flex items-center gap-1 text-xs text-red-400" title={h.error || ''}>
                <XCircle className="w-3 h-3" /> Unreachable
            </span>
        );
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white font-mono tracking-tight">
                        Multi-Cluster
                    </h1>
                    <p className="text-sm text-gray-500 mt-1">
                        Register and monitor remote Kubernetes clusters · EE feature
                    </p>
                </div>
                <div className="flex gap-2">
                    <button
                        onClick={() => fetchClusters().then(() => probeAll(clusters))}
                        className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm text-gray-300 transition-colors"
                    >
                        <RefreshCw className="w-4 h-4" /> Refresh
                    </button>
                    <button
                        onClick={() => setShowForm(v => !v)}
                        className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-400 text-sm font-mono rounded-lg transition-colors"
                    >
                        <Plus className="w-4 h-4" /> Register Cluster
                    </button>
                </div>
            </div>

            {/* Registration form */}
            {showForm && (
                <div className="bg-gray-900/60 border border-gray-700 rounded-lg p-6">
                    <h2 className="text-base font-semibold text-white mb-4">Register Remote Cluster</h2>
                    <form onSubmit={handleRegister} className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Name</label>
                            <input required value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                                placeholder="prod-us-east-1"
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Environment</label>
                            <select value={form.environment} onChange={e => setForm(f => ({ ...f, environment: e.target.value }))}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                                <option value="production">Production</option>
                                <option value="staging">Staging</option>
                                <option value="dev">Dev</option>
                            </select>
                        </div>
                        <div className="col-span-2">
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">API Server URL</label>
                            <input required value={form.api_server_url} onChange={e => setForm(f => ({ ...f, api_server_url: e.target.value }))}
                                placeholder="https://1.2.3.4:6443"
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500" />
                        </div>
                        <div className="col-span-2">
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Service Account Bearer Token</label>
                            <textarea required value={form.bearer_token} onChange={e => setForm(f => ({ ...f, bearer_token: e.target.value }))}
                                rows={3} placeholder="eyJhbGciO..."
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-cyan-500 resize-none" />
                        </div>
                        <div className="col-span-2">
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">CA Certificate (PEM) — optional</label>
                            <textarea value={form.ca_cert_pem} onChange={e => setForm(f => ({ ...f, ca_cert_pem: e.target.value }))}
                                rows={3} placeholder="-----BEGIN CERTIFICATE-----"
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-cyan-500 resize-none" />
                        </div>
                        <div className="col-span-2 flex gap-3 justify-end">
                            <button type="button" onClick={() => setShowForm(false)}
                                className="px-4 py-2 bg-gray-800 text-gray-400 rounded-lg text-sm hover:text-white transition-colors">
                                Cancel
                            </button>
                            <button type="submit"
                                className="px-5 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-400 text-sm font-mono rounded-lg transition-colors">
                                Register
                            </button>
                        </div>
                    </form>
                </div>
            )}

            {/* Cluster cards */}
            {loading ? (
                <div className="text-gray-600 text-sm">Loading…</div>
            ) : clusters.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-gray-600">
                    <Server className="w-12 h-12 mb-3 opacity-30" />
                    <p className="text-sm">No clusters registered yet.</p>
                    <p className="text-xs mt-1">Click "Register Cluster" to add a remote cluster.</p>
                </div>
            ) : (
                <div className="grid grid-cols-1 gap-4">
                    {clusters.map(cluster => (
                        <div key={cluster.id} className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-5 flex items-center gap-6">
                            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center shrink-0">
                                <Server className="w-5 h-5 text-cyan-400" />
                            </div>
                            <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                    <span className="text-white font-semibold font-mono">{cluster.name}</span>
                                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${ENV_COLOR[cluster.environment] || 'text-gray-400 border-gray-700 bg-gray-800'}`}>
                                        {cluster.environment}
                                    </span>
                                    {!cluster.active && (
                                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border text-gray-500 border-gray-700 bg-gray-900">
                                            deregistered
                                        </span>
                                    )}
                                </div>
                                <p className="text-xs text-gray-500 font-mono mt-0.5 truncate">{cluster.api_server_url}</p>
                                <div className="mt-1">
                                    <HealthBadge id={cluster.id} />
                                </div>
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                                <button onClick={() => probeHealth(cluster.id)}
                                    className="p-2 hover:bg-gray-700 rounded-lg text-gray-500 hover:text-white transition-colors" title="Re-probe">
                                    <RefreshCw className="w-4 h-4" />
                                </button>
                                <button onClick={() => handleDeregister(cluster.id, cluster.name)}
                                    className="p-2 hover:bg-red-500/10 rounded-lg text-gray-500 hover:text-red-400 transition-colors" title="Deregister">
                                    <Trash2 className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}
