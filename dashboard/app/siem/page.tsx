"use client";

import { useEffect, useState, FormEvent } from 'react';
import { useAuth } from '../../components/AuthContext';
import { Plus, Trash2, Play, CheckCircle, XCircle, Zap } from 'lucide-react';

const CP_URL = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL || 'http://localhost:8001';

interface SIEMConfig {
    id: string;
    name: string;
    siem_type: string;
    endpoint_url: string;
    filters: Record<string, unknown> | null;
    enabled: boolean;
    last_forwarded_at: string | null;
    created_at: string;
}

const TYPE_LABEL: Record<string, { label: string; color: string }> = {
    splunk_hec: { label: 'Splunk HEC',     color: 'text-orange-400 border-orange-500/30 bg-orange-500/10' },
    elastic:    { label: 'Elasticsearch',  color: 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10' },
    webhook:    { label: 'Webhook',        color: 'text-blue-400 border-blue-500/30 bg-blue-500/10' },
};

export default function SIEMPage() {
    const { token } = useAuth();
    const [configs, setConfigs] = useState<SIEMConfig[]>([]);
    const [loading, setLoading] = useState(true);
    const [showForm, setShowForm] = useState(false);
    const [testResult, setTestResult] = useState<Record<string, { status: string; http_status?: number }>>({});

    const [form, setForm] = useState({
        name: '',
        siem_type: 'webhook',
        endpoint_url: '',
        api_key: '',
        filters: '',
    });

    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    async function fetchConfigs() {
        setLoading(true);
        try {
            const res = await fetch(`${CP_URL}/siem`, { headers });
            if (res.ok) setConfigs(await res.json());
        } catch { setConfigs([]); }
        finally { setLoading(false); }
    }

    useEffect(() => { if (token) fetchConfigs(); }, [token]);

    async function handleCreate(e: FormEvent) {
        e.preventDefault();
        let filters: unknown = undefined;
        if (form.filters.trim()) {
            try { filters = JSON.parse(form.filters); } catch { alert('Filters must be valid JSON'); return; }
        }
        const res = await fetch(`${CP_URL}/siem`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
                name: form.name,
                siem_type: form.siem_type,
                endpoint_url: form.endpoint_url,
                api_key: form.api_key || undefined,
                filters: filters || undefined,
            }),
        });
        if (res.ok) {
            setShowForm(false);
            setForm({ name: '', siem_type: 'webhook', endpoint_url: '', api_key: '', filters: '' });
            fetchConfigs();
        } else {
            const err = await res.json();
            alert(err.detail || 'Failed to create config');
        }
    }

    async function handleDelete(id: string, name: string) {
        if (!confirm(`Delete SIEM integration "${name}"?`)) return;
        await fetch(`${CP_URL}/siem/${id}`, { method: 'DELETE', headers });
        fetchConfigs();
    }

    async function handleTest(id: string) {
        const res = await fetch(`${CP_URL}/siem/${id}/test`, { method: 'POST', headers });
        const data = await res.json();
        setTestResult(prev => ({ ...prev, [id]: data }));
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white font-mono tracking-tight">SIEM Integrations</h1>
                    <p className="text-sm text-gray-500 mt-1">
                        Forward audit events to Splunk, Elasticsearch, or any webhook · EE feature
                    </p>
                </div>
                <button onClick={() => setShowForm(v => !v)}
                    className="flex items-center gap-2 px-4 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-400 text-sm font-mono rounded-lg transition-colors">
                    <Plus className="w-4 h-4" /> Add Integration
                </button>
            </div>

            {/* Create form */}
            {showForm && (
                <div className="bg-gray-900/60 border border-gray-700 rounded-lg p-6">
                    <h2 className="text-sm font-semibold text-white mb-4">New SIEM Integration</h2>
                    <form onSubmit={handleCreate} className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-[10px] text-gray-500 mb-1 font-mono uppercase">Name</label>
                            <input required value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
                                placeholder="prod-splunk"
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500" />
                        </div>
                        <div>
                            <label className="block text-[10px] text-gray-500 mb-1 font-mono uppercase">Type</label>
                            <select value={form.siem_type} onChange={e => setForm(f => ({ ...f, siem_type: e.target.value }))}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                                <option value="webhook">Webhook (generic)</option>
                                <option value="splunk_hec">Splunk HEC</option>
                                <option value="elastic">Elasticsearch</option>
                            </select>
                        </div>
                        <div className="col-span-2">
                            <label className="block text-[10px] text-gray-500 mb-1 font-mono uppercase">Endpoint URL</label>
                            <input required value={form.endpoint_url} onChange={e => setForm(f => ({ ...f, endpoint_url: e.target.value }))}
                                placeholder="https://splunk.example.com:8088/services/collector/event"
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500" />
                        </div>
                        <div>
                            <label className="block text-[10px] text-gray-500 mb-1 font-mono uppercase">
                                {form.siem_type === 'splunk_hec' ? 'HEC Token' : form.siem_type === 'elastic' ? 'API Key' : 'Bearer Token (optional)'}
                            </label>
                            <input type="password" value={form.api_key} onChange={e => setForm(f => ({ ...f, api_key: e.target.value }))}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-cyan-500" />
                        </div>
                        <div>
                            <label className="block text-[10px] text-gray-500 mb-1 font-mono uppercase">
                                Filters JSON (optional)
                            </label>
                            <input value={form.filters} onChange={e => setForm(f => ({ ...f, filters: e.target.value }))}
                                placeholder='{"actions": ["jit.approve","jit.deny"]}'
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-cyan-500" />
                        </div>
                        <div className="col-span-2 flex gap-3 justify-end">
                            <button type="button" onClick={() => setShowForm(false)}
                                className="px-4 py-2 bg-gray-800 text-gray-400 rounded-lg text-sm hover:text-white">Cancel</button>
                            <button type="submit"
                                className="px-5 py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-400 text-sm font-mono rounded-lg transition-colors">
                                Create
                            </button>
                        </div>
                    </form>
                </div>
            )}

            {/* Config cards */}
            {loading ? (
                <p className="text-gray-600 text-sm">Loading…</p>
            ) : configs.length === 0 ? (
                <div className="flex flex-col items-center py-16 text-gray-600">
                    <Zap className="w-10 h-10 mb-3 opacity-30" />
                    <p className="text-sm">No SIEM integrations configured.</p>
                    <p className="text-xs mt-1">Audit events are stored locally — add a SIEM to forward them externally.</p>
                </div>
            ) : (
                <div className="space-y-3">
                    {configs.map(cfg => {
                        const typeInfo = TYPE_LABEL[cfg.siem_type] || { label: cfg.siem_type, color: 'text-gray-400 border-gray-700 bg-gray-800' };
                        const test = testResult[cfg.id];
                        return (
                            <div key={cfg.id} className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-5 flex items-center gap-5">
                                <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                        <span className="text-white font-semibold font-mono">{cfg.name}</span>
                                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${typeInfo.color}`}>
                                            {typeInfo.label}
                                        </span>
                                        {!cfg.enabled && (
                                            <span className="text-[10px] font-mono text-gray-600">disabled</span>
                                        )}
                                    </div>
                                    <p className="text-xs text-gray-500 font-mono mt-0.5 truncate">{cfg.endpoint_url}</p>
                                    <p className="text-[10px] text-gray-700 mt-1">
                                        {cfg.last_forwarded_at
                                            ? `Last forwarded: ${new Date(cfg.last_forwarded_at).toLocaleString()}`
                                            : 'Not yet forwarded'}
                                    </p>
                                    {test && (
                                        <div className={`flex items-center gap-1 text-[10px] mt-1 ${test.status === 'ok' ? 'text-green-400' : 'text-red-400'}`}>
                                            {test.status === 'ok'
                                                ? <><CheckCircle className="w-3 h-3" /> Test OK (HTTP {test.http_status})</>
                                                : <><XCircle className="w-3 h-3" /> Test failed</>
                                            }
                                        </div>
                                    )}
                                </div>
                                <div className="flex items-center gap-2 shrink-0">
                                    <button onClick={() => handleTest(cfg.id)}
                                        className="flex items-center gap-1 px-3 py-1.5 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-xs text-gray-400 hover:text-white transition-colors">
                                        <Play className="w-3 h-3" /> Test
                                    </button>
                                    <button onClick={() => handleDelete(cfg.id, cfg.name)}
                                        className="p-2 hover:bg-red-500/10 rounded-lg text-gray-500 hover:text-red-400 transition-colors">
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
