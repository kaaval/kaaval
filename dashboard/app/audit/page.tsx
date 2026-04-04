"use client";

import { useEffect, useState, FormEvent } from 'react';
import { useAuth } from '../../components/AuthContext';
import { Search, RefreshCw, CheckCircle, XCircle, Filter } from 'lucide-react';

const CP_URL = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL || 'http://localhost:8001';

interface AuditEntry {
    id: string;
    actor: string;
    actor_ip: string | null;
    action: string;
    resource_type: string | null;
    resource_id: string | null;
    outcome: string;
    detail: Record<string, unknown> | null;
    created_at: string;
}

const ACTION_COLOR: Record<string, string> = {
    'jit.approve':       'text-green-400',
    'jit.deny':          'text-red-400',
    'jit.request':       'text-blue-400',
    'siem.test':         'text-purple-400',
    'compliance.export': 'text-yellow-400',
};

export default function AuditPage() {
    const { token } = useAuth();
    const [entries, setEntries] = useState<AuditEntry[]>([]);
    const [stats, setStats] = useState<Record<string, Record<string, number>>>({});
    const [loading, setLoading] = useState(true);

    const [filters, setFilters] = useState({
        actor: '',
        action: '',
        outcome: '',
        since: '',
    });

    const headers = { Authorization: `Bearer ${token}` };

    async function fetchLogs() {
        setLoading(true);
        try {
            const params = new URLSearchParams();
            if (filters.actor)   params.set('actor', filters.actor);
            if (filters.action)  params.set('action', filters.action);
            if (filters.outcome) params.set('outcome', filters.outcome);
            if (filters.since)   params.set('since', new Date(filters.since).toISOString());
            params.set('limit', '200');

            const [logsRes, statsRes] = await Promise.all([
                fetch(`${CP_URL}/audit?${params}`, { headers }),
                fetch(`${CP_URL}/audit/stats`, { headers }),
            ]);
            if (logsRes.ok)  setEntries(await logsRes.json());
            if (statsRes.ok) setStats(await statsRes.json());
        } catch { /* EE not licensed or unavailable */ }
        finally { setLoading(false); }
    }

    useEffect(() => { if (token) fetchLogs(); }, [token]);

    function handleFilter(e: FormEvent) {
        e.preventDefault();
        fetchLogs();
    }

    const totalEvents = entries.length;
    const failureCount = entries.filter(e => e.outcome === 'failure').length;

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white font-mono tracking-tight">Audit Log</h1>
                    <p className="text-sm text-gray-500 mt-1">
                        Structured log of all privileged actions · EE feature · append-only
                    </p>
                </div>
                <button onClick={fetchLogs}
                    className="flex items-center gap-2 px-3 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-sm text-gray-300 transition-colors">
                    <RefreshCw className="w-4 h-4" /> Refresh
                </button>
            </div>

            {/* Stats bar */}
            <div className="grid grid-cols-4 gap-4">
                {[
                    { label: 'Total Events', value: totalEvents, color: 'text-white' },
                    { label: 'Failures', value: failureCount, color: 'text-red-400' },
                    { label: 'Unique Actors', value: new Set(entries.map(e => e.actor)).size, color: 'text-cyan-400' },
                    { label: 'Action Types', value: Object.keys(stats).length, color: 'text-purple-400' },
                ].map(s => (
                    <div key={s.label} className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-4">
                        <p className="text-xs text-gray-600 font-mono uppercase tracking-wider">{s.label}</p>
                        <p className={`text-2xl font-bold font-mono mt-1 ${s.color}`}>{s.value}</p>
                    </div>
                ))}
            </div>

            {/* Filters */}
            <form onSubmit={handleFilter}
                className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-4 flex flex-wrap gap-3 items-end">
                <div>
                    <label className="block text-[10px] text-gray-600 font-mono uppercase mb-1">Actor</label>
                    <input value={filters.actor} onChange={e => setFilters(f => ({ ...f, actor: e.target.value }))}
                        placeholder="username"
                        className="bg-black/40 border border-gray-700 rounded px-3 py-1.5 text-sm text-white w-36 focus:outline-none focus:border-cyan-500 font-mono" />
                </div>
                <div>
                    <label className="block text-[10px] text-gray-600 font-mono uppercase mb-1">Action</label>
                    <input value={filters.action} onChange={e => setFilters(f => ({ ...f, action: e.target.value }))}
                        placeholder="jit. or jit.approve"
                        className="bg-black/40 border border-gray-700 rounded px-3 py-1.5 text-sm text-white w-40 focus:outline-none focus:border-cyan-500 font-mono" />
                </div>
                <div>
                    <label className="block text-[10px] text-gray-600 font-mono uppercase mb-1">Outcome</label>
                    <select value={filters.outcome} onChange={e => setFilters(f => ({ ...f, outcome: e.target.value }))}
                        className="bg-black/40 border border-gray-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-500">
                        <option value="">All</option>
                        <option value="success">Success</option>
                        <option value="failure">Failure</option>
                    </select>
                </div>
                <div>
                    <label className="block text-[10px] text-gray-600 font-mono uppercase mb-1">Since</label>
                    <input type="datetime-local" value={filters.since}
                        onChange={e => setFilters(f => ({ ...f, since: e.target.value }))}
                        className="bg-black/40 border border-gray-700 rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-500" />
                </div>
                <button type="submit"
                    className="flex items-center gap-1.5 px-4 py-1.5 bg-cyan-500/20 border border-cyan-500/40 text-cyan-400 text-sm font-mono rounded-lg hover:bg-cyan-500/30 transition-colors">
                    <Filter className="w-3.5 h-3.5" /> Apply
                </button>
                <button type="button" onClick={() => { setFilters({ actor: '', action: '', outcome: '', since: '' }); }}
                    className="px-3 py-1.5 text-gray-600 hover:text-gray-400 text-sm transition-colors">
                    Clear
                </button>
            </form>

            {/* Log table */}
            {loading ? (
                <p className="text-gray-600 text-sm">Loading…</p>
            ) : entries.length === 0 ? (
                <p className="text-gray-600 text-sm">
                    No audit events found. Actions logged include JIT approvals, attestations, cluster registrations, and SSO changes.
                </p>
            ) : (
                <div className="bg-gray-900/50 border border-gray-800/60 rounded-lg overflow-hidden">
                    <table className="w-full text-xs font-mono">
                        <thead>
                            <tr className="border-b border-gray-800 bg-black/30">
                                {['Timestamp', 'Actor', 'Action', 'Resource', 'Outcome', 'Detail'].map(h => (
                                    <th key={h} className="px-4 py-2.5 text-left text-[10px] text-gray-600 uppercase tracking-wider">
                                        {h}
                                    </th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {entries.map(entry => (
                                <tr key={entry.id} className="border-b border-gray-900 hover:bg-gray-800/20">
                                    <td className="px-4 py-2 text-gray-500 whitespace-nowrap">
                                        {new Date(entry.created_at).toLocaleString()}
                                    </td>
                                    <td className="px-4 py-2 text-white">{entry.actor}</td>
                                    <td className={`px-4 py-2 font-semibold ${ACTION_COLOR[entry.action] || 'text-gray-300'}`}>
                                        {entry.action}
                                    </td>
                                    <td className="px-4 py-2 text-gray-400">
                                        {entry.resource_type && (
                                            <span>
                                                <span className="text-gray-600">{entry.resource_type}/</span>
                                                {entry.resource_id}
                                            </span>
                                        )}
                                    </td>
                                    <td className="px-4 py-2">
                                        {entry.outcome === 'success'
                                            ? <span className="flex items-center gap-1 text-green-400"><CheckCircle className="w-3 h-3" />ok</span>
                                            : <span className="flex items-center gap-1 text-red-400"><XCircle className="w-3 h-3" />fail</span>
                                        }
                                    </td>
                                    <td className="px-4 py-2 text-gray-600 max-w-xs truncate">
                                        {entry.detail ? JSON.stringify(entry.detail) : ''}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
