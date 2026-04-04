"use client";
import { useEffect, useState } from 'react';
import { useAuth } from '../../components/AuthContext';
import { CheckCircle, XCircle, Clock, ShieldAlert } from 'lucide-react';

const CP_URL = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL || 'http://localhost:8001';

const STATE_STYLE: Record<string, string> = {
    Pending:  'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    Approved: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    Active:   'bg-green-500/10 text-green-400 border-green-500/30',
    Denied:   'bg-red-500/10 text-red-400 border-red-500/30',
    Expired:  'bg-gray-700 text-gray-500 border-gray-700',
};

export default function AccessPage() {
    const { token, user } = useAuth();
    const [requests, setRequests] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [acting, setActing] = useState<string | null>(null);
    const [formData, setFormData] = useState({
        namespace: 'default',
        target_role: 'view',
        duration: '1h',
        reason: '',
    });

    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
    const isAdmin = user?.role === 'admin';

    const fetchRequests = async () => {
        if (!token) return;
        try {
            const res = await fetch(`${CP_URL}/jit/requests`, { headers });
            const data = await res.json();
            setRequests(Array.isArray(data) ? data : []);
        } catch { setRequests([]); }
        finally { setLoading(false); }
    };

    useEffect(() => { fetchRequests(); }, [token]);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const res = await fetch(`${CP_URL}/jit/request`, {
                method: 'POST',
                headers,
                body: JSON.stringify(formData),
            });
            if (res.ok) {
                setFormData({ ...formData, reason: '' });
                fetchRequests();
            } else {
                const err = await res.json();
                alert(`Error: ${err.detail}`);
            }
        } catch { alert('Failed to submit request'); }
    };

    const handleApprove = async (name: string) => {
        setActing(name);
        try {
            await fetch(`${CP_URL}/jit/requests/${name}/approve`, { method: 'POST', headers });
            fetchRequests();
        } finally { setActing(null); }
    };

    const handleDeny = async (name: string) => {
        const reason = prompt('Reason for denial (optional):') ?? undefined;
        setActing(name);
        try {
            await fetch(
                `${CP_URL}/jit/requests/${name}/deny${reason ? `?reason=${encodeURIComponent(reason)}` : ''}`,
                { method: 'POST', headers },
            );
            fetchRequests();
        } finally { setActing(null); }
    };

    const handleDelete = async (name: string) => {
        if (!confirm('Retract this request?')) return;
        await fetch(`${CP_URL}/jit/requests/${name}`, { method: 'DELETE', headers });
        fetchRequests();
    };

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-2xl font-bold text-white font-mono tracking-tight">JIT Access</h1>
                <p className="text-sm text-gray-500 mt-1">
                    Request time-bound Kubernetes access · requires admin approval
                </p>
            </div>

            <div className="grid grid-cols-3 gap-6">
                {/* Request Form */}
                <div className="col-span-1 bg-gray-900/50 border border-gray-800/60 rounded-lg p-5">
                    <h2 className="text-sm font-semibold text-white mb-4">New Request</h2>
                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Namespace</label>
                            <input type="text" value={formData.namespace}
                                onChange={e => setFormData({ ...formData, namespace: e.target.value })}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Role</label>
                            <select value={formData.target_role}
                                onChange={e => setFormData({ ...formData, target_role: e.target.value })}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                                <option value="view">View (Read-Only)</option>
                                <option value="edit">Edit (Read-Write)</option>
                                <option value="admin">Admin (Full Control)</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Duration</label>
                            <select value={formData.duration}
                                onChange={e => setFormData({ ...formData, duration: e.target.value })}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500">
                                <option value="30m">30 Minutes</option>
                                <option value="1h">1 Hour</option>
                                <option value="4h">4 Hours</option>
                                <option value="8h">8 Hours</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Reason</label>
                            <textarea required value={formData.reason}
                                onChange={e => setFormData({ ...formData, reason: e.target.value })}
                                placeholder="e.g. Debugging production pod crash"
                                rows={3}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 resize-none" />
                        </div>
                        <button type="submit"
                            className="w-full py-2 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-400 text-sm font-mono rounded-lg transition-colors">
                            Submit Request
                        </button>
                    </form>
                </div>

                {/* Request List */}
                <div className="col-span-2 bg-gray-900/50 border border-gray-800/60 rounded-lg p-5">
                    <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                        <Clock className="w-4 h-4 text-yellow-400" />
                        {isAdmin ? 'All Requests' : 'Your Requests'}
                    </h2>
                    {loading ? (
                        <p className="text-gray-600 text-sm">Loading…</p>
                    ) : requests.length === 0 ? (
                        <p className="text-gray-600 text-sm">No requests found.</p>
                    ) : (
                        <div className="space-y-3">
                            {requests.map((req: any, i) => {
                                const name = req.metadata?.name;
                                const state = req.status?.state || 'Pending';
                                const isOwn = req.spec?.requestor === user?.username;
                                return (
                                    <div key={i} className="flex items-start gap-3 p-3 bg-black/30 border border-gray-800 rounded-lg">
                                        <ShieldAlert className="w-4 h-4 mt-0.5 text-gray-500 shrink-0" />
                                        <div className="flex-1 min-w-0">
                                            <div className="flex items-center gap-2 flex-wrap">
                                                <span className="text-white text-sm font-mono">{req.spec?.requestor}</span>
                                                <span className="text-gray-500 text-xs">→</span>
                                                <span className="text-xs font-mono bg-gray-800 px-1.5 py-0.5 rounded text-gray-300">
                                                    {req.spec?.roleRef?.name}
                                                </span>
                                                <span className="text-gray-500 text-xs">in</span>
                                                <span className="text-cyan-400 text-xs font-mono">{req.spec?.namespace}</span>
                                                <span className="text-gray-500 text-xs">for {req.spec?.duration}</span>
                                            </div>
                                            <p className="text-xs text-gray-500 mt-1 truncate">{req.spec?.reason}</p>
                                            {req.status?.expiresAt && (
                                                <p className="text-[10px] text-gray-600 mt-0.5">
                                                    Expires: {new Date(req.status.expiresAt).toLocaleTimeString()}
                                                </p>
                                            )}
                                            {req.status?.denialReason && (
                                                <p className="text-[10px] text-red-400 mt-0.5">
                                                    Denied: {req.status.denialReason}
                                                </p>
                                            )}
                                        </div>
                                        <div className="flex items-center gap-2 shrink-0">
                                            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${STATE_STYLE[state] || STATE_STYLE['Pending']}`}>
                                                {state}
                                            </span>
                                            {isAdmin && state === 'Pending' && (
                                                <>
                                                    <button onClick={() => handleApprove(name)} disabled={acting === name}
                                                        className="p-1.5 hover:bg-green-500/10 rounded text-gray-500 hover:text-green-400 transition-colors disabled:opacity-50" title="Approve">
                                                        <CheckCircle className="w-4 h-4" />
                                                    </button>
                                                    <button onClick={() => handleDeny(name)} disabled={acting === name}
                                                        className="p-1.5 hover:bg-red-500/10 rounded text-gray-500 hover:text-red-400 transition-colors disabled:opacity-50" title="Deny">
                                                        <XCircle className="w-4 h-4" />
                                                    </button>
                                                </>
                                            )}
                                            {(isOwn || isAdmin) && state === 'Pending' && (
                                                <button onClick={() => handleDelete(name)}
                                                    className="text-[10px] text-gray-600 hover:text-gray-400 transition-colors px-1">
                                                    retract
                                                </button>
                                            )}
                                        </div>
                                    </div>
                                );
                            })}
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
}
