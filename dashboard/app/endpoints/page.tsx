"use client";

import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { RefreshCw, Monitor, Server, Wifi, WifiOff } from 'lucide-react';

import { useAuth } from '../../components/AuthContext';

interface Endpoint {
    id: string;
    hostname: string;
    ip_address: string;
    os_info: string;
    status: string;
    last_seen: string;
}

export default function EndpointsPage() {
    const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
    const [loading, setLoading] = useState(true);
    const [lastUpdated, setLastUpdated] = useState<Date>(new Date());
    const { token } = useAuth();

    const fetchEndpoints = async () => {
        if (!token) return;
        try {
            const res = await axios.get('http://localhost:8001/api/v1/endpoints', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            setEndpoints(res.data);
            setLastUpdated(new Date());
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchEndpoints();
        const interval = setInterval(fetchEndpoints, 5000); // Auto-refresh
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="p-8">
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold font-mono uppercase tracking-tight text-primary mb-2">Endpoint Security</h1>
                    <p className="text-gray-400">Real-time status of enrolled agents and fleet telemetry.</p>
                </div>
                <div className="flex items-center gap-4">
                    <span className="text-xs font-mono text-gray-500">
                        Updated: {lastUpdated.toLocaleTimeString()}
                    </span>
                    <button
                        onClick={fetchEndpoints}
                        className="p-2 bg-gray-800 hover:bg-gray-700 rounded-full transition-colors border border-gray-700"
                    >
                        <RefreshCw size={18} className={loading ? "animate-spin" : ""} />
                    </button>
                    <div className="bg-blue-900/30 border border-blue-800 px-4 py-2 rounded-lg flex items-center gap-2">
                        <Monitor size={18} className="text-blue-400" />
                        <span className="text-2xl font-bold font-mono text-blue-100">{endpoints.length}</span>
                        <span className="text-xs uppercase tracking-wider text-blue-300 font-semibold">Online</span>
                    </div>
                </div>
            </div>

            <div className="bg-surface border border-border-color rounded-xl overflow-hidden backdrop-blur-sm">
                <table className="w-full text-left">
                    <thead className="bg-nav text-text-secondary text-xs uppercase font-mono tracking-wider">
                        <tr>
                            <th className="p-4">Hostname</th>
                            <th className="p-4">Status</th>
                            <th className="p-4">IP Address</th>
                            <th className="p-4">OS / Architecture</th>
                            <th className="p-4">Last Seen</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-border-color">
                        {endpoints.length === 0 ? (
                            <tr>
                                <td colSpan={5} className="p-8 text-center text-text-secondary italic">
                                    No agents enrolled. Run `./agent -token={'{TENANT_ID}'}` to connect.
                                </td>
                            </tr>
                        ) : (
                            endpoints.map((ep) => (
                                <tr key={ep.id} className="hover:bg-white/5 transition-colors">
                                    <td className="p-4 font-medium text-primary flex items-center gap-3">
                                        <Server size={16} className="text-text-secondary" />
                                        {ep.hostname}
                                    </td>
                                    <td className="p-4">
                                        <div className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold border ${ep.status === 'ONLINE' ? 'bg-emerald-950/50 text-emerald-400 border-emerald-900' : 'bg-red-950/50 text-red-400 border-red-900'}`}>
                                            {ep.status === 'ONLINE' ? <Wifi size={12} /> : <WifiOff size={12} />}
                                            {ep.status}
                                        </div>
                                    </td>
                                    <td className="p-4 font-mono text-sm text-primary">{ep.ip_address}</td>
                                    <td className="p-4 text-sm text-text-secondary">{ep.os_info}</td>
                                    <td className="p-4 font-mono text-xs text-text-secondary">
                                        {new Date(ep.last_seen).toLocaleString()}
                                    </td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
