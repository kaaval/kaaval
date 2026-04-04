"use client";

import React, { useState } from 'react';
import { useAuth } from '../../components/AuthContext';
import { Shield } from 'lucide-react';

export default function LoginPage() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const { login } = useAuth();
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const res = await fetch('http://localhost:8001/auth/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    username,
                    password,
                }),
            });

            if (!res.ok) {
                throw new Error('Invalid credentials');
            }

            const data = await res.json();
            // For prototype, we mock role extraction since backend token doesn't expose it in clear text 
            // (it is in JWT payload, but we don't have a decoder lib on frontend yet).
            // We'll just trust the username 'admin' -> 'admin' for now, or fetch /me if we added it.
            // Or we can rely on what the backend gave us? Backend just returns access_token.
            // Let's assume 'admin' if username is 'admin', else 'viewer'.

            const role = username === 'admin' ? 'admin' : 'viewer';
            login(data.access_token, username, role);
        } catch (err: any) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-background px-4">
            <div className="max-w-md w-full bg-card p-8 rounded-lg border border-border-color shadow-xl">
                <div className="flex flex-col items-center mb-6">
                    <div className="p-3 bg-blue-500/10 rounded-full mb-3">
                        <Shield size={40} className="text-neon-blue" />
                    </div>
                    <h1 className="text-2xl font-bold text-primary tracking-tight">Welcome to Provenance</h1>
                    <p className="text-text-secondary text-sm mt-1">Secure Cloud Infrastructure Discovery</p>
                </div>

                {error && (
                    <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 text-red-500 text-sm rounded flex items-center gap-2">
                        <span>Auth Failed:</span> {error}
                    </div>
                )}

                <form onSubmit={handleSubmit} className="space-y-4">
                    <div>
                        <label className="block text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Username</label>
                        <input
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            className="w-full bg-surface border border-border-color rounded p-2 text-primary focus:outline-none focus:border-neon-blue focus:ring-1 focus:ring-neon-blue transition-colors placeholder:text-text-secondary"
                            placeholder="admin"
                            required
                        />
                    </div>
                    <div>
                        <label className="block text-xs font-medium text-text-secondary uppercase tracking-wider mb-1">Password</label>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className="w-full bg-surface border border-border-color rounded p-2 text-primary focus:outline-none focus:border-neon-blue focus:ring-1 focus:ring-neon-blue transition-colors placeholder:text-text-secondary"
                            placeholder="••••••••"
                            required
                        />
                    </div>
                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed mt-2"
                    >
                        {loading ? 'Authenticating...' : 'Sign In'}
                    </button>
                </form>

                <div className="mt-6 text-center text-xs text-text-secondary">
                    Protected by Provenance RBAC &bull; v0.1.0
                </div>
            </div>
        </div>
    );
}
