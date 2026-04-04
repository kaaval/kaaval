"use client";

import { useEffect, useState, FormEvent } from 'react';
import { useAuth } from '../../components/AuthContext';
import { Shield, Save, CheckCircle, AlertCircle } from 'lucide-react';

const CP_URL = process.env.NEXT_PUBLIC_CONTROL_PLANE_URL || 'http://localhost:8001';

interface OIDCConfig {
    id: string;
    provider_name: string;
    issuer_url: string;
    client_id: string;
    redirect_uri: string;
    scopes: string;
    enabled: boolean;
    created_at: string;
}

export default function SSOPage() {
    const { token, user } = useAuth();
    const [config, setConfig] = useState<OIDCConfig | null>(null);
    const [loading, setLoading] = useState(true);
    const [saving, setSaving] = useState(false);
    const [saved, setSaved] = useState(false);
    const [error, setError] = useState('');

    const [form, setForm] = useState({
        provider_name: '',
        issuer_url: '',
        client_id: '',
        client_secret: '',
        redirect_uri: `${typeof window !== 'undefined' ? window.location.origin : ''}/api/auth/oidc/callback`,
        scopes: 'openid email profile',
        attribute_mapping: '{}',
    });

    const headers = { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };

    async function fetchConfig() {
        setLoading(true);
        try {
            const res = await fetch(`${CP_URL}/auth/oidc/configure`, { headers });
            if (res.ok) {
                const data: OIDCConfig = await res.json();
                setConfig(data);
                setForm(f => ({
                    ...f,
                    provider_name: data.provider_name,
                    issuer_url: data.issuer_url,
                    client_id: data.client_id,
                    redirect_uri: data.redirect_uri,
                    scopes: data.scopes,
                }));
            }
        } catch { /* not configured yet */ }
        finally { setLoading(false); }
    }

    useEffect(() => {
        if (!token) return;
        fetchConfig();
    }, [token]);

    async function handleSave(e: FormEvent) {
        e.preventDefault();
        setSaving(true);
        setError('');
        setSaved(false);
        try {
            let mapping = undefined;
            try { mapping = JSON.parse(form.attribute_mapping); } catch { /* ignore */ }
            const res = await fetch(`${CP_URL}/auth/oidc/configure`, {
                method: 'POST',
                headers,
                body: JSON.stringify({
                    provider_name: form.provider_name,
                    issuer_url: form.issuer_url,
                    client_id: form.client_id,
                    client_secret: form.client_secret,
                    redirect_uri: form.redirect_uri,
                    scopes: form.scopes,
                    attribute_mapping: mapping,
                }),
            });
            if (!res.ok) {
                const err = await res.json();
                setError(err.detail || 'Save failed');
                return;
            }
            const data = await res.json();
            setConfig(data);
            setSaved(true);
            setForm(f => ({ ...f, client_secret: '' })); // clear secret from form
        } catch (e: unknown) {
            setError(e instanceof Error ? e.message : 'Save failed');
        } finally {
            setSaving(false);
        }
    }

    const isAdmin = user?.role === 'admin';

    return (
        <div className="space-y-6 max-w-3xl">
            <div>
                <h1 className="text-2xl font-bold text-white font-mono tracking-tight">SSO / OIDC</h1>
                <p className="text-sm text-gray-500 mt-1">
                    Configure a generic OIDC provider for single sign-on · EE feature
                </p>
            </div>

            {!isAdmin && (
                <div className="flex items-center gap-2 p-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm">
                    <AlertCircle className="w-4 h-4 shrink-0" />
                    Admin role required to configure SSO.
                </div>
            )}

            {/* Current status */}
            <div className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-5">
                <h2 className="text-sm font-semibold text-white flex items-center gap-2 mb-3">
                    <Shield className="w-4 h-4 text-purple-400" /> Current Configuration
                </h2>
                {loading ? (
                    <p className="text-sm text-gray-600">Loading…</p>
                ) : config ? (
                    <div className="space-y-1 text-sm font-mono">
                        <div className="flex gap-3">
                            <span className="text-gray-500 w-32">Provider</span>
                            <span className="text-white">{config.provider_name}</span>
                        </div>
                        <div className="flex gap-3">
                            <span className="text-gray-500 w-32">Issuer URL</span>
                            <span className="text-cyan-400">{config.issuer_url}</span>
                        </div>
                        <div className="flex gap-3">
                            <span className="text-gray-500 w-32">Client ID</span>
                            <span className="text-gray-300">{config.client_id}</span>
                        </div>
                        <div className="flex gap-3">
                            <span className="text-gray-500 w-32">Redirect URI</span>
                            <span className="text-gray-300 text-xs">{config.redirect_uri}</span>
                        </div>
                        <div className="flex gap-3">
                            <span className="text-gray-500 w-32">Status</span>
                            <span className={config.enabled ? 'text-green-400' : 'text-gray-500'}>
                                {config.enabled ? 'Enabled' : 'Disabled'}
                            </span>
                        </div>
                        <div className="mt-3 pt-3 border-t border-gray-800">
                            <p className="text-xs text-gray-600">
                                Login URL:&nbsp;
                                <span className="text-cyan-400 font-mono">
                                    {CP_URL}/auth/oidc/login
                                </span>
                            </p>
                        </div>
                    </div>
                ) : (
                    <p className="text-sm text-gray-600">Not configured — fill out the form below.</p>
                )}
            </div>

            {/* Configuration form */}
            <div className="bg-gray-900/50 border border-gray-800/60 rounded-lg p-5">
                <h2 className="text-sm font-semibold text-white mb-4">
                    {config ? 'Update OIDC Configuration' : 'Configure OIDC Provider'}
                </h2>
                <form onSubmit={handleSave} className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Provider Name</label>
                            <input required value={form.provider_name} onChange={e => setForm(f => ({ ...f, provider_name: e.target.value }))}
                                placeholder="Okta" disabled={!isAdmin}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500 disabled:opacity-50" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Scopes</label>
                            <input value={form.scopes} onChange={e => setForm(f => ({ ...f, scopes: e.target.value }))}
                                disabled={!isAdmin}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50" />
                        </div>
                    </div>
                    <div>
                        <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Issuer URL</label>
                        <input required value={form.issuer_url} onChange={e => setForm(f => ({ ...f, issuer_url: e.target.value }))}
                            placeholder="https://your-okta-domain.okta.com" disabled={!isAdmin}
                            className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50" />
                        <p className="text-[10px] text-gray-600 mt-1">
                            Discovery document will be fetched from &lt;issuer_url&gt;/.well-known/openid-configuration
                        </p>
                    </div>
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Client ID</label>
                            <input required value={form.client_id} onChange={e => setForm(f => ({ ...f, client_id: e.target.value }))}
                                disabled={!isAdmin}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50" />
                        </div>
                        <div>
                            <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">
                                Client Secret {config && '(leave blank to keep existing)'}
                            </label>
                            <input type="password" value={form.client_secret}
                                onChange={e => setForm(f => ({ ...f, client_secret: e.target.value }))}
                                required={!config} disabled={!isAdmin}
                                className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50" />
                        </div>
                    </div>
                    <div>
                        <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">Redirect URI</label>
                        <input value={form.redirect_uri} onChange={e => setForm(f => ({ ...f, redirect_uri: e.target.value }))}
                            disabled={!isAdmin}
                            className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50" />
                    </div>
                    <div>
                        <label className="block text-xs text-gray-500 mb-1 font-mono uppercase">
                            Attribute Mapping (JSON) — optional
                        </label>
                        <input value={form.attribute_mapping}
                            onChange={e => setForm(f => ({ ...f, attribute_mapping: e.target.value }))}
                            placeholder='{"email": "preferred_username"}' disabled={!isAdmin}
                            className="w-full bg-black/40 border border-gray-700 rounded px-3 py-2 text-sm text-white font-mono focus:outline-none focus:border-purple-500 disabled:opacity-50" />
                    </div>

                    {error && (
                        <div className="flex items-center gap-2 text-red-400 text-sm p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
                            <AlertCircle className="w-4 h-4 shrink-0" /> {error}
                        </div>
                    )}
                    {saved && (
                        <div className="flex items-center gap-2 text-green-400 text-sm p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
                            <CheckCircle className="w-4 h-4 shrink-0" /> Configuration saved.
                        </div>
                    )}

                    <div className="flex justify-end pt-2">
                        <button type="submit" disabled={saving || !isAdmin}
                            className="flex items-center gap-2 px-5 py-2 bg-purple-500/20 hover:bg-purple-500/30 border border-purple-500/40 text-purple-400 text-sm font-mono rounded-lg transition-colors disabled:opacity-50">
                            <Save className="w-4 h-4" />
                            {saving ? 'Saving…' : 'Save Configuration'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
