"use client";
import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';
import { useAuth } from '../../components/AuthContext';
import { Plus, Trash2, Cloud, CheckCircle, AlertTriangle, RotateCw, Clock, Globe, Play, Activity } from 'lucide-react';

const ActivityFeed = dynamic(() => import('../../components/ActivityFeed'), { ssr: false });

export default function AccountsPage() {
    const { token, user } = useAuth();
    const [accounts, setAccounts] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [showModal, setShowModal] = useState(false);

    // Rescan State
    const [showScanModal, setShowScanModal] = useState(false);
    const [selectedAccount, setSelectedAccount] = useState<any>(null);
    const [scanning, setScanning] = useState(false);
    const [scanConfig, setScanConfig] = useState<{
        frequency: string;
        allRegions: boolean;
        viewOnly?: boolean;
    }>({
        frequency: 'Manual Only',
        allRegions: false,
        viewOnly: false
    });

    const openRescan = (account: any) => {
        setSelectedAccount(account);
        setScanning(false);
        setScanConfig({
            frequency: 'Manual Only',
            allRegions: account.status === 'active', // Auto-select if active
            viewOnly: false
        });
        setShowScanModal(true);
    };

    const handleStartScan = async () => {
        if (!selectedAccount || !token) return;
        setScanning(true);
        try {
            // Trigger backend (Mocking API call here, ActivityFeed waits for stream)
            await fetch(`http://localhost:8001/api/v1/accounts/${selectedAccount.id}/scan`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    frequency: scanConfig.frequency,
                    all_regions: scanConfig.allRegions
                })
            });
        } catch (e) {
            console.error("Scan trigger failed:", e);
        }
    };

    // Form State ...
    const [formData, setFormData] = useState({
        account_name: '',
        account_id: '',
        role_arn: '',
        provider: 'AWS'
    });

    const fetchAccounts = async () => {
        if (!token) return;
        try {
            const res = await fetch('http://localhost:8001/api/v1/accounts', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            if (res.ok) {
                setAccounts(await res.json());
            }
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAccounts();
    }, [token]);

    const handleOnboard = async (e: React.FormEvent) => {
        e.preventDefault();
        try {
            const res = await fetch('http://localhost:8001/api/v1/accounts', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(formData)
            });
            if (res.ok) {
                setShowModal(false);
                fetchAccounts();
                setFormData({ account_name: '', account_id: '', role_arn: '', provider: 'AWS' });
            } else {
                alert("Failed to onboard account");
            }
        } catch (err) {
            console.error(err);
        }
    };

    return (
        <div className="p-2">
            <div className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white mb-2">Cloud Accounts</h1>
                    <p className="text-text-secondary">Manage connected infrastructure providers and credentials.</p>
                </div>
                <button
                    onClick={() => setShowModal(true)}
                    className="flex items-center gap-2 bg-neon-blue hover:bg-neon-blue/80 text-tab-active-text font-bold py-2 px-4 rounded shadow-lg shadow-neon-blue/20 transition-all"
                >
                    <Plus size={18} />
                    Onboard Account
                </button>
            </div>

            {loading ? (
                <div className="text-center text-gray-500 py-20">Loading accounts...</div>
            ) : accounts.length === 0 ? (
                <div className="glass-card p-10 text-center border-dashed border-2 border-gray-700">
                    <Cloud size={48} className="mx-auto text-gray-600 mb-4" />
                    <h3 className="text-xl font-bold text-gray-300">No Accounts Connected</h3>
                    <p className="text-gray-500 mb-6">Connect an AWS account to start scanning.</p>
                    <button
                        onClick={() => setShowModal(true)}
                        className="text-neon-blue hover:underline"
                    >
                        Onboard Now
                    </button>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {accounts.map((acc) => (
                        <div key={acc.id} className="glass-card p-6 border-l-4 border-l-neon-amber hover:border-neon-amber/50 transition-all">
                            <div className="flex justify-between items-start mb-4">
                                <div className="flex items-center gap-3">
                                    <div className="p-2 bg-surface rounded border border-white/5">
                                        <Cloud size={20} className="text-neon-amber" />
                                    </div>
                                    <div>
                                        <h3 className="font-bold text-white">{acc.account_name}</h3>
                                        <div className="text-xs text-text-secondary font-mono">{acc.account_id}</div>
                                    </div>
                                </div>
                                <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${acc.status === 'active' ? 'bg-green-900/50 text-green-400' : 'bg-yellow-900/50 text-yellow-400'
                                    }`}>
                                    {acc.status}
                                </span>
                            </div>

                            <div className="flex gap-2 mt-4 mb-2">
                                <button
                                    onClick={() => openRescan(acc)}
                                    className="flex-1 bg-gray-800 hover:bg-gray-700 text-neon-blue border border-gray-700 py-2 rounded text-sm font-bold flex items-center justify-center gap-2 transition-all shadow-md"
                                >
                                    <RotateCw size={14} />
                                    Rescan
                                </button>
                                <button
                                    onClick={() => { setSelectedAccount(acc); setShowScanModal(true); setScanConfig({ ...scanConfig, frequency: 'Manual Only', allRegions: false, viewOnly: true }); }}
                                    className="flex-1 bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 py-2 rounded text-sm font-bold flex items-center justify-center gap-2 transition-all shadow-md"
                                >
                                    <Activity size={14} className="text-neon-purple" />
                                    Logs
                                </button>
                            </div>

                            <div className="space-y-2 mt-4 text-xs">
                                <div className="flex justify-between">
                                    <span className="text-text-secondary">Provider</span>
                                    <span className="text-white font-mono">{acc.provider}</span>
                                </div>
                                <div className="flex justify-between items-start">
                                    <span className="text-text-secondary mt-1">Active Regions</span>
                                    <div className="flex flex-wrap justify-end gap-1 max-w-[60%]">
                                        {acc.active_regions && acc.active_regions.length > 0 ? (
                                            acc.active_regions.map((region: string) => (
                                                <span key={region} className="bg-neon-blue/10 text-neon-blue px-1.5 py-0.5 rounded border border-neon-blue/20 text-[10px] font-mono">
                                                    {region}
                                                </span>
                                            ))
                                        ) : (
                                            <span className="text-gray-500 italic">None detected</span>
                                        )}
                                    </div>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-text-secondary">Last Added</span>
                                    <span className="text-primary font-mono">{acc.created_at ? new Date(acc.created_at).toLocaleDateString() : 'N/A'}</span>
                                </div>
                                <div className="flex justify-between">
                                    <span className="text-text-secondary">Resources Discovered</span>
                                    <span className="text-neon-blue font-mono font-bold">{acc.asset_count || 0}</span>
                                </div>
                                <div className="bg-nav p-2 rounded border border-border-color mt-2 truncate font-mono text-gray-400" title={acc.role_arn}>
                                    {acc.provider === 'AWS' ? acc.role_arn : '••••••••••••••••••••••••' + acc.role_arn.slice(-4)}
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            {/* Rescan Modal */}
            {showScanModal && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-[var(--surface)] border border-[var(--border-color)] rounded-xl w-full max-w-2xl p-0 shadow-2xl flex flex-col max-h-[90vh]">
                        <div className="p-6 border-b border-[var(--border-color)]">
                            <h2 className="text-xl font-bold text-[var(--text-primary)] flex items-center gap-2">
                                <RotateCw className={scanning ? "animate-spin text-neon-blue" : "text-neon-blue"} />
                                {(scanConfig as any).viewOnly ? "Live Activity Logs" : (scanning ? "Scanning in Progress..." : "Rescan & Sync Settings")}
                            </h2>
                            <p className="text-[var(--text-secondary)] text-sm mt-1">Configure scan scope and synchronization frequency.</p>
                        </div>

                        <div className="p-6 flex-grow overflow-y-auto">
                            {!scanning ? (
                                <div className="space-y-6">
                                    {/* Frequency Selector */}
                                    <div>
                                        <label className="block text-sm font-bold text-[var(--text-primary)] mb-2 flex items-center gap-2">
                                            <Clock size={16} className="text-neon-purple" />
                                            Sync Frequency
                                        </label>
                                        <div className="grid grid-cols-3 gap-3">
                                            {['Manual Only', '30 Minutes', '1 Hour', '6 Hours', '12 Hours', '24 Hours'].map((freq) => (
                                                <button
                                                    key={freq}
                                                    onClick={() => setScanConfig({ ...scanConfig, frequency: freq })}
                                                    className={`px-3 py-2 rounded border text-sm font-medium transition-all whitespace-nowrap ${scanConfig.frequency === freq
                                                        ? 'bg-neon-purple/20 border-neon-purple text-[var(--text-primary)]'
                                                        : 'bg-[var(--card-bg)] border-[var(--border-color)] text-[var(--text-secondary)] hover:border-gray-500'
                                                        }`}
                                                >
                                                    {freq}
                                                </button>
                                            ))}
                                        </div>
                                    </div>

                                    {/* Region Scope */}
                                    <div>
                                        <label className="block text-sm font-bold text-[var(--text-primary)] mb-2 flex items-center gap-2">
                                            <Globe size={16} className="text-neon-amber" />
                                            Region Scope
                                        </label>
                                        <div
                                            onClick={() => setScanConfig({ ...scanConfig, allRegions: !scanConfig.allRegions })}
                                            className={`flex items-center justify-between p-4 rounded border cursor-pointer transition-all ${scanConfig.allRegions
                                                ? 'bg-neon-amber/10 border-neon-amber'
                                                : 'bg-[var(--card-bg)] border-[var(--border-color)] hover:border-gray-500'
                                                }`}
                                        >
                                            <div>
                                                <div className="font-bold text-[var(--text-primary)]">Scan All Active Regions</div>
                                                <div className="text-xs text-[var(--text-secondary)]">Automatically discover and scan resources in all enabled regions.</div>
                                            </div>
                                            <div className={`w-6 h-6 rounded border flex items-center justify-center ${scanConfig.allRegions ? 'bg-neon-amber border-neon-amber text-black' : 'border-gray-500'
                                                }`}>
                                                {scanConfig.allRegions && <CheckCircle size={14} />}
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            ) : (
                                <div className="h-[400px] bg-black/50 rounded border border-[var(--border-color)] overflow-hidden">
                                    <ActivityFeed sourceId={`scan-${selectedAccount?.id}`} />
                                </div>
                            )}
                        </div>

                        <div className="p-6 border-t border-[var(--border-color)] flex justify-end gap-3 bg-[var(--card-bg)]/50">
                            {!scanning ? (
                                <>
                                    <button
                                        onClick={() => setShowScanModal(false)}
                                        className="px-4 py-2 rounded text-[var(--text-secondary)] hover:text-white"
                                    >
                                        Close
                                    </button>
                                    {!(scanConfig as any).viewOnly && (
                                        <button
                                            onClick={handleStartScan}
                                            className="px-6 py-2 rounded bg-neon-blue text-black font-bold hover:bg-neon-blue/80 shadow-lg shadow-neon-blue/20 flex items-center gap-2 whitespace-nowrap"
                                        >
                                            <Play size={16} />
                                            Start Rescan
                                        </button>
                                    )}
                                </>
                            ) : (
                                <button
                                    onClick={() => setShowScanModal(false)}
                                    className="px-4 py-2 rounded border border-[var(--border-color)] text-white hover:bg-white/5 whitespace-nowrap"
                                >
                                    Running in Background... (Close)
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Onboard Modal */}
            {showModal && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    {/* ... existing onboard modal content ... */}
                    <div className="bg-surface border border-border-color rounded-xl w-full max-w-md p-6 shadow-2xl">
                        <h2 className="text-xl font-bold text-primary mb-4">Onboard AWS Account</h2>

                        <form onSubmit={handleOnboard} className="space-y-4">
                            {/* ... Rest of existing form ... */}
                            <div className="grid grid-cols-2 gap-4 mb-6">
                                <button
                                    type="button"
                                    onClick={() => setFormData({ ...formData, provider: 'AWS' })}
                                    className={`p-3 rounded border flex flex-col items-center gap-2 transition-all ${formData.provider === 'AWS'
                                        ? 'bg-neon-amber/20 border-neon-amber text-primary'
                                        : 'bg-card border-border-color text-text-secondary hover:bg-white/5'
                                        }`}
                                >
                                    <Cloud size={24} />
                                    <span className="text-xs font-bold">AWS</span>
                                </button>
                                <button
                                    type="button"
                                    onClick={() => setFormData({ ...formData, provider: 'DigitalOcean' })}
                                    className={`p-3 rounded border flex flex-col items-center gap-2 transition-all ${formData.provider === 'DigitalOcean'
                                        ? 'bg-neon-blue/20 border-neon-blue text-primary'
                                        : 'bg-card border-border-color text-text-secondary hover:bg-white/5'
                                        }`}
                                >
                                    <Cloud size={24} className="text-blue-400" />
                                    <span className="text-xs font-bold">DigitalOcean</span>
                                </button>
                            </div>

                            <div className="space-y-4">
                                <div>
                                    <label className="block text-xs font-bold text-text-secondary uppercase mb-1">Account Alias</label>
                                    <input
                                        type="text"
                                        required
                                        className="w-full bg-card border border-border-color rounded px-3 py-2 text-primary focus:outline-none focus:border-neon-blue"
                                        placeholder={formData.provider === 'AWS' ? "e.g. Production AWS" : "e.g. My DigitalOcean Team"}
                                        value={formData.account_name}
                                        onChange={e => setFormData({ ...formData, account_name: e.target.value })}
                                    />
                                </div>

                                {formData.provider === 'AWS' ? (
                                    <>
                                        {/* AWS Configuration Tabs */}
                                        <div className="bg-nav rounded-lg p-3 border border-border-color">
                                            <div className="flex gap-4 border-b border-gray-700 mb-3 pb-2 text-xs font-bold uppercase tracking-wider">
                                                <div className="text-neon-blue cursor-default">Quick Setup</div>
                                            </div>

                                            <div className="space-y-3">
                                                <p className="text-xs text-gray-400">Run this snippet to create the required read-only role.</p>

                                                <div className="relative group">
                                                    <pre className="bg-black/50 p-3 rounded border border-white/5 text-[10px] font-mono text-gray-300 overflow-x-auto whitespace-pre-wrap">
                                                        {`Resources:
  ProvenanceScannerRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ProvenanceScannerRole
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: "arn:aws:iam::123456789012:root" # Pro-NDS Account
            Action: "sts:AssumeRole"
            Condition:
              StringEquals:
                "sts:ExternalId": "PROV-${user?.tenant_id?.slice(0, 8) || 'GEN'}"
      ManagedPolicyArns:
        - "arn:aws:iam::aws:policy/SecurityAudit"
        - "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"`}
                                                    </pre>
                                                    <button
                                                        type="button"
                                                        onClick={() => navigator.clipboard.writeText("Resource...")} // Mock copy
                                                        className="absolute top-2 right-2 bg-neon-blue/10 hover:bg-neon-blue/20 text-neon-blue text-[10px] px-2 py-1 rounded border border-neon-blue/30 opacity-0 group-hover:opacity-100 transition-opacity"
                                                    >
                                                        COPY YAML
                                                    </button>
                                                </div>

                                                <div className="flex items-center gap-2 text-[10px] text-gray-500">
                                                    <div className="w-2 h-2 rounded-full bg-blue-500"></div>
                                                    Terraform user? <span className="text-neon-blue cursor-pointer hover:underline">View .tf snippet</span>
                                                </div>
                                            </div>
                                        </div>

                                        <div>
                                            <label className="block text-xs font-bold text-text-secondary uppercase mb-1">AWS Account ID</label>
                                            <input
                                                type="text"
                                                required
                                                className="w-full bg-surface border border-border-color rounded px-3 py-2 text-primary focus:outline-none focus:border-neon-blue font-mono placeholder:text-text-secondary"
                                                placeholder="123456789012"
                                                value={formData.account_id}
                                                onChange={e => setFormData({ ...formData, account_id: e.target.value })}
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-xs font-bold text-text-secondary uppercase mb-1">Role ARN</label>
                                            <input
                                                type="text"
                                                required
                                                className="w-full bg-surface border border-border-color rounded px-3 py-2 text-primary focus:outline-none focus:border-neon-blue font-mono text-xs placeholder:text-text-secondary"
                                                placeholder="arn:aws:iam::123456789012:role/ProvenanceScannerRole"
                                                value={formData.role_arn}
                                                onChange={e => setFormData({ ...formData, role_arn: e.target.value })}
                                            />
                                        </div>
                                    </>
                                ) : (
                                    <>
                                        {/* DigitalOcean Fields */}
                                        <div>
                                            <label className="block text-xs font-bold text-text-secondary uppercase mb-1">Team ID / Name</label>
                                            <input
                                                type="text"
                                                className="w-full bg-surface border border-border-color rounded px-3 py-2 text-primary focus:outline-none focus:border-neon-blue font-mono placeholder:text-text-secondary"
                                                placeholder="Optional (Visual identifier)"
                                                value={formData.account_id}
                                                onChange={e => setFormData({ ...formData, account_id: e.target.value })}
                                            />
                                        </div>
                                        <div>
                                            <label className="block text-xs font-bold text-text-secondary uppercase mb-1">Personal Access Token (PAT)</label>
                                            <input
                                                type="password"
                                                required
                                                className="w-full bg-surface border border-border-color rounded px-3 py-2 text-primary focus:outline-none focus:border-neon-blue font-mono text-xs placeholder:text-text-secondary"
                                                placeholder="dop_v1_..."
                                                value={formData.role_arn}
                                                onChange={e => setFormData({ ...formData, role_arn: e.target.value })}
                                            />
                                            <div className="bg-blue-900/20 border border-blue-900/50 p-2 rounded mt-2 text-[10px] text-gray-400">
                                                <strong>Documentation:</strong> Go to <a href="https://cloud.digitalocean.com/account/api/tokens" target="_blank" className="text-neon-blue underline">API Settings</a>. Generate a new token with <code>Read</code> scope only.
                                            </div>
                                        </div>
                                    </>
                                )}
                            </div>

                            <div className="flex justify-end gap-3 mt-6">
                                <button
                                    type="button"
                                    onClick={() => setShowModal(false)}
                                    className="px-4 py-2 rounded text-gray-400 hover:text-white"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="px-4 py-2 rounded bg-neon-blue text-tab-active-text font-bold hover:bg-neon-blue/80"
                                >
                                    Connect Account
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}
