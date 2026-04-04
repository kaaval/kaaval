"use client";
import { useEffect, useState } from 'react';
import { Upload, Plus, HelpCircle, X, Copy, Check } from 'lucide-react';
import { useAuth } from '../../components/AuthContext';

export default function IntegrationsPage() {
    const { token } = useAuth();
    const [available, setAvailable] = useState<any[]>([]);
    const [installed, setInstalled] = useState<any[]>([]);
    const [loading, setLoading] = useState(true);
    const [uploading, setUploading] = useState(false);
    const [showHelp, setShowHelp] = useState(false);

    const sampleYaml = `meta:
  id: "custom-check-v1"
  name: "My Custom Framework"
  version: "1.0.0"
  description: "Checks for specific tags on EC2."
  price_tier: "Free"

checks:
  - id: "EC2_TAG_CHECK"
    name: "Ensure Environment Tag"
    severity: "HIGH"
    target_asset_type: "EC2"
    condition:
      operator: "contains"
      field: "details.Tags"
      value: "Environment"
    remediation: "Add Environment tag to instance."`;

    const fetchData = async () => {
        if (!token) return;
        try {
            const resAvail = await fetch('http://localhost:8001/api/v1/integrations/available', {
                headers: { 'Authorization': `Bearer ${token}` }
            });
            const resInst = await fetch('http://localhost:8001/api/v1/integrations/installed', {
                headers: { 'Authorization': `Bearer ${token}` }
            });

            setAvailable(await resAvail.json());
            setInstalled(await resInst.json());
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchData();
    }, [token]);

    const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
        const file = event.target.files?.[0];
        if (!file || !token) return;

        setUploading(true);
        const formData = new FormData();
        formData.append('file', file);

        try {
            const res = await fetch('http://localhost:8001/api/v1/integrations/upload', {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` },
                body: formData
            });

            if (res.ok) {
                alert("Integration uploaded successfully!");
                fetchData();
            } else {
                const err = await res.json();
                alert(`Upload failed: ${err.detail}`);
            }
        } catch (e) {
            console.error(e);
            alert("Upload failed due to network error.");
        } finally {
            setUploading(false);
        }
    };

    // ... rest of handlers ...

    const handleInstall = async (id: string) => {
        if (!token) return;
        try {
            await fetch(`http://localhost:8001/api/v1/integrations/${id}/install`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            fetchData(); // Refresh
        } catch (err) {
            console.error(err);
        }
    };

    const handleUninstall = async (id: string) => {
        if (!token) return;
        try {
            await fetch(`http://localhost:8001/api/v1/integrations/${id}/uninstall`, {
                method: 'POST',
                headers: { 'Authorization': `Bearer ${token}` }
            });
            fetchData(); // Refresh
        } catch (err) {
            console.error(err);
        }
    };

    const isInstalled = (id: string) => {
        return installed.some((i: any) => i.id === id);
    };

    return (
        <div className="p-2">
            <div className="flex justify-between items-end mb-8">
                <div>
                    <h1 className="text-3xl font-bold mb-2 text-neon-blue drop-shadow-[0_0_10px_rgba(0,212,255,0.3)]">Integrations Marketplace</h1>
                    <p className="text-gray-400 max-w-2xl">Extend your security coverage by adding compliance frameworks and third-party tools.</p>
                </div>
                <div className="flex gap-3">
                    <button
                        onClick={() => setShowHelp(true)}
                        className="flex items-center gap-2 px-3 py-2 rounded-md hover:bg-white/5 text-gray-400 hover:text-white transition-colors border border-transparent hover:border-white/10"
                    >
                        <HelpCircle size={18} />
                        <span className="text-sm font-bold">Schema Guide</span>
                    </button>
                    <label className={`flex items-center gap-2 px-4 py-2 rounded-md bg-neon-purple/20 text-neon-purple border border-neon-purple/50 cursor-pointer hover:bg-neon-purple/30 transition-all ${uploading ? 'opacity-50 cursor-not-allowed' : ''}`}>
                        <Upload size={18} />
                        <span className="font-bold text-sm uppercase tracking-wide">{uploading ? 'Uploading...' : 'Import YAML'}</span>
                        <input
                            type="file"
                            accept=".yaml,.yml"
                            className="hidden"
                            onChange={handleFileUpload}
                            disabled={uploading}
                        />
                    </label>
                </div>
            </div>

            {/* Help Modal */}
            {showHelp && (
                <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
                    <div className="bg-surface border border-border-color rounded-xl w-full max-w-3xl p-0 shadow-2xl flex flex-col max-h-[90vh]">
                        <div className="p-6 border-b border-gray-800 flex justify-between items-center">
                            <h2 className="text-xl font-bold text-white flex items-center gap-2">
                                <HelpCircle className="text-neon-blue" />
                                Integration Schema Guide
                            </h2>
                            <button onClick={() => setShowHelp(false)} className="text-gray-400 hover:text-white">
                                <X size={24} />
                            </button>
                        </div>
                        <div className="p-6 overflow-y-auto space-y-6 text-gray-300 text-sm">
                            <div className="bg-blue-900/20 border border-blue-900/50 p-4 rounded-lg">
                                <h3 className="text-blue-400 font-bold mb-2 flex items-center gap-2">
                                    <Check size={16} />
                                    Security & Validation
                                </h3>
                                <ul className="list-disc list-inside space-y-1 text-xs">
                                    <li>Files are strictly validated against a schema.</li>
                                    <li>Max file size: <strong>1MB</strong>.</li>
                                    <li>Only <code>.yaml</code> extensions are allowed.</li>
                                    <li>Target asset types must be valid (e.g., EC2, IAM_USER).</li>
                                </ul>
                            </div>

                            <div className="grid grid-cols-2 gap-6">
                                <div>
                                    <h3 className="font-bold text-white mb-2">Required Fields</h3>
                                    <ul className="space-y-2 text-xs font-mono">
                                        <li><span className="text-neon-intro">meta.id</span>: Unique ID (alphanumeric)</li>
                                        <li><span className="text-neon-intro">meta.name</span>: Display Name</li>
                                        <li><span className="text-neon-intro">checks[].id</span>: Rule ID</li>
                                        <li><span className="text-neon-intro">checks[].target_asset_type</span>: Resource type</li>
                                        <li><span className="text-neon-intro">checks[].condition</span>: Logic definition</li>
                                    </ul>
                                </div>
                                <div>
                                    <h3 className="font-bold text-white mb-2">Example YAML</h3>
                                    <div className="relative group">
                                        <pre className="bg-black/50 p-4 rounded border border-white/5 font-mono text-xs overflow-x-auto text-green-400 whitespace-pre">
                                            {sampleYaml}
                                        </pre>
                                        <button
                                            onClick={() => navigator.clipboard.writeText(sampleYaml)}
                                            className="absolute top-2 right-2 p-1.5 bg-white/10 rounded hover:bg-white/20 text-white opacity-0 group-hover:opacity-100 transition-opacity"
                                            title="Copy to Clipboard"
                                        >
                                            <Copy size={14} />
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            )}

            {loading ? (
                <div className="flex items-center justify-center h-64">
                    <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-neon-blue"></div>
                </div>
            ) : (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {Array.isArray(available) && available.length > 0 ? (
                        available.map((item: any) => (
                            <div key={item.id} className="glass-card flex flex-col hover:border-neon-blue/50 transition-colors duration-300">
                                <div className="p-6 flex-grow">
                                    <div className="flex justify-between items-start mb-4">
                                        <div className={`text-xs font-bold px-2.5 py-0.5 rounded uppercase tracking-wider ${item.price_tier === 'Free' ? 'bg-green-500/20 text-green-400' : 'bg-neon-purple/20 text-neon-purple'
                                            }`}>
                                            {item.price_tier}
                                        </div>
                                        {item.is_premium && (
                                            <span className="text-neon-amber text-xs font-bold border border-neon-amber/50 px-2 py-0.5 rounded">PREMIUM</span>
                                        )}
                                    </div>
                                    <h3 className="text-xl font-bold mb-2 text-primary">{item.name}</h3>
                                    <p className="text-gray-400 text-sm mb-4 leading-relaxed">{item.description}</p>
                                    <div className="text-xs text-gray-600 font-mono">v{item.version}</div>
                                </div>
                                <div className="bg-black/20 p-4 border-t border-white/5">
                                    {isInstalled(item.id) ? (
                                        <button
                                            onClick={() => handleUninstall(item.id)}
                                            className="w-full py-2 px-4 border border-neon-red/30 rounded-md shadow-sm text-sm font-medium text-neon-red hover:bg-neon-red/10 transition-all font-mono uppercase tracking-wide"
                                        >
                                            Uninstall
                                        </button>
                                    ) : (
                                        <button
                                            onClick={() => handleInstall(item.id)}
                                            className="w-full py-2 px-4 rounded-md shadow-lg text-sm font-bold text-black bg-neon-blue hover:bg-neon-blue/80 transition-all shadow-neon-blue/20 font-mono uppercase tracking-wide"
                                        >
                                            Install Integration
                                        </button>
                                    )}
                                </div>
                            </div>
                        ))
                    ) : (
                        <div className="col-span-full text-center py-10 text-gray-500">
                            No integrations available.
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
