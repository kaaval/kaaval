"use client";

import { useEffect, useState } from 'react';
import InventoryViews from '../../components/InventoryViews';
import { useAuth } from '../../components/AuthContext';
import { Server, Shield, Globe, Database, LayoutGrid } from 'lucide-react';
import AssetGrid from '../../components/AssetGrid';

interface Asset {
    id: string;
    asset_type: string;
    region: string;
    account_id: string;
    details: any;
}

export default function InventoryPage() {
    const [assets, setAssets] = useState<Asset[]>([]);
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState<string>('OVERVIEW');
    const { token } = useAuth();

    useEffect(() => {
        if (!token) return;
        fetch('http://localhost:8001/api/v1/assets', {
            headers: { 'Authorization': `Bearer ${token}` }
        })
            .then(res => res.json())
            .then(data => {
                setAssets(data);
                setLoading(false);
            })
            .catch(err => {
                console.error('Failed to fetch assets', err);
                setLoading(false);
            });
    }, [token]);

    const tabs = [
        { id: 'OVERVIEW', label: 'Overview', icon: LayoutGrid },
        { id: 'NETWORKING', label: 'Networking', icon: Globe },
        { id: 'COMPUTE', label: 'Compute', icon: Server },
        { id: 'SECURITY', label: 'Security & IAM', icon: Shield },
        { id: 'STORAGE', label: 'Storage', icon: Database },
    ];

    return (
        <div className="space-y-6">
            <header className="flex flex-col md:flex-row justify-between items-end border-b border-border-color pb-4 gap-4">
                <div>
                    <h2 className="text-3xl font-bold text-foreground mb-2">Cloud Inventory</h2>
                    <p className="text-gray-400">Manage and audit your multi-cloud usage.</p>
                </div>

                {/* Tab Navigation */}
                <div className="flex bg-nav p-1 rounded-lg border border-border-color overflow-x-auto">
                    {tabs.map((tab) => {
                        const Icon = tab.icon;
                        return (
                            <button
                                key={tab.id}
                                onClick={() => setActiveTab(tab.id)}
                                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-bold transition-all whitespace-nowrap ${activeTab === tab.id
                                    ? 'bg-neon-blue text-tab-active-text shadow-lg shadow-neon-blue/20'
                                    : 'text-gray-400 hover:text-foreground hover:bg-white/5'
                                    }`}
                            >
                                <Icon size={16} />
                                {tab.label}
                            </button>
                        );
                    })}
                </div>
            </header>

            {loading ? (
                <div className="flex flex-col items-center justify-center h-64 text-gray-400 animate-pulse">
                    <LayoutGrid size={48} className="mb-4 text-gray-600" />
                    <div>Loading Asset Data...</div>
                </div>
            ) : (
                <>
                    {activeTab === 'OVERVIEW' ? (
                        <div>
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
                                <div className="glass-card p-4 text-center">
                                    <div className="text-3xl font-bold text-foreground">{assets.length}</div>
                                    <div className="text-xs text-gray-500 uppercase tracking-wider">Total Assets</div>
                                </div>
                                <div className="glass-card p-4 text-center border-neon-blue/30 border-b-2">
                                    <div className="text-3xl font-bold text-neon-blue">{assets.filter(a => ['VPC', 'SUBNET'].includes(a.asset_type)).length}</div>
                                    <div className="text-xs text-neon-blue/70 uppercase tracking-wider">Networking</div>
                                </div>
                                <div className="glass-card p-4 text-center border-neon-amber/30 border-b-2">
                                    <div className="text-3xl font-bold text-neon-amber">{assets.filter(a => a.asset_type === 'EC2').length}</div>
                                    <div className="text-xs text-neon-amber/70 uppercase tracking-wider">Compute</div>
                                </div>
                                <div className="glass-card p-4 text-center border-neon-red/30 border-b-2">
                                    <div className="text-3xl font-bold text-neon-red">{assets.filter(a => a.details?.compliance?.length > 0).length}</div>
                                    <div className="text-xs text-neon-red/70 uppercase tracking-wider">Misconfigured</div>
                                </div>
                            </div>
                            <AssetGrid assets={assets} />
                        </div>
                    ) : (
                        <InventoryViews assets={assets} activeTab={activeTab} />
                    )}
                </>
            )}
        </div>
    );
}
