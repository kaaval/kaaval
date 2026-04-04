"use client";

import { Server, User, Globe, Database, Cpu, Box } from 'lucide-react';
import IAMDetails from './IAMDetails';

interface Asset {
    id: string;
    asset_type: string;
    region: string;
    account_id: string;
    details: any;
}

export default function AssetGrid({ assets }: { assets: Asset[] }) {
    if (assets.length === 0) {
        return (
            <div className="text-center text-gray-400 mt-20 border border-dashed border-gray-800 rounded-lg p-10 bg-surface/30">
                <p className="text-lg mb-2">No assets found matching criteria.</p>
            </div>
        );
    }

    const getIcon = (type: string) => {
        switch (type) {
            case 'EC2': return <Server size={20} className="text-neon-blue" />;
            case 'IAM_USER': return <User size={20} className="text-neon-purple" />;
            case 'S3': return <Database size={20} className="text-neon-green" />;
            case 'EKS_CLUSTER': return <Cpu size={20} className="text-neon-amber" />;
            case 'VPC': return <Globe size={20} className="text-white" />;
            default: return <Box size={20} className="text-gray-400" />;
        }
    };

    return (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {assets.map((asset) => (
                <div key={asset.id} className="glass-card flex flex-col hover:border-neon-blue/40 transition-all duration-300">
                    <div className="p-4 border-b border-border-color flex justify-between items-start bg-surface/50 rounded-t-xl">
                        <div className="flex items-center gap-3">
                            <div className="p-2 bg-surface rounded-lg border border-border-color shadow-inner">
                                {getIcon(asset.asset_type)}
                            </div>
                            <div className="overflow-hidden">
                                <h3 className="font-bold text-lg text-text-primary truncate max-w-[150px]" title={asset.details.UserName || asset.id}>
                                    {asset.details.UserName || asset.details.InstanceId || asset.id}
                                </h3>
                                <div className="text-xs text-text-secondary font-mono flex items-center gap-1">
                                    <span className="w-1.5 h-1.5 rounded-full bg-neon-green"></span>
                                    {asset.asset_type}
                                </div>
                            </div>
                        </div>
                        <div className="bg-surface px-2 py-1 rounded text-[10px] text-text-secondary font-mono border border-border-color">
                            {asset.region}
                        </div>
                    </div>

                    <div className="p-4 flex-grow">
                        {asset.asset_type === 'IAM_USER' ? (
                            <IAMDetails details={asset.details} />
                        ) : (
                            // Generic Fallback / Specifics for other types
                            <div className="space-y-3">
                                {asset.asset_type === 'EKS_CLUSTER' && asset.details.Namespaces && (
                                    <div>
                                        <h3 className="text-xs font-semibold text-text-secondary mb-1 uppercase tracking-wider">Namespaces</h3>
                                        <div className="flex flex-wrap gap-1.5">
                                            {asset.details.Namespaces.map((ns: string) => (
                                                <span key={ns} className="px-2 py-0.5 bg-neon-blue/10 text-neon-blue rounded text-[10px] border border-neon-blue/20 font-mono">
                                                    {ns}
                                                </span>
                                            ))}
                                        </div>
                                    </div>
                                )}

                                {asset.asset_type === 'EKS_CLUSTER' && asset.details.RBACSummary && (
                                    <div className="grid grid-cols-2 gap-2 mt-2">
                                        {Object.entries(asset.details.RBACSummary).map(([key, count]) => (
                                            <div key={key} className="bg-surface p-2 rounded border border-border-color flex justify-between items-center">
                                                <span className="text-[10px] text-text-secondary">{key}</span>
                                                <span className="text-xs font-mono font-bold text-text-primary">{count as number}</span>
                                            </div>
                                        ))}
                                    </div>
                                )}

                                {asset.asset_type === 'VPC' && (
                                    <div className="space-y-2">
                                        <div className="flex justify-between text-xs">
                                            <span className="text-text-secondary">CIDR</span>
                                            <span className="font-mono text-text-primary">{asset.details.CidrBlock}</span>
                                        </div>
                                        <div className="flex justify-between text-xs">
                                            <span className="text-text-secondary">State</span>
                                            <span className={`font-bold ${asset.details.State === 'available' ? 'text-neon-green' : 'text-neon-amber'}`}>{asset.details.State}</span>
                                        </div>
                                    </div>
                                )}

                                {/* JSON Fallback for complex details */}
                                {!['IAM_USER'].includes(asset.asset_type) && (
                                    <div className="bg-nav p-3 rounded text-xs font-mono text-text-secondary overflow-x-auto h-32 scrollbar-thin scrollbar-thumb-gray-700 border border-border-color mt-2">
                                        <pre>{JSON.stringify(asset.details, null, 2)}</pre>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                </div>
            ))}
        </div>
    );
}
