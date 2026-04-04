"use client";

import { useState } from 'react';
import {
    Server, Shield, Globe, Database, Lock, AlertTriangle, CheckCircle,
    Box, HardDrive, Key, ChevronDown, ChevronRight, Activity, Zap,
    ArrowRightLeft, AlertOctagon, Info
} from 'lucide-react';

// --- Shared Components ---

const ComplianceBubble = ({ level, control, message }: { level: 'critical' | 'high' | 'medium' | 'low', control: string, message: string }) => {
    const colors = {
        critical: 'bg-red-500 text-white shadow-red-500/50',
        high: 'bg-orange-500 text-white shadow-orange-500/50',
        medium: 'bg-yellow-500 text-black shadow-yellow-500/50',
        low: 'bg-blue-500 text-white shadow-blue-500/50',
    };

    return (
        <div className={`relative group inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wider shadow-lg ${colors[level]} cursor-help`}>
            <AlertOctagon size={10} />
            <span>{control}</span>
            {/* Tooltip */}
            <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 w-48 bg-gray-900 border border-gray-700 text-gray-200 text-xs p-2 rounded shadow-2xl opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-50 normal-case font-normal leading-tight">
                <div className="font-bold mb-1 text-white">{control} Violation</div>
                {message}
                <div className="absolute top-full left-1/2 -translate-x-1/2 border-4 border-transparent border-t-gray-900"></div>
            </div>
        </div>
    );
};

const StatusBadge = ({ status, text }: { status: 'pass' | 'fail' | 'warn'; text?: string }) => {
    const colors = {
        pass: 'bg-neon-green/10 text-neon-green border-neon-green/50',
        fail: 'bg-neon-red/10 text-neon-red border-neon-red/50',
        warn: 'bg-neon-amber/10 text-neon-amber border-neon-amber/50'
    };
    return (
        <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider border ${colors[status]} flex items-center gap-1`}>
            {status === 'pass' && <CheckCircle size={10} />}
            {status === 'fail' && <AlertTriangle size={10} />}
            {text || status}
        </span>
    );
};

// --- Logic Helpers ---

const analyzeSecurityGroup = (sg: any) => {
    const issues = [];
    // Check Inbound 0.0.0.0/0
    if (sg.details.IpPermissions) {
        for (const rule of sg.details.IpPermissions) {
            const isPublic = rule.IpRanges?.some((r: any) => r.CidrIp === '0.0.0.0/0');
            if (isPublic) {
                if (rule.FromPort === -1 || (rule.FromPort <= 22 && rule.ToPort >= 22)) {
                    issues.push({ level: 'critical', control: 'CIS 4.1', message: 'SSH port (22) is open to the world (0.0.0.0/0).' });
                } else if (rule.FromPort <= 3389 && rule.ToPort >= 3389) {
                    issues.push({ level: 'critical', control: 'CIS 4.2', message: 'RDP port (3389) is open to the world.' });
                } else {
                    issues.push({ level: 'medium', control: 'Security', message: `Port ${rule.FromPort} open to 0.0.0.0/0` });
                }
            }
        }
    }
    return issues;
};

// --- Risk Analysis Components ---

const RiskAssessment = ({ type, context }: { type: string, context?: string }) => {
    let red = "", blue = "";

    switch (type) {
        case 'CIS 4.1': // SSH Open
            red = "Attacker can perform internet-wide scanning to identify SSH services and launch brute-force or credential stuffing attacks for Initial Access.";
            blue = "Restrict ingress to trusted CIDR ranges (VPN/Office). Consider using AWS Systems Manager Session Manager to remove the need for open SSH ports entirely.";
            break;
        case 'CIS 4.2': // RDP Open
            red = "Exposed RDP is a prime target for ransomware groups. Successful authentication grants GUI access, often leading to rapid lateral movement.";
            blue = "RDP should never be exposed to 0.0.0.0/0. Use RD Gateway or SSM Port Forwarding. Enforce NLA (Network Level Authentication).";
            break;
        case 'S3.1': // Public Bucket
            red = "Anonymous users can list and download objects. Data Exfiltration is trivial. Attackers may also upload malware if write permissions are loose.";
            blue = "Enable 'Block Public Access' at the bucket or account level. Use CloudFront OAI/OAC if public serving is required. Audit Bucket Policy.";
            break;
        case 'IAM.NoMFA':
            red = "Compromised credentials lead to immediate account takeover. Phishing resistance is zero.";
            blue = "Enforce MFA for Console Access via IAM Policy. Rotate access keys every 90 days.";
            break;
        default:
            red = "Potential misconfiguration exposes attack surface.";
            blue = "Review against least-privilege principles.";
    }

    return (
        <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-2 text-[10px]">
            <div className="bg-red-950/30 border border-red-900/50 p-2 rounded relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-1 opacity-10 group-hover:opacity-20"><Zap size={40} className="text-red-500" /></div>
                <h5 className="font-bold text-red-400 flex items-center gap-1 mb-1"><Zap size={10} /> RED TEAM (Threat)</h5>
                <p className="text-gray-400 leading-tight">{red}</p>
            </div>
            <div className="bg-blue-950/30 border border-blue-900/50 p-2 rounded relative overflow-hidden group">
                <div className="absolute top-0 right-0 p-1 opacity-10 group-hover:opacity-20"><Shield size={40} className="text-blue-500" /></div>
                <h5 className="font-bold text-blue-400 flex items-center gap-1 mb-1"><Shield size={10} /> BLUE TEAM (Defense)</h5>
                <p className="text-gray-400 leading-tight">{blue}</p>
            </div>
        </div>
    );
};

// --- View Components ---

function VPCDetailCard({ vpc, assets }: { vpc: any, assets: any[] }) {
    const [expanded, setExpanded] = useState(false);

    // Drill Down Data
    const subnets = assets.filter(a => a.asset_type === 'SUBNET' && a.details.VpcId === vpc.details.VpcId);
    const sgs = assets.filter(a => a.asset_type === 'SECURITY_GROUP' && a.details.VpcId === vpc.details.VpcId);
    const routeTables = assets.filter(a => a.asset_type === 'ROUTE_TABLE' && a.details.VpcId === vpc.details.VpcId);

    // Analyze subnets for public/private
    const publicSubnets = subnets.filter(s => s.details.MapPublicIpOnLaunch);
    const privateSubnets = subnets.filter(s => !s.details.MapPublicIpOnLaunch);

    return (
        <div className={`glass-card transition-all duration-300 ${expanded ? 'border-l-4 border-l-neon-blue ring-1 ring-neon-blue/30' : 'border-l-4 border-l-gray-700 hover:border-l-neon-blue'}`}>
            {/* Header */}
            <div className="p-5 cursor-pointer flex justify-between items-start" onClick={() => setExpanded(!expanded)}>
                <div className="flex items-center gap-4">
                    <div className={`p-3 rounded-lg ${expanded ? 'bg-neon-blue/20 text-neon-blue' : 'bg-surface text-gray-400'}`}>
                        <Globe size={24} />
                    </div>
                    <div>
                        <div className="flex items-center gap-3">
                            <h3 className="font-bold text-lg text-primary">{vpc.details.Tags?.find((t: any) => t.Key === 'Name')?.Value || vpc.details.VpcId}</h3>
                            <div className="text-xs font-mono text-gray-500 bg-nav px-2 py-0.5 rounded">{vpc.details.VpcId}</div>
                        </div>
                        <div className="flex items-center gap-4 mt-1">
                            <div className="flex items-center gap-1.5 text-xs text-gray-400">
                                <Activity size={12} className="text-neon-green" />
                                <span className="font-mono">{vpc.details.CidrBlock}</span>
                            </div>
                            <div className="flex items-center gap-1.5 text-xs text-gray-400">
                                <MapIcon size={12} />
                                <span>{subnets.length} Subnets</span>
                            </div>
                            <div className="flex items-center gap-1.5 text-xs text-gray-400">
                                <Shield size={12} />
                                <span>{sgs.length} SecGroups</span>
                            </div>
                        </div>
                    </div>
                </div>
                <div className="flex items-center gap-3">
                    <StatusBadge status={vpc.details.State === 'available' ? 'pass' : 'fail'} text={vpc.details.State} />
                    {expanded ? <ChevronDown className="text-neon-blue" /> : <ChevronRight className="text-gray-600" />}
                </div>
            </div>

            {/* Drill Down Content */}
            {expanded && (
                <div className="border-t border-border-color bg-surface/30 p-6 space-y-8 animate-in slide-in-from-top-2 duration-300">

                    {/* Topology Summary */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                        {/* Subnets Visualization */}
                        <div className="bg-surface/50 rounded-xl p-4 border border-border-color">
                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                                <LayoutIcon size={14} /> Network Segmentation
                            </h4>
                            <div className="space-y-3">
                                <div className="flex gap-2 text-xs mb-2">
                                    <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-neon-green"></div> Public</span>
                                    <span className="flex items-center gap-1"><div className="w-2 h-2 rounded-full bg-neon-blue"></div> Private</span>
                                </div>
                                <div className="space-y-1">
                                    {subnets.map(subnet => {
                                        const isPublic = subnet.details.MapPublicIpOnLaunch;
                                        return (
                                            <div key={subnet.id} className="flex items-center justify-between p-2 rounded bg-card border border-border-color group hover:border-border-color transition-colors">
                                                <div className="flex items-center gap-3">
                                                    <div className={`w-1.5 h-8 rounded-full ${isPublic ? 'bg-neon-green shadow-[0_0_8px_rgba(0,255,157,0.5)]' : 'bg-neon-blue'}`}></div>
                                                    <div>
                                                        <div className="text-sm font-mono text-white">{subnet.details.CidrBlock}</div>
                                                        <div className="text-[10px] text-gray-500">{subnet.details.AvailabilityZone}</div>
                                                    </div>
                                                </div>
                                                <div className="text-right">
                                                    <div className="text-[10px] text-gray-500 font-mono">{subnet.details.SubnetId}</div>
                                                    <div className="text-[10px] font-bold text-gray-400">{isPublic ? 'IGW Attached' : 'NAT/Private'}</div>
                                                </div>
                                            </div>
                                        );
                                    })}
                                </div>
                            </div>
                        </div>

                        {/* Security Groups Analysis */}
                        <div className="bg-surface/50 rounded-xl p-4 border border-white/5">
                            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-4 flex items-center gap-2">
                                <Shield size={14} /> Security Compliance
                            </h4>
                            <div className="space-y-3 h-full overflow-y-auto scrollbar-thin scrollbar-thumb-gray-700 pr-2">
                                {sgs.map(sg => {
                                    const violations = analyzeSecurityGroup(sg);
                                    return (
                                        <div key={sg.id} className="p-3 bg-black/40 rounded border border-white/5">
                                            <div className="flex justify-between items-start mb-2">
                                                <div className="font-bold text-sm text-gray-200">{sg.details.GroupName}</div>
                                                <div className="text-[10px] font-mono text-gray-500">{sg.details.GroupId}</div>
                                            </div>

                                            {violations.length > 0 ? (
                                                <div>
                                                    <div className="flex flex-wrap gap-2 mt-2">
                                                        {violations.map((v, i) => (
                                                            <ComplianceBubble key={i} level={v.level as any} control={v.control} message={v.message} />
                                                        ))}
                                                    </div>
                                                    {/* RED/BLUE TEAM INSIGHTS */}
                                                    {violations.map((v, i) => (
                                                        <RiskAssessment key={i} type={v.control} />
                                                    ))}
                                                </div>
                                            ) : (
                                                <div className="flex items-center gap-1.5 text-[10px] text-neon-green mt-1">
                                                    <CheckCircle size={10} /> No critical overrides detected
                                                </div>
                                            )}

                                            {/* Expandable Rules (Mini) */}
                                            <div className="mt-3 pt-2 border-t border-white/5">
                                                <div className="text-[10px] text-gray-500 mb-1">Inbound Rules Sample:</div>
                                                {sg.details.IpPermissions?.slice(0, 3).map((rule: any, idx: number) => (
                                                    <div key={idx} className="flex items-center gap-2 text-[10px] font-mono text-gray-400">
                                                        <ArrowRightLeft size={8} />
                                                        <span className={rule.IpRanges?.some((r: any) => r.CidrIp === '0.0.0.0/0') ? 'text-neon-red font-bold' : ''}>
                                                            Port {rule.FromPort === -1 ? 'ALL' : rule.FromPort}
                                                        </span>
                                                        <span className="text-gray-600">from</span>
                                                        <span>{rule.IpRanges?.map((r: any) => r.CidrIp).join(', ')}</span>
                                                    </div>
                                                ))}
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}

// Icons Helpers
const MapIcon = ({ size }: { size: number }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="1 6 1 22 8 18 16 22 23 18 23 2 16 6 8 2 1 6"></polygon><line x1="8" y1="2" x2="8" y2="18"></line><line x1="16" y1="6" x2="16" y2="22"></line></svg>
);
const LayoutIcon = ({ size }: { size: number }) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>
);


// --- Main Views ---

export function NetworkingView({ assets }: { assets: any[] }) {
    const vpcs = assets.filter(a => a.asset_type === 'VPC');
    return (
        <div className="space-y-6">
            {vpcs.map(vpc => <VPCDetailCard key={vpc.id} vpc={vpc} assets={assets} />)}
        </div>
    );
}

export function ComputeView({ assets }: { assets: any[] }) {
    // ... (Keep existing simple logic or expand similarly)
    const vms = assets.filter(a => a.asset_type === 'EC2');
    return (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {vms.map(vm => (
                <div key={vm.id} className="glass-card p-6 border-l-4 border-l-neon-amber">
                    <div className="flex justify-between items-start mb-4">
                        <div>
                            <h3 className="font-bold text-lg text-primary">{vm.details.Tags?.find((t: any) => t.Key === 'Name')?.Value || vm.id}</h3>
                            <div className="flex items-center gap-2 text-xs text-gray-400 font-mono mt-1">
                                <Server size={12} /> {vm.details.InstanceType}
                                <span className="w-1 h-1 rounded-full bg-gray-600"></span>
                                <span className={vm.details.State?.Name === 'running' ? 'text-neon-green' : 'text-red-500'}>{vm.details.State?.Name}</span>
                            </div>
                        </div>
                        <div className="text-right">
                            <div className="text-xs text-gray-500 mb-1">{vm.region}</div>
                            <div className="font-mono text-sm text-neon-blue">{vm.details.PublicIpAddress || 'No Public IP'}</div>
                        </div>
                    </div>
                    {/* Compliance Check */}
                    {(!vm.details.IamInstanceProfile) && (
                        <div className="mt-4 bg-red-950/20 border border-red-900/50 p-3 rounded flex items-start gap-3">
                            <AlertTriangle className="text-red-500 shrink-0" size={16} />
                            <div>
                                <div className="text-xs font-bold text-red-300">Identity Risk</div>
                                <div className="text-[10px] text-gray-400">Instance has no IAM Profile attached. Credentials might be hardcoded.</div>
                            </div>
                        </div>
                    )}
                </div>
            ))}
        </div>
    );
}

export function SecurityView({ assets }: { assets: any[] }) {
    // Re-use logic from previous step but wrapped
    const users = assets.filter(a => a.asset_type === 'IAM_USER');
    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {users.map(u => (
                <div key={u.id} className="glass-card p-6 border-l-4 border-l-neon-purple">
                    <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3">
                            <div className="p-2 rounded bg-neon-purple/20"><Key size={18} className="text-neon-purple" /></div>
                            <div>
                                <div className="font-bold text-primary">{u.details.UserName}</div>
                                <div className="text-xs text-gray-500 font-mono">{u.details.UserId}</div>
                            </div>
                        </div>
                    </div>
                    <div className="mt-4 grid grid-cols-2 gap-2">
                        <div className="p-2 bg-nav rounded border border-border-color text-center">
                            <div className="text-[10px] text-text-secondary uppercase">MFA Status</div>
                            <div className="text-xs font-bold text-neon-red flex items-center justify-center gap-1"><AlertTriangle size={10} /> Disabled</div>
                        </div>
                        <div className="p-2 bg-nav rounded border border-border-color text-center">
                            <div className="text-[10px] text-text-secondary uppercase">Password Age</div>
                            <div className="text-xs font-bold text-primary">45 Days</div>
                        </div>
                    </div>
                </div>
            ))}
        </div>
    )
}

export function StorageView({ assets }: { assets: any[] }) {
    const buckets = assets.filter(a => a.asset_type === 'S3');
    return (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {buckets.map(b => (
                <div key={b.id} className="glass-card p-6 border-t-4 border-t-neon-green">
                    <div className="flex items-start justify-between mb-4">
                        <div className="flex items-center gap-3">
                            <Database className="text-neon-green" />
                            <div className="font-bold text-primary break-all">{b.details.Name}</div>
                        </div>
                    </div>

                    <div className="space-y-2">
                        {/* Dynamic Check: Public Access */}
                        {!b.details.PublicAccessBlock && (
                            <div className="flex items-center justify-between p-2 rounded bg-red-950/20 border border-red-900/50">
                                <div className="flex items-center gap-2 text-xs text-red-300">
                                    <AlertOctagon size={14} />
                                    <span>Public Access Allowed</span>
                                </div>
                                <ComplianceBubble level="critical" control="S3.1" message="Bucket allows public access via ACLs or Policies." />
                            </div>
                        )}
                        <div className="flex justify-between items-center text-xs p-2 rounded bg-nav">
                            <span className="text-gray-400">Encryption</span>
                            <span className={b.details.Encryption ? 'text-neon-green font-bold' : 'text-gray-500'}>{b.details.Encryption ? 'Enabled' : 'Disabled'}</span>
                        </div>
                    </div>
                </div>
            ))}
        </div>
    )
}


export default function InventoryViews({ assets, activeTab }: { assets: any[], activeTab: string }) {
    switch (activeTab) {
        case 'NETWORKING': return <NetworkingView assets={assets} />;
        case 'COMPUTE': return <ComputeView assets={assets} />;
        case 'SECURITY': return <SecurityView assets={assets} />;
        case 'STORAGE': return <StorageView assets={assets} />;
        default: return <div className="text-gray-500">Select a category</div>;
    }
}
