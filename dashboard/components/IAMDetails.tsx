"use client";

import { Shield, Key, Users, FileText, CheckCircle, XCircle } from 'lucide-react';

interface IAMDetailsProps {
    details: any;
}

export default function IAMDetails({ details }: IAMDetailsProps) {
    // Helper to format dates
    const formatDate = (dateStr: string) => {
        if (!dateStr) return 'Never';
        return new Date(dateStr).toLocaleDateString();
    };

    return (
        <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
                <div className="p-3 bg-surface/50 rounded-lg border border-border-color">
                    <div className="text-xs text-text-secondary uppercase tracking-wider mb-1">Status</div>
                    <div className="flex items-center gap-2">
                        {details.PasswordLastUsed ? (
                            <CheckCircle size={16} className="text-neon-green" />
                        ) : (
                            <XCircle size={16} className="text-gray-500" />
                        )}
                        <span className="font-mono text-sm">
                            {details.PasswordLastUsed ? 'Active' : 'Inactive'}
                        </span>
                    </div>
                </div>
                <div className="p-3 bg-surface/50 rounded-lg border border-border-color">
                    <div className="text-xs text-text-secondary uppercase tracking-wider mb-1">MFA Status</div>
                    <div className="flex items-center gap-2">
                        {/* Mock MFA check - in real app, this comes from credential report */}
                        <XCircle size={16} className="text-neon-red" />
                        <span className="font-mono text-sm text-neon-red">Disabled</span>
                    </div>
                </div>
            </div>

            {/* Groups */}
            <div>
                <div className="flex items-center gap-2 text-sm font-semibold text-neon-blue mb-2">
                    <Users size={14} />
                    <span>Groups</span>
                </div>
                <div className="flex flex-wrap gap-2">
                    {details.Groups && details.Groups.length > 0 ? (
                        details.Groups.map((g: any) => (
                            <span key={g.GroupId} className="px-2 py-1 rounded bg-neon-blue/10 text-neon-blue text-xs border border-neon-blue/20">
                                {g.GroupName}
                            </span>
                        ))
                    ) : (
                        <span className="text-xs text-text-secondary italic">No groups assigned</span>
                    )}
                </div>
            </div>

            {/* Policies */}
            <div>
                <div className="flex items-center gap-2 text-sm font-semibold text-neon-purple mb-2">
                    <FileText size={14} />
                    <span>Attached Policies</span>
                </div>
                <div className="space-y-1">
                    {details.Policies && details.Policies.length > 0 ? (
                        details.Policies.map((p: any) => (
                            <div key={p.PolicyName} className="flex justify-between items-center text-xs p-1.5 rounded bg-surface border border-border-color">
                                <span className="text-text-primary">{p.PolicyName}</span>
                                <span className="text-text-secondary text-[10px]">{p.PolicyArn ? 'Managed' : 'Inline'}</span>
                            </div>
                        ))
                    ) : (
                        <span className="text-xs text-text-secondary italic">No policies attached</span>
                    )}
                </div>
            </div>

            {/* Keys */}
            <div className="pt-2 border-t border-border-color">
                <div className="flex justify-between text-xs text-text-secondary">
                    <span>Created: {formatDate(details.CreateDate)}</span>
                    <span>ID: {details.UserId?.substring(0, 8)}...</span>
                </div>
            </div>
        </div>
    );
}
