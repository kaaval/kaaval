"use client";

import React, { useState } from 'react';
import dynamic from 'next/dynamic';
import { Play } from 'lucide-react';

const ActivityFeed = dynamic(() => import('../../components/ActivityFeed'), { ssr: false });

export default function LogsPage() {
    const [streamId, setStreamId] = useState<string>("audit-log-001");
    const [activeStream, setActiveStream] = useState<string>("audit-log-001");
    const [key, setKey] = useState(0); // Force remount to reconnect

    const handleConnect = () => {
        setActiveStream(streamId);
        setKey(prev => prev + 1);
    };

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h1 className="text-2xl font-bold text-white">Security Audit Log</h1>
                    <p className="text-gray-400">Real-time structured event feed for compliance and security operations.</p>
                </div>
                <div className="flex gap-2">
                    <input
                        type="text"
                        value={streamId}
                        onChange={(e) => setStreamId(e.target.value)}
                        className="bg-surface border border-gray-700 rounded-md px-3 py-2 text-sm text-white focus:outline-none focus:border-neon-blue"
                        placeholder="Stream ID (e.g. audit-log-001)"
                    />
                    <button
                        onClick={handleConnect}
                        className="bg-neon-blue/10 hover:bg-neon-blue/20 text-neon-blue border border-neon-blue/50 px-4 py-2 rounded-md text-sm font-medium flex items-center gap-2 transition-colors"
                    >
                        <Play size={16} />
                        Connect
                    </button>
                </div>
            </div>

            <div className="h-[600px] w-full">
                <ActivityFeed key={key} sourceId={activeStream} />
            </div>
        </div>
    );
}
