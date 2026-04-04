"use client";

import React, { useEffect, useRef, useState } from 'react';
import { useAuth } from './AuthContext';
import { Shield, AlertTriangle, CheckCircle, Info, Server, Activity } from 'lucide-react';

interface ActivityEvent {
    timestamp: string;
    type: "INFO" | "SUCCESS" | "WARNING" | "CRITICAL" | "ERROR" | "SYSTEM";
    message: string;
    component: string;
}

interface ActivityFeedProps {
    sourceId: string;
}

const ActivityFeed: React.FC<ActivityFeedProps> = ({ sourceId }) => {
    const { token } = useAuth();
    const [events, setEvents] = useState<ActivityEvent[]>([]);
    const [status, setStatus] = useState<string>("Connecting...");
    const scrollRef = useRef<HTMLDivElement>(null);

    // Auto-scroll to bottom
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollIntoView({ behavior: 'smooth' });
        }
    }, [events]);

    useEffect(() => {
        if (!token) return;

        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `ws://localhost:8001/api/v1/logs/stream/${sourceId}`;

        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
            setStatus("Live");
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                setEvents(prev => [...prev, data]);
            } catch (e) {
                console.error("Failed to parse event:", event.data);
            }
        };

        ws.onclose = () => {
            setStatus("Disconnected");
        };

        return () => {
            ws.close();
        };
    }, [sourceId, token]);

    const getIcon = (type: string) => {
        switch (type) {
            case 'CRITICAL': return <AlertTriangle className="text-neon-red" size={20} />;
            case 'WARNING': return <AlertTriangle className="text-neon-amber" size={20} />;
            case 'SUCCESS': return <CheckCircle className="text-neon-green" size={20} />;
            case 'SYSTEM': return <Server className="text-gray-400" size={20} />;
            default: return <Info className="text-neon-blue" size={20} />;
        }
    };

    const getBorderColor = (type: string) => {
        switch (type) {
            case 'CRITICAL': return 'border-neon-red/50 bg-neon-red/5';
            case 'WARNING': return 'border-neon-amber/50 bg-neon-amber/5';
            case 'SUCCESS': return 'border-neon-green/30 bg-neon-green/5';
            case 'SYSTEM': return 'border-gray-700 bg-gray-900/50';
            default: return 'border-neon-blue/30 bg-neon-blue/5';
        }
    };

    return (
        <div className="flex flex-col h-full bg-black/40 rounded-lg overflow-hidden border border-gray-800 shadow-2xl backdrop-blur-sm">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 bg-gray-900/80 border-b border-gray-800">
                <div className="flex items-center gap-2">
                    <Activity className="text-neon-purple" size={18} />
                    <span className="font-bold text-gray-200">Security Activity Stream</span>
                </div>
                <div className="flex items-center gap-2">
                    <span className={`w-2 h-2 rounded-full ${status === 'Live' ? 'bg-neon-green animate-pulse' : 'bg-gray-500'}`}></span>
                    <span className="text-xs text-gray-400 font-mono uppercase">{status}</span>
                </div>
            </div>

            {/* Event List */}
            <div className="flex-1 overflow-y-auto p-4 space-y-3 scrollbar-thin scrollbar-thumb-gray-800">
                {events.length === 0 && (
                    <div className="text-center text-gray-500 mt-10 italic">Waiting for activity...</div>
                )}

                {events.map((event, idx) => (
                    <div
                        key={idx}
                        className={`flex items-start gap-4 p-3 rounded-md border ${getBorderColor(event.type)} transition-all duration-300 animate-in fade-in slide-in-from-bottom-2`}
                    >
                        <div className="mt-1 flex-shrink-0">
                            {getIcon(event.type)}
                        </div>
                        <div className="flex-1 min-w-0">
                            <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-mono text-gray-500">{new Date(event.timestamp).toLocaleTimeString()}</span>
                                <span className="text-[10px] uppercase font-bold tracking-wider text-gray-600 bg-gray-900/50 px-2 py-0.5 rounded">
                                    {event.component}
                                </span>
                            </div>
                            <p className="text-sm text-gray-200 font-medium break-words leading-relaxed">
                                {event.message}
                            </p>
                        </div>
                    </div>
                ))}
                <div ref={scrollRef} />
            </div>
        </div>
    );
};

export default ActivityFeed;
