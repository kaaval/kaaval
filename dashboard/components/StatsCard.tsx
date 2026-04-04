import React from 'react';

interface StatsCardProps {
    title: string;
    value: string | number;
    icon?: string;
    color?: string;
}

export default function StatsCard({ title, value, icon, color = "blue" }: StatsCardProps) {
    const colorClasses = {
        blue: "text-neon-blue border-neon-blue/20 bg-neon-blue/5 shadow-[0_0_10px_rgba(0,212,255,0.1)]",
        green: "text-neon-green border-neon-green/20 bg-neon-green/5 shadow-[0_0_10px_rgba(0,255,157,0.1)]",
        purple: "text-purple-400 border-purple-500/20 bg-purple-500/5",
        orange: "text-neon-amber border-neon-amber/20 bg-neon-amber/5",
    };

    const activeColor = colorClasses[color as keyof typeof colorClasses] || colorClasses.blue;

    return (
        <div className={`p-6 rounded-none border border-l-4 backdrop-blur-sm transition-all hover:bg-white/5 ${activeColor.replace('text-', 'border-')}`}>
            <div className="flex justify-between items-start mb-2">
                <h3 className="text-gray-400 font-mono text-[10px] tracking-widest uppercase">{title}</h3>
                {icon && <span className="text-lg opacity-80">{icon}</span>}
            </div>
            <div className={`text-4xl font-bold font-mono tracking-tighter ${activeColor.split(' ')[0]}`}>
                {value}
            </div>
        </div>
    );
}
