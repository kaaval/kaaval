"use client";

import React from 'react';

interface TimeSliderProps {
    value: number;
    onChange: (val: number) => void;
}

export default function TimeSlider({ value, onChange }: TimeSliderProps) {
    return (
        <div className="fixed bottom-0 left-64 right-0 p-4 bg-black/80 backdrop-blur-md border-t border-gray-800/50 z-40">
            <div className="flex items-center gap-4 max-w-4xl mx-auto">
                <div className="text-neon-blue font-mono text-xs whitespace-nowrap">
                    {value === 100 ? "● LIVE STREAM" : `↺ REPLAY: -${100 - value}m`}
                </div>

                <div className="relative flex-1 h-12 flex items-center">
                    {/* Timeline Ticks */}
                    <div className="absolute inset-x-0 h-2 flex justify-between px-2 opacity-30 pointer-events-none">
                        {Array.from({ length: 20 }).map((_, i) => (
                            <div key={i} className="w-[1px] h-full bg-neon-blue"></div>
                        ))}
                    </div>

                    {/* The Slider Input */}
                    <input
                        type="range"
                        min="0"
                        max="100"
                        value={value}
                        onChange={(e) => onChange(parseInt(e.target.value))}
                        className="w-full h-1 bg-gray-800 rounded-lg appearance-none cursor-pointer accent-neon-green z-10 hover:accent-neon-blue transition-all"
                    />
                </div>

                <button
                    onClick={() => onChange(100)}
                    className="px-3 py-1 border border-neon-green/30 text-neon-green text-xs font-mono rounded hover:bg-neon-green/10 transition-colors"
                >
                    JUMP TO NOW
                </button>
            </div>
        </div>
    );
}
