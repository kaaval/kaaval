"use client";

import React, { useState } from 'react';

interface Asset {
    id: string;
    asset_type: string;
    status?: string; // e.g. "RUNNING", "STOPPED"
    details: any;
}

interface HoneycombGridProps {
    assets: Asset[];
}

const HEX_SIZE = 30; // Radius
const HEX_WIDTH = Math.sqrt(3) * HEX_SIZE;
const HEX_HEIGHT = 2 * HEX_SIZE;
const GAP = 4;

export default function HoneycombGrid({ assets }: HoneycombGridProps) {
    const [hoveredAsset, setHoveredAsset] = useState<Asset | null>(null);

    // Calculate grid positions
    const columns = 12; // Fixed columns for now, or calculate based on width

    const getHexPoints = (x: number, y: number, radius: number) => {
        const points = [];
        for (let i = 0; i < 6; i++) {
            const angle_deg = 60 * i - 30;
            const angle_rad = Math.PI / 180 * angle_deg;
            points.push(`${x + radius * Math.cos(angle_rad)},${y + radius * Math.sin(angle_rad)}`);
        }
        return points.join(" ");
    };

    const getColor = (asset: Asset) => {
        // Mock status logic if missing from API
        const status = asset.status || (Math.random() > 0.8 ? "STOPPED" : "RUNNING");
        if (status === "RUNNING") return "#00ff9d"; // neon-green
        if (status === "STOPPED") return "#ff0055"; // neon-red
        return "#ffbe0b"; // neon-amber
    };

    return (
        <div className="relative w-full overflow-visible p-4">
            {/* Tooltip Overlay */}
            {hoveredAsset && (
                <div className="absolute z-50 pointer-events-none p-4 bg-black/80 backdrop-blur-md border border-neon-blue/30 rounded-lg shadow-[0_0_20px_rgba(0,212,255,0.2)]"
                    style={{ top: 0, right: 0 }}
                >
                    <div className="text-neon-blue font-mono font-bold text-sm mb-1">{hoveredAsset.asset_type}</div>
                    <div className="text-white text-xs font-mono mb-1">{hoveredAsset.id}</div>
                    <div className="text-xs text-gray-400">
                        <div>Region: {hoveredAsset.details.region || 'us-east-1'}</div>
                        <div className={getColor(hoveredAsset) === "#00ff9d" ? "text-neon-green" : "text-neon-red"}>
                            Status: {hoveredAsset.status || "UNKNOWN"}
                        </div>
                    </div>
                </div>
            )}

            <svg width="100%" height={Math.ceil(assets.length / columns) * (HEX_HEIGHT * 0.75) + HEX_HEIGHT} className="overflow-visible">
                {assets.map((asset, i) => {
                    const col = i % columns;
                    const row = Math.floor(i / columns);

                    const xOffset = (row % 2 === 0) ? 0 : HEX_WIDTH / 2;
                    const x = col * (HEX_WIDTH + GAP) + xOffset + HEX_SIZE;
                    const y = row * ((HEX_HEIGHT * 0.75) + GAP) + HEX_SIZE;

                    const color = getColor(asset);
                    const isHovered = hoveredAsset?.id === asset.id;

                    return (
                        <g key={asset.id}
                            onMouseEnter={() => setHoveredAsset(asset)}
                            onMouseLeave={() => setHoveredAsset(null)}
                            className="cursor-pointer transition-all duration-300"
                            style={{ transformOrigin: `${x}px ${y}px`, transform: isHovered ? "scale(1.1)" : "scale(1)" }}
                        >
                            <polygon
                                points={getHexPoints(x, y, HEX_SIZE - 2)}
                                fill={isHovered ? color : `${color}40`} // 25% opacity default, 100% hover
                                stroke={color}
                                strokeWidth={isHovered ? 2 : 1}
                                className="transition-all duration-300"
                            />
                            <text x={x} y={y} fontSize="8" fill="white" textAnchor="middle" dy=".3em" className="pointer-events-none font-mono opacity-60">
                                {asset.asset_type.substring(0, 3)}
                            </text>

                            {/* Glow Effect on Hover */}
                            {isHovered && (
                                <polygon
                                    points={getHexPoints(x, y, HEX_SIZE + 4)}
                                    fill="none"
                                    stroke={color}
                                    strokeWidth={1}
                                    strokeOpacity={0.5}
                                    filter="url(#glow)"
                                />
                            )}
                        </g>
                    );
                })}
                <defs>
                    <filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
                        <feGaussianBlur stdDeviation="3" result="coloredBlur" />
                        <feMerge>
                            <feMergeNode in="coloredBlur" />
                            <feMergeNode in="SourceGraphic" />
                        </feMerge>
                    </filter>
                </defs>
            </svg>
        </div>
    );
}
