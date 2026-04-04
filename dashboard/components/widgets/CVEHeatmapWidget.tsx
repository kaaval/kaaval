'use client';

import { useEffect, useState } from 'react';
import axios from 'axios';
import { WidgetProps } from './WidgetRegistry';

interface Breakdown {
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  UNKNOWN: number;
}

const BARS = [
  { key: 'CRITICAL', color: 'bg-red-500',    label: 'Critical' },
  { key: 'HIGH',     color: 'bg-orange-500', label: 'High' },
  { key: 'MEDIUM',   color: 'bg-yellow-500', label: 'Medium' },
  { key: 'LOW',      color: 'bg-blue-500',   label: 'Low' },
  { key: 'UNKNOWN',  color: 'bg-gray-600',   label: 'Unknown' },
];

export function CVEHeatmapWidget({}: WidgetProps) {
  const [breakdown, setBreakdown] = useState<Breakdown | null>(null);
  const [total, setTotal] = useState(0);

  useEffect(() => {
    const api = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    axios.get(`${api}/api/v1/cve/scan/latest`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
    })
      .then((r) => {
        const bd = r.data?.severity_breakdown;
        if (bd) {
          setBreakdown(bd);
          setTotal(Object.values(bd as Record<string,number>).reduce((a, b) => a + b, 0));
        }
      })
      .catch(() => {});
  }, []);

  if (!breakdown) return <div className="text-gray-500 text-sm">No CVE scan data</div>;

  return (
    <div className="flex flex-col gap-2 h-full justify-center">
      {BARS.map(({ key, color, label }) => {
        const count = breakdown[key as keyof Breakdown] || 0;
        const pct = total > 0 ? (count / total) * 100 : 0;
        return (
          <div key={key} className="flex items-center gap-2">
            <span className="text-xs text-gray-400 w-14 shrink-0">{label}</span>
            <div className="flex-1 h-3 bg-gray-800 rounded-full overflow-hidden">
              <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${pct}%` }} />
            </div>
            <span className="text-xs text-gray-400 w-6 text-right">{count}</span>
          </div>
        );
      })}
      <p className="text-xs text-gray-600 mt-1">{total} CVEs checked</p>
    </div>
  );
}
