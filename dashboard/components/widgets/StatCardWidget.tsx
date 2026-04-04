'use client';

import { useEffect, useState } from 'react';
import axios from 'axios';
import { WidgetProps } from './WidgetRegistry';

const METRIC_CONFIG: Record<string, { label: string; color: string; unit?: string }> = {
  total_assets:     { label: 'Total Assets',      color: 'text-blue-400' },
  open_cves:        { label: 'Open CVEs',          color: 'text-red-400' },
  online_endpoints: { label: 'Online Endpoints',   color: 'text-green-400' },
  open_findings:    { label: 'Open Findings',      color: 'text-yellow-400' },
};

export function StatCardWidget({ config }: WidgetProps) {
  const metric = (config.metric as string) || 'total_assets';
  const meta = METRIC_CONFIG[metric] || { label: metric, color: 'text-gray-300' };
  const [value, setValue] = useState<number | null>(null);

  useEffect(() => {
    const api = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    axios.get(`${api}/api/v1/stats`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
    })
      .then((r) => setValue(r.data[metric] ?? null))
      .catch(() => setValue(null));
  }, [metric]);

  return (
    <div className="flex flex-col items-center justify-center h-full">
      <p className={`text-4xl font-bold ${meta.color}`}>
        {value === null ? '—' : value.toLocaleString()}
      </p>
      <p className="text-xs text-gray-500 mt-2 uppercase tracking-wider">{meta.label}</p>
    </div>
  );
}
