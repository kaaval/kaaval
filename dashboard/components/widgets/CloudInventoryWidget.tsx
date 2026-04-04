'use client';

import { useEffect, useState } from 'react';
import axios from 'axios';
import { WidgetProps } from './WidgetRegistry';

export function CloudInventoryWidget({}: WidgetProps) {
  const [stats, setStats] = useState<{ total_assets: number; ec2_count?: number; iam_count?: number } | null>(null);

  useEffect(() => {
    const api = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    axios.get(`${api}/api/v1/stats`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
    })
      .then((r) => setStats(r.data))
      .catch(() => {});
  }, []);

  const rows = [
    { label: 'Total Assets', value: stats?.total_assets },
    { label: 'EC2 Instances', value: stats?.ec2_count },
    { label: 'IAM Users', value: stats?.iam_count },
  ];

  return (
    <div className="flex flex-col gap-2 h-full justify-center">
      {rows.map(({ label, value }) => (
        <div key={label} className="flex items-center justify-between">
          <span className="text-xs text-gray-400">{label}</span>
          <span className="text-sm font-semibold text-gray-200">
            {value === undefined || value === null ? '—' : value.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}
