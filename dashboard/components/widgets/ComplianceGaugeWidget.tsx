'use client';

import { useEffect, useState } from 'react';
import axios from 'axios';
import { WidgetProps } from './WidgetRegistry';

export function ComplianceGaugeWidget({ config }: WidgetProps) {
  const framework = (config.framework as string) || '';
  const [score, setScore] = useState<number | null>(null);
  const [pass, setPass] = useState(0);
  const [fail, setFail] = useState(0);

  useEffect(() => {
    const api = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    axios.get(`${api}/api/v1/compliance/summary`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
    })
      .then((r) => {
        const data = framework ? r.data?.[framework] : Object.values(r.data || {})[0];
        if (data) {
          const p = (data as { pass: number }).pass || 0;
          const f = (data as { fail: number }).fail || 0;
          setPass(p);
          setFail(f);
          setScore(p + f > 0 ? Math.round((p / (p + f)) * 100) : null);
        }
      })
      .catch(() => {});
  }, [framework]);

  const color = score === null ? 'text-gray-500' : score >= 80 ? 'text-green-400' : score >= 60 ? 'text-yellow-400' : 'text-red-400';

  return (
    <div className="flex flex-col items-center justify-center h-full gap-1">
      <p className={`text-5xl font-bold ${color}`}>{score === null ? '—' : `${score}%`}</p>
      <p className="text-xs text-gray-500">{framework || 'Overall'} compliance</p>
      {score !== null && (
        <p className="text-[10px] text-gray-600 mt-1">{pass} pass · {fail} fail</p>
      )}
    </div>
  );
}
