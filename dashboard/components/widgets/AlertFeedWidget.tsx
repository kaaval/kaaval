'use client';

import { useEffect, useState } from 'react';
import axios from 'axios';
import { WidgetProps } from './WidgetRegistry';

const SEV_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-500/20 text-red-400 border-red-500/40',
  HIGH:     'bg-orange-500/20 text-orange-400 border-orange-500/40',
  MEDIUM:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  LOW:      'bg-blue-500/20 text-blue-400 border-blue-500/40',
  INFO:     'bg-gray-500/20 text-gray-400 border-gray-500/40',
};

interface Finding {
  id: string;
  source_tool: string;
  severity: string;
  title: string;
  detected_at: string;
}

export function AlertFeedWidget({ config }: WidgetProps) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const integrationId = config.integration_id as string | undefined;

  useEffect(() => {
    const api = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    if (!integrationId) { setLoading(false); return; }
    axios.get(`${api}/api/v1/integrations/${integrationId}/findings?limit=20`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
    })
      .then((r) => setFindings(r.data.findings || []))
      .catch(() => setFindings([]))
      .finally(() => setLoading(false));
  }, [integrationId]);

  if (!integrationId) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500 text-sm">
        Configure an integration_id in widget settings
      </div>
    );
  }

  if (loading) return <div className="text-gray-500 text-sm">Loading...</div>;

  if (findings.length === 0)
    return <div className="text-gray-500 text-sm">No findings yet</div>;

  return (
    <div className="flex flex-col gap-1.5 overflow-y-auto h-full">
      {findings.map((f) => (
        <div key={f.id} className="flex items-start gap-2 p-2 rounded-lg bg-gray-800/60">
          <span className={`text-[10px] px-1.5 py-0.5 rounded border font-semibold shrink-0 ${SEV_COLORS[f.severity] || SEV_COLORS.INFO}`}>
            {f.severity}
          </span>
          <div className="flex-1 min-w-0">
            <p className="text-xs text-gray-200 truncate">{f.title}</p>
            <p className="text-[10px] text-gray-500 mt-0.5">{f.source_tool} · {new Date(f.detected_at).toLocaleTimeString()}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
