'use client';

import { useEffect, useState } from 'react';
import axios from 'axios';
import { WidgetProps } from './WidgetRegistry';

interface Endpoint {
  id: string;
  hostname: string;
  ip_address: string;
  os_info: string;
  status: string;
  last_seen: string;
}

export function EndpointListWidget({}: WidgetProps) {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);

  useEffect(() => {
    const api = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    axios.get(`${api}/api/v1/endpoints`, {
      headers: { Authorization: `Bearer ${localStorage.getItem('token')}` },
    })
      .then((r) => setEndpoints(r.data || []))
      .catch(() => {});
  }, []);

  return (
    <div className="flex flex-col h-full overflow-y-auto gap-1">
      {endpoints.length === 0 && <p className="text-gray-500 text-sm">No agents enrolled</p>}
      {endpoints.map((e) => (
        <div key={e.id} className="flex items-center gap-2 p-1.5 rounded bg-gray-800/60">
          <span className={`w-2 h-2 rounded-full shrink-0 ${e.status === 'ONLINE' ? 'bg-green-400' : 'bg-gray-600'}`} />
          <div className="flex-1 min-w-0">
            <p className="text-xs text-gray-200 truncate">{e.hostname}</p>
            <p className="text-[10px] text-gray-500">{e.ip_address} · {e.os_info}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
