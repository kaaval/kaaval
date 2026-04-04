'use client';

import { useEffect, useState, useCallback } from 'react';
import axios from 'axios';
import { WidgetCanvas } from '@/components/widgets/WidgetCanvas';
import { WIDGET_REGISTRY } from '@/components/widgets/WidgetRegistry';
import type { Layout } from 'react-grid-layout';

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

interface WidgetInstance {
  id: string;
  widget_type: string;
  title?: string;
  grid_x: number;
  grid_y: number;
  grid_w: number;
  grid_h: number;
  config: Record<string, unknown>;
}

interface Dashboard {
  id: string;
  name: string;
  is_default: boolean;
  widgets: WidgetInstance[];
}

function authHeaders() {
  return { Authorization: `Bearer ${localStorage.getItem('token')}` };
}

export default function HomePage() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [dashboardList, setDashboardList] = useState<{ id: string; name: string }[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  // Load or create the default dashboard
  useEffect(() => {
    axios.get(`${API}/api/v1/dashboards`, { headers: authHeaders() })
      .then(async (r) => {
        const list = r.data as { id: string; name: string; is_default: boolean }[];
        setDashboardList(list);
        const def = list.find((d) => d.is_default) || list[0];
        if (def) {
          const detail = await axios.get(`${API}/api/v1/dashboards/${def.id}`, { headers: authHeaders() });
          setDashboard(detail.data);
        } else {
          // First visit — create a default dashboard
          const created = await axios.post(`${API}/api/v1/dashboards`, { name: 'My Dashboard', is_default: true }, { headers: authHeaders() });
          const detail = await axios.get(`${API}/api/v1/dashboards/${created.data.id}`, { headers: authHeaders() });
          setDashboard(detail.data);
          setDashboardList([{ id: created.data.id, name: 'My Dashboard' }]);
        }
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleLayoutChange = useCallback(async (positions: Layout[]) => {
    if (!dashboard) return;
    setSaving(true);
    try {
      await axios.patch(
        `${API}/api/v1/dashboards/${dashboard.id}/layout`,
        { positions: positions.map((p) => ({ id: p.i, grid_x: p.x, grid_y: p.y, grid_w: p.w, grid_h: p.h })) },
        { headers: authHeaders() }
      );
    } finally {
      setSaving(false);
    }
  }, [dashboard]);

  const handleAddWidget = useCallback(async (widgetType: string) => {
    if (!dashboard) return;
    const def = WIDGET_REGISTRY[widgetType];
    const res = await axios.post(
      `${API}/api/v1/dashboards/${dashboard.id}/widgets`,
      {
        widget_type: widgetType,
        title: def.label,
        grid_x: 0,
        grid_y: 99,
        grid_w: def.defaultSize.w,
        grid_h: def.defaultSize.h,
        config: {},
      },
      { headers: authHeaders() }
    );
    setDashboard((prev) => prev ? {
      ...prev,
      widgets: [...prev.widgets, {
        id: res.data.id,
        widget_type: widgetType,
        title: def.label,
        grid_x: 0, grid_y: 99,
        grid_w: def.defaultSize.w,
        grid_h: def.defaultSize.h,
        config: {},
      }],
    } : prev);
  }, [dashboard]);

  const handleRemoveWidget = useCallback(async (widgetId: string) => {
    if (!dashboard) return;
    await axios.delete(`${API}/api/v1/dashboards/${dashboard.id}/widgets/${widgetId}`, { headers: authHeaders() });
    setDashboard((prev) => prev ? { ...prev, widgets: prev.widgets.filter((w) => w.id !== widgetId) } : prev);
  }, [dashboard]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96 text-gray-400">
        Loading dashboard...
      </div>
    );
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">{dashboard?.name || 'Dashboard'}</h1>
          <p className="text-sm text-gray-500 mt-0.5">Drag and resize widgets to customise your view</p>
        </div>
        <div className="flex items-center gap-3">
          {saving && <span className="text-xs text-gray-500 animate-pulse">Saving...</span>}
          {/* Dashboard switcher */}
          {dashboardList.length > 1 && (
            <select
              className="text-sm bg-gray-800 border border-gray-700 text-gray-200 rounded-lg px-3 py-1.5"
              value={dashboard?.id}
              onChange={async (e) => {
                const detail = await axios.get(`${API}/api/v1/dashboards/${e.target.value}`, { headers: authHeaders() });
                setDashboard(detail.data);
              }}
            >
              {dashboardList.map((d) => <option key={d.id} value={d.id}>{d.name}</option>)}
            </select>
          )}
          <button
            onClick={async () => {
              const name = prompt('Dashboard name:');
              if (!name) return;
              const created = await axios.post(`${API}/api/v1/dashboards`, { name }, { headers: authHeaders() });
              const detail = await axios.get(`${API}/api/v1/dashboards/${created.data.id}`, { headers: authHeaders() });
              setDashboard(detail.data);
              setDashboardList((prev) => [...prev, { id: created.data.id, name }]);
            }}
            className="text-sm px-3 py-1.5 bg-gray-800 border border-gray-700 text-gray-300 rounded-lg hover:bg-gray-700 transition-colors"
          >
            + New Dashboard
          </button>
        </div>
      </div>

      {dashboard && (
        <WidgetCanvas
          dashboardId={dashboard.id}
          widgets={dashboard.widgets}
          onLayoutChange={handleLayoutChange}
          onAddWidget={handleAddWidget}
          onRemoveWidget={handleRemoveWidget}
          editable
        />
      )}
    </div>
  );
}
