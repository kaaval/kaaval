'use client';

import { useState, useCallback } from 'react';
import GridLayout, { Layout } from 'react-grid-layout';
import { WIDGET_REGISTRY } from './WidgetRegistry';
import 'react-grid-layout/css/styles.css';
import 'react-resizable/css/styles.css';

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

interface WidgetCanvasProps {
  dashboardId: string;
  widgets: WidgetInstance[];
  onLayoutChange?: (positions: Layout[]) => void;
  onAddWidget?: (widgetType: string) => void;
  onRemoveWidget?: (widgetId: string) => void;
  editable?: boolean;
}

export function WidgetCanvas({
  dashboardId,
  widgets,
  onLayoutChange,
  onAddWidget,
  onRemoveWidget,
  editable = true,
}: WidgetCanvasProps) {
  const [showPalette, setShowPalette] = useState(false);

  const layout: Layout[] = widgets.map((w) => ({
    i: w.id,
    x: w.grid_x,
    y: w.grid_y,
    w: w.grid_w,
    h: w.grid_h,
    minW: 2,
    minH: 2,
  }));

  const handleLayoutChange = useCallback(
    (newLayout: Layout[]) => {
      if (onLayoutChange) onLayoutChange(newLayout);
    },
    [onLayoutChange]
  );

  return (
    <div className="relative w-full">
      {editable && (
        <div className="flex items-center justify-between mb-4">
          <span className="text-sm text-gray-400">
            {widgets.length} widget{widgets.length !== 1 ? 's' : ''}
          </span>
          <button
            onClick={() => setShowPalette((v) => !v)}
            className="px-3 py-1.5 text-sm bg-green-500/10 text-green-400 border border-green-500/30 rounded-lg hover:bg-green-500/20 transition-colors"
          >
            + Add Widget
          </button>
        </div>
      )}

      {/* Widget palette */}
      {showPalette && editable && (
        <div className="mb-4 p-4 bg-gray-900 border border-gray-700 rounded-xl grid grid-cols-2 md:grid-cols-3 gap-3">
          {Object.entries(WIDGET_REGISTRY).map(([type, def]) => (
            <button
              key={type}
              onClick={() => {
                onAddWidget?.(type);
                setShowPalette(false);
              }}
              className="flex items-start gap-3 p-3 bg-gray-800 hover:bg-gray-700 rounded-lg text-left transition-colors"
            >
              <span className="text-2xl">{def.icon}</span>
              <div>
                <p className="text-sm font-medium text-gray-200">{def.label}</p>
                <p className="text-xs text-gray-500 mt-0.5">{def.description}</p>
              </div>
            </button>
          ))}
        </div>
      )}

      {widgets.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 border-2 border-dashed border-gray-700 rounded-xl text-gray-500">
          <p className="text-lg font-medium">No widgets yet</p>
          <p className="text-sm mt-1">Click &quot;+ Add Widget&quot; to build your view</p>
        </div>
      ) : (
        <GridLayout
          className="layout"
          layout={layout}
          cols={12}
          rowHeight={80}
          width={1200}
          isDraggable={editable}
          isResizable={editable}
          onLayoutChange={handleLayoutChange}
          margin={[12, 12]}
        >
          {widgets.map((widget) => {
            const def = WIDGET_REGISTRY[widget.widget_type];
            if (!def) return null;
            const WidgetComponent = def.component;
            return (
              <div
                key={widget.id}
                className="bg-gray-900 border border-gray-700/60 rounded-xl overflow-hidden flex flex-col"
              >
                <div className="flex items-center justify-between px-3 py-2 border-b border-gray-700/60">
                  <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider">
                    {widget.title || def.label}
                  </span>
                  {editable && (
                    <button
                      onClick={() => onRemoveWidget?.(widget.id)}
                      className="text-gray-600 hover:text-red-400 text-xs transition-colors"
                      title="Remove widget"
                    >
                      ✕
                    </button>
                  )}
                </div>
                <div className="flex-1 p-3 overflow-hidden">
                  <WidgetComponent config={widget.config} title={widget.title} />
                </div>
              </div>
            );
          })}
        </GridLayout>
      )}
    </div>
  );
}
