'use client';

import { ComponentType } from 'react';
import { StatCardWidget } from './StatCardWidget';
import { CVEHeatmapWidget } from './CVEHeatmapWidget';
import { ComplianceGaugeWidget } from './ComplianceGaugeWidget';
import { AlertFeedWidget } from './AlertFeedWidget';
import { EndpointListWidget } from './EndpointListWidget';
import { CloudInventoryWidget } from './CloudInventoryWidget';

export interface WidgetConfig {
  [key: string]: unknown;
}

export interface WidgetProps {
  config: WidgetConfig;
  title?: string;
}

export interface WidgetDefinition {
  component: ComponentType<WidgetProps>;
  label: string;
  description: string;
  defaultSize: { w: number; h: number };
  icon: string;
}

export const WIDGET_REGISTRY: Record<string, WidgetDefinition> = {
  stat_card: {
    component: StatCardWidget,
    label: 'Stat Counter',
    description: 'Display a single key metric (assets, CVEs, endpoints, findings)',
    defaultSize: { w: 2, h: 2 },
    icon: '📊',
  },
  cve_heatmap: {
    component: CVEHeatmapWidget,
    label: 'CVE Heatmap',
    description: 'Severity breakdown of CVEs affecting your cluster or endpoints',
    defaultSize: { w: 4, h: 3 },
    icon: '🔴',
  },
  compliance_gauge: {
    component: ComplianceGaugeWidget,
    label: 'Compliance Score',
    description: 'Pass/fail ratio for a selected compliance framework',
    defaultSize: { w: 2, h: 2 },
    icon: '✅',
  },
  alert_feed: {
    component: AlertFeedWidget,
    label: 'Integration Alerts',
    description: 'Live feed of findings from all installed integrations',
    defaultSize: { w: 4, h: 4 },
    icon: '🔔',
  },
  endpoint_list: {
    component: EndpointListWidget,
    label: 'Endpoint Status',
    description: 'Table of enrolled agents with online/offline status',
    defaultSize: { w: 3, h: 4 },
    icon: '💻',
  },
  cloud_inventory: {
    component: CloudInventoryWidget,
    label: 'Cloud Assets',
    description: 'Asset breakdown by type from the last cloud scan',
    defaultSize: { w: 3, h: 3 },
    icon: '☁️',
  },
};
