"use client";

import React from 'react';
import { Book, FileText, Code, Shield, CheckCircle } from 'lucide-react';

export default function DocsPage() {
    return (
        <div className="p-8 max-w-5xl mx-auto pb-20">
            <div className="mb-8 border-b border-border-color pb-6">
                <h1 className="text-4xl font-bold text-white mb-2 flex items-center gap-3">
                    <Book className="text-neon-blue" size={32} />
                    Argus Documentation
                </h1>
                <p className="text-text-secondary text-lg">
                    Official standards and guides for extending the Argus Security Visibility Platform.
                </p>
            </div>

            <div className="space-y-12">
                {/* Integration Standard Section */}
                <section className="glass-card p-8 rounded-xl border-l-4 border-l-neon-purple animate-in fade-in slide-in-from-bottom-4 duration-500">
                    <h2 className="text-2xl font-bold text-primary mb-6 flex items-center gap-2">
                        <Shield className="text-neon-purple" />
                        Integration Standard v1.0
                    </h2>

                    <div className="space-y-8 text-gray-300 leading-relaxed">

                        {/* 1. Purpose */}
                        <div>
                            <h3 className="text-xl font-semibold text-white mb-3">1. Purpose of Integrations</h3>
                            <p className="mb-4">
                                Integrations in Argus serve as modular &quot;Compliance Packs&quot; or &quot;Security Frameworks&quot;. They allow users to enable specific sets of security checks (e.g., CIS AWS, PCI-DSS, HIPAA) or connect third-party data sources (e.g., Wazuh, CrowdStrike, Qualys) without bloating the core engine with irrelevant logic.
                            </p>
                        </div>

                        {/* 2. Architecture */}
                        <div>
                            <h3 className="text-xl font-semibold text-white mb-3">2. Integration Architecture</h3>
                            <p className="mb-2">An integration consists of three parts:</p>
                            <ul className="list-disc pl-6 space-y-2">
                                <li><strong className="text-neon-blue">Plugin YAML</strong>: Defines connector type, auth schema, normalization field mappings, and optional compliance rules.</li>
                                <li><strong className="text-neon-blue">Connector (Control Plane)</strong>: Scheduled pull, inbound webhook push, or agent module — normalizes findings to the canonical schema.</li>
                                <li><strong className="text-neon-blue">Activation (Database)</strong>: An <code className="bg-nav px-1 rounded text-neon-amber">IntegrationConfig</code> record linking a tenant to the plugin with encrypted credentials.</li>
                            </ul>
                        </div>

                        {/* 3. Standard Format */}
                        <div>
                            <h3 className="text-xl font-semibold text-white mb-3">3. Plugin YAML Format</h3>
                            <p className="mb-4">All plugins live in <code className="text-neon-amber">plugins/&lt;name&gt;/plugin.yaml</code> and follow this schema:</p>

                            <div className="bg-black/50 p-4 rounded-lg border border-white/5 font-mono text-sm relative group">
                                <Code size={16} className="absolute top-3 right-3 text-gray-600" />
                                <pre className="text-neon-green overflow-x-auto">
                                    {`meta:
  id: "vendor-product"
  name: "Human Readable Name"
  category: "cloud|endpoint|siem|syslog"
  description: "Short description."

connector:
  type: "pull|push|agent_module"
  auth_schema:
    api_key: { type: string, required: true }

normalization:
  finding_type: "$.alert.type"
  severity:     "$.alert.severity"
  title:        "$.alert.description"

compliance_rules: []   # optional YAML check array`}
                                </pre>
                            </div>

                            <div className="mt-4 bg-nav/50 p-4 rounded border border-border-color">
                                <h4 className="font-bold text-sm text-text-secondary uppercase mb-2">Naming Convention</h4>
                                <ul className="space-y-1 text-sm">
                                    <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-neon-blue"></div> <strong>ID:</strong> vendor-product (e.g., cis-aws-1.5, crowdstrike-falcon)</li>
                                    <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-neon-blue"></div> <strong>Name:</strong> Title Case (e.g., CrowdStrike Falcon)</li>
                                    <li className="flex items-center gap-2"><div className="w-1.5 h-1.5 rounded-full bg-neon-blue"></div> <strong>Category:</strong> One of: cloud, endpoint, siem, syslog</li>
                                </ul>
                            </div>
                        </div>

                        {/* 4. Implementation */}
                        <div>
                            <h3 className="text-xl font-semibold text-white mb-3">4. Implementation Standard</h3>
                            <p className="mb-4">All compliance checks run inside the <code className="text-neon-amber">cloud-scanner</code> (Go) for cloud resources, or via the control-plane normalization engine for third-party tool findings.</p>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <div className="bg-surface p-4 rounded border border-white/5">
                                    <div className="text-xs text-text-secondary uppercase mb-1">Cloud Checks</div>
                                    <code className="text-neon-blue text-sm">cloud-scanner/internal/compliance/checks.go</code>
                                </div>
                                <div className="bg-surface p-4 rounded border border-white/5">
                                    <div className="text-xs text-text-secondary uppercase mb-1">Finding Normalization</div>
                                    <code className="text-neon-green text-sm">control-plane/app/routers/integrations.py</code>
                                </div>
                            </div>
                        </div>

                        {/* 5. Stability */}
                        <div>
                            <h3 className="text-xl font-semibold text-white mb-3">5. Ensuring Stability</h3>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                                <div className="bg-nav p-4 rounded border border-border-color hover:border-green-500/50 transition-colors">
                                    <div className="flex items-center gap-2 font-bold text-green-400 mb-2">
                                        <CheckCircle size={16} /> Isolation
                                    </div>
                                    <p className="text-sm text-gray-400">Each plugin connector must be self-contained. Failures in one plugin must not affect others.</p>
                                </div>
                                <div className="bg-nav p-4 rounded border border-border-color hover:border-green-500/50 transition-colors">
                                    <div className="flex items-center gap-2 font-bold text-green-400 mb-2">
                                        <CheckCircle size={16} /> Graceful Failure
                                    </div>
                                    <p className="text-sm text-gray-400">Return empty findings on API errors, never crash the scheduler.</p>
                                </div>
                            </div>
                        </div>

                        {/* 6. Workflow */}
                        <div>
                            <h3 className="text-xl font-semibold text-white mb-3">6. Development Workflow</h3>
                            <ol className="list-decimal pl-6 space-y-4 font-mono text-sm text-gray-400">
                                <li>
                                    <span className="text-white font-sans font-bold">Add Plugin YAML:</span> Create <span className="text-neon-amber">plugins/&lt;name&gt;/plugin.yaml</span> following the schema above.
                                </li>
                                <li>
                                    <span className="text-white font-sans font-bold">Mount in Compose:</span> The control-plane mounts <span className="text-neon-amber">../plugins</span> — restart to pick up new plugins.
                                </li>
                                <li>
                                    <span className="text-white font-sans font-bold">Verify:</span> The plugin will appear in the Integrations page available list.
                                </li>
                                <li>
                                    <span className="text-white font-sans font-bold">Test:</span> Install it via the UI, configure credentials, and verify findings arrive.
                                </li>
                            </ol>
                        </div>

                    </div>

                    <div className="mt-8 pt-6 border-t border-white/10 text-center">
                        <a href="/integrations" className="inline-flex items-center gap-2 text-neon-blue hover:text-white transition-colors font-bold uppercase tracking-wide text-sm">
                            View Integrations Marketplace <FileText size={16} />
                        </a>
                    </div>
                </section>
            </div>
        </div>
    );
}
