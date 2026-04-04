"use client";
import { useEffect, useState } from 'react';
import { useAuth } from '../../components/AuthContext';

export default function CompliancePage() {
    const { token } = useAuth();
    const [data, setData] = useState<any>(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            if (!token) return;
            try {
                const res = await fetch('http://localhost:8001/compliance/dashboard', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                setData(await res.json());
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [token]);

    return (
        <div className="p-8">
            <h1 className="text-3xl font-bold mb-6">Security & Compliance</h1>

            {loading ? <p>Loading...</p> : (
                <div className="space-y-8">
                    {/* Scorecards */}
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        {data?.standards?.length ? (
                            data.standards.map((std: any) => (
                                <div key={std.name} className="glass-card p-6 border-l-4 border-l-neon-blue">
                                    <div className="flex justify-between items-start mb-4">
                                        <div>
                                            <h2 className="text-xl font-bold">{std.name}</h2>
                                            <p className="text-sm text-gray-500">{std.description}</p>
                                        </div>
                                        <div className="text-2xl font-bold text-blue-600">{std.score}%</div>
                                    </div>
                                    <div className="space-y-2">
                                        {std.checks.map((check: any) => (
                                            <div key={check.id} className="flex justify-between text-sm">
                                                <span>{check.name}</span>
                                                <span className={check.status === 'PASS' ? 'text-green-600' : 'text-red-600'}>
                                                    {check.status}
                                                </span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            ))
                        ) : (
                            <div className="col-span-full text-center py-10 text-gray-400">
                                <div className="flex flex-col items-center gap-4">
                                    <p>No compliance standards enabled.</p>
                                    <a href="/integrations" className="text-neon-blue hover:underline">
                                        Visit Integrations Marketplace to enable standards.
                                    </a>
                                </div>
                            </div>
                        )}
                    </div>

                    {/* Detailed Controls */}
                    <div className="bg-card p-6 rounded-lg border border-border-color text-primary">
                        <h2 className="text-xl font-semibold mb-4 text-primary">All Security Controls</h2>
                        <table className="min-w-full divide-y divide-border-color">
                            <thead>
                                <tr>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider">ID</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider">Control</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider">Status</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider">Severity</th>
                                    <th className="px-6 py-3 text-left text-xs font-medium text-text-secondary uppercase tracking-wider">Message</th>
                                </tr>
                            </thead>
                            <tbody className="bg-card divide-y divide-border-color">
                                {data?.all_checks?.length ? (
                                    data.all_checks.map((check: any) => (
                                        <tr key={check.id}>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-primary">{check.id}</td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-text-secondary">{check.name}</td>
                                            <td className="px-6 py-4 whitespace-nowrap">
                                                <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${check.status === 'PASS' ? 'bg-green-100 text-green-800' :
                                                    check.status === 'WARNING' ? 'bg-yellow-100 text-yellow-800' : 'bg-red-100 text-red-800'
                                                    }`}>
                                                    {check.status}
                                                </span>
                                            </td>
                                            <td className="px-6 py-4 whitespace-nowrap text-sm text-text-secondary">{check.severity}</td>
                                            <td className="px-6 py-4 text-sm text-text-secondary max-w-md truncate" title={check.description}>{check.description}</td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan={5} className="px-6 py-10 text-center text-text-secondary">
                                            No compliance controls found.
                                        </td>
                                    </tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}
        </div>
    );
}
