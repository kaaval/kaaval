"use client";
import { useEffect, useState, useCallback } from 'react';
import ReactFlow, {
    Background,
    Controls,
    MiniMap,
    useNodesState,
    useEdgesState,
    addEdge,
    Connection,
    Edge,
    Node
} from 'reactflow';
import 'reactflow/dist/style.css';
import { useAuth } from '../../components/AuthContext';
import dagre from 'dagre';

const dagreGraph = new dagre.graphlib.Graph();
dagreGraph.setDefaultEdgeLabel(() => ({}));

const getLayoutedElements = (nodes: Node[], edges: Edge[]) => {
    dagreGraph.setGraph({ rankdir: 'LR' });

    nodes.forEach((node) => {
        dagreGraph.setNode(node.id, { width: 150, height: 50 });
    });

    edges.forEach((edge) => {
        dagreGraph.setEdge(edge.source, edge.target);
    });

    dagre.layout(dagreGraph);

    nodes.forEach((node) => {
        const nodeWithPosition = dagreGraph.node(node.id);
        node.targetPosition = 'left' as any;
        node.sourcePosition = 'right' as any;
        // We are shifting the dagre node position (anchor=center center) to the top left
        // so it matches the React Flow node anchor point (top left).
        node.position = {
            x: nodeWithPosition.x - 75,
            y: nodeWithPosition.y - 25,
        };
    });

    return { nodes, edges };
};

export default function RBACPage() {
    const { token } = useAuth();
    const [nodes, setNodes, onNodesChange] = useNodesState([]);
    const [edges, setEdges, onEdgesChange] = useEdgesState([]);
    const [loading, setLoading] = useState(true);

    const onConnect = useCallback((params: Connection) => setEdges((eds) => addEdge(params, eds)), [setEdges]);

    useEffect(() => {
        const fetchData = async () => {
            if (!token) return;
            try {
                const res = await fetch('http://localhost:8000/rbac/graph', {
                    headers: { 'Authorization': `Bearer ${token}` }
                });
                if (!res.ok) throw new Error("Failed to fetch");
                const data = await res.json();

                // Apply Layout
                const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
                    data.nodes,
                    data.edges
                );

                setNodes(layoutedNodes);
                setEdges(layoutedEdges);
            } catch (err) {
                console.error(err);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, [token, setNodes, setEdges]);

    return (
        <div style={{ height: '85vh', width: '100%' }} className="bg-white rounded-lg shadow border border-gray-200">
            <div className="absolute top-4 left-4 z-10 bg-white/80 p-2 rounded shadow backdrop-blur-sm">
                <h1 className="text-xl font-bold text-gray-800">RBAC Visualization</h1>
                <p className="text-xs text-gray-500">Subject (Blue) → Binding (Teal/Orange) → Role (Pink/Purple)</p>
            </div>

            {loading ? (
                <div className="flex h-full items-center justify-center text-gray-500">Loading RBAC Graph...</div>
            ) : (
                <ReactFlow
                    nodes={nodes}
                    edges={edges}
                    onNodesChange={onNodesChange}
                    onEdgesChange={onEdgesChange}
                    onConnect={onConnect}
                    fitView
                >
                    <Background />
                    <Controls />
                    <MiniMap />
                </ReactFlow>
            )}
        </div>
    );
}
