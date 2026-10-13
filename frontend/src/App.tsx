import React, { useState, useEffect } from 'react';
import { ShieldAlert, Cloud, Zap, Scissors, RefreshCw, CheckCircle2 } from 'lucide-react';

export default function App() {
  const [nodes, setNodes] = useState<any[]>([]);
  const [edges, setEdges] = useState<any[]>([]);
  const [paths, setPaths] = useState<any[]>([]);
  const [chokePoints, setChokePoints] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [msg, setMsg] = useState('');

  const fetchScan = async () => {
    setLoading(true);
    setMsg('Scanning live AWS account via boto3...');
    try {
      const res = await fetch('http://localhost:8000/api/scan');
      const data = await res.json();
      setNodes(data.nodes);
      setEdges(data.edges);
      setPaths(data.paths);
      setChokePoints(data.choke_points);
      setMsg(`Discovered ${data.total_paths} live attack path(s) in AWS!`);
    } catch (e) {
      setMsg('Error connecting to backend on port 8000.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchScan(); }, []);

  const severChokePoint = async (edgeId: string) => {
    try {
      const res = await fetch('http://localhost:8000/api/sever', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ edge_id: edgeId, nodes, edges })
      });
      const data = await res.json();
      setEdges(data.remaining_edges);
      setPaths(data.paths);
      setChokePoints(data.choke_points);
      setMsg(`Severed permission! Active attack paths dropped to: ${data.total_paths}`);
    } catch (e) {
      console.error(e);
    }
  };

  return (
    <div style={{ background: '#0a0f1d', color: '#e2e8f0', minHeight: '100vh', padding: '24px', fontFamily: 'monospace' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1e293b', paddingBottom: '16px', marginBottom: '20px' }}>
        <div>
          <h1 style={{ margin: 0, fontSize: '20px', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Cloud size={24} /> AWS CloudGoat Attack Path Discovery
          </h1>
          <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#94a3b8' }}>
            NetworkX Graph Engine + Live AWS IAM Analysis
          </p>
        </div>
        <button onClick={fetchScan} disabled={loading} style={{ background: '#0284c7', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: '6px', cursor: 'pointer' }}>
          <RefreshCw size={14} /> Re-scan AWS
        </button>
      </div>

      {msg && <div style={{ background: '#1e293b', padding: '10px', borderRadius: '6px', fontSize: '13px', marginBottom: '20px', color: '#38bdf8' }}>{msg}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
        {/* Paths */}
        <div style={{ background: '#111827', padding: '16px', borderRadius: '8px', border: '1px solid #1f2937' }}>
          <h2 style={{ fontSize: '15px', color: '#f43f5e', display: 'flex', alignItems: 'center', gap: '6px', marginTop: 0 }}>
            <ShieldAlert size={18} /> Active Attack Routes ({paths.length})
          </h2>
          {paths.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '30px', color: '#4ade80' }}>
              <CheckCircle2 size={36} style={{ margin: '0 auto 8px' }} />
              <p>Zero paths to AdministratorAccess. Environment secure!</p>
            </div>
          ) : (
            paths.map((p, idx) => (
              <div key={idx} style={{ background: '#1f2937', padding: '12px', borderRadius: '6px', marginBottom: '10px', borderLeft: '4px solid #f43f5e' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: '#fbbf24', marginBottom: '6px' }}>
                  <span>HOPS: {p.total_hops}</span>
                  <span style={{ color: '#f43f5e' }}>Risk: {p.composite_risk}/100</span>
                </div>
                <div style={{ fontSize: '12px', color: '#cbd5e1' }}>
                  {p.path_nodes.map((node: string, nIdx: number) => (
                    <span key={nIdx}>
                      <span style={{ color: nIdx === 0 ? '#4ade80' : nIdx === p.path_nodes.length - 1 ? '#f43f5e' : '#38bdf8' }}>
                        {node.split('/').pop()}
                      </span>
                      {nIdx < p.path_nodes.length - 1 && ' ➔ '}
                    </span>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>

        {/* Choke Points */}
        <div style={{ background: '#111827', padding: '16px', borderRadius: '8px', border: '1px solid #1f2937' }}>
          <h2 style={{ fontSize: '15px', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px', marginTop: 0 }}>
            <Zap size={18} /> Critical Choke Points ({chokePoints.length})
          </h2>
          {chokePoints.map((cp, idx) => (
            <div key={idx} style={{ background: '#1f2937', padding: '12px', borderRadius: '6px', marginBottom: '10px', border: '1px solid #059669' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontWeight: 'bold', color: '#6ee7b7' }}>{cp.action}</div>
                  <div style={{ fontSize: '11px', color: '#94a3b8' }}>Edge: {cp.edge_id}</div>
                </div>
                <button onClick={() => severChokePoint(cp.edge_id)} style={{ background: '#dc2626', color: '#fff', border: 'none', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}>
                  <Scissors size={12} /> Sever Choke Point
                </button>
              </div>
              <div style={{ fontSize: '11px', color: '#fde047', marginTop: '6px' }}>
                Blocks {cp.paths_blocked} attack path(s) ({cp.choke_percentage}%)
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
