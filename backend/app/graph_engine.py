
import networkx as nx
from typing import List, Dict, Any

class AttackGraphEngine:
    def __init__(self, nodes: List[Dict], edges: List[Dict]):
        self.nodes = nodes
        self.edges = edges
        self.graph = nx.DiGraph()
        for n in self.nodes:
            self.graph.add_node(n["id"], **n)
        for e in self.edges:
            self.graph.add_edge(e["source"], e["target"], **e)

    def find_all_attack_paths(self, max_hops: int = 5) -> List[Dict[str, Any]]:
        entry_points = [n["id"] for n in self.nodes if n.get("is_entry_point")]
        crown_jewels = [n["id"] for n in self.nodes if n.get("is_crown_jewel")]
        
        discovered_paths = []
        for s in entry_points:
            for t in crown_jewels:
                if not self.graph.has_node(s) or not self.graph.has_node(t):
                    continue
                try:
                    for p in nx.all_simple_paths(self.graph, source=s, target=t, cutoff=max_hops):
                        p_edges = []
                        total_risk = 0
                        for i in range(len(p) - 1):
                            ed = self.graph.get_edge_data(p[i], p[i+1]) or {}
                            p_edges.append(ed)
                            total_risk += ed.get("risk_score", 50)

                        attack_edge = next(
                            (
                                edge
                                for edge in p_edges
                                if edge.get("action") != "Compromised Access Key"
                            ),
                            p_edges[0] if p_edges else {},
                        )
                        path_labels = [node.rsplit("/", 1)[-1] for node in p]
                        discovered_paths.append({
                            "path_nodes": p,
                            "path_labels": path_labels,
                            "path_edges": p_edges,
                            "via_action": attack_edge.get("action", ""),
                            "risk_score": attack_edge.get("risk_score", 50),
                            "total_hops": len(p) - 1,
                            "composite_risk": round(total_risk / max(1, len(p) - 1), 2)
                        })
                except nx.NetworkXNoPath:
                    continue

        discovered_paths.sort(key=lambda x: x["composite_risk"], reverse=True)
        for index, path in enumerate(discovered_paths, start=1):
            path["display_path"] = (
                f"Path {index}: {' ➔ '.join(path['path_labels'])}\n"
                f"(via {path['via_action']} - Risk: {path['risk_score']}/100)"
            )
        return discovered_paths

    def calculate_choke_points(self, paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not paths:
            return []
        
        counts = {}
        lookup = {}
        for p in paths:
            for e in p["path_edges"]:
                eid = e.get("id", f"{e.get('source')}->{e.get('target')}")
                counts[eid] = counts.get(eid, 0) + 1
                lookup[eid] = e

        results = []
        for eid, count in counts.items():
            results.append({
                "edge_id": eid,
                "action": lookup[eid].get("action", ""),
                "source": lookup[eid].get("source", ""),
                "target": lookup[eid].get("target", ""),
                "paths_blocked": count,
                "choke_percentage": round((count / len(paths)) * 100, 1)
            })
        results.sort(key=lambda x: x["choke_percentage"], reverse=True)
        return results
