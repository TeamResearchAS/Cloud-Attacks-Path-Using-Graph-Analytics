from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .models import AttackGraphPayload, SeverRequest
from .graph_engine import AttackGraphEngine
from .aws_scanner import scan_cloudgoat_iam

app = FastAPI(title="Cloud Attack Path Discovery")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/scan")
def scan_endpoint():
    data = scan_cloudgoat_iam()
    engine = AttackGraphEngine(nodes=data["nodes"], edges=data["edges"])
    paths = engine.find_all_attack_paths()
    choke_points = engine.calculate_choke_points(paths)
    return {
        "nodes": data["nodes"],
        "edges": data["edges"],
        "total_paths": len(paths),
        "paths": paths,
        "choke_points": choke_points
    }

@app.post("/api/sever")
def sever_endpoint(req: SeverRequest):
    remaining_edges = [e.dict() for e in req.edges if e.id != req.edge_id]
    engine = AttackGraphEngine(nodes=[n.dict() for n in req.nodes], edges=remaining_edges)
    paths = engine.find_all_attack_paths()
    choke_points = engine.calculate_choke_points(paths)
    return {
        "remaining_edges": remaining_edges,
        "total_paths": len(paths),
        "paths": paths,
        "choke_points": choke_points
    }