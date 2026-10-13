
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class NodeModel(BaseModel):
    id: str
    label: str
    type: str  # INTERNET, IAM_USER, IAM_ROLE, POLICY, ADMIN_ACCESS
    is_entry_point: bool = False
    is_crown_jewel: bool = False

class EdgeModel(BaseModel):
    id: str
    source: str
    target: str
    action: str  # iam:AttachUserPolicy, sts:AssumeRole, etc.
    risk_score: int

class AttackGraphPayload(BaseModel):
    nodes: List[NodeModel]
    edges: List[EdgeModel]

class SeverRequest(BaseModel):
    edge_id: str
    nodes: List[NodeModel]
    edges: List[EdgeModel]
