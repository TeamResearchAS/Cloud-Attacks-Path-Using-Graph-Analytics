
import boto3

def scan_cloudgoat_iam():
    iam = boto3.client('iam')
    nodes = []
    edges = []

    # 1. Entry Point: Public Internet / Attacker
    nodes.append({
        "id": "attacker_entry",
        "label": "Attacker (Compromised Creds)",
        "type": "INTERNET",
        "is_entry_point": True,
        "is_crown_jewel": False
    })

    # 2. Crown Jewel: AdministratorAccess
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    nodes.append({
        "id": admin_arn,
        "label": "AdministratorAccess",
        "type": "ADMIN_ACCESS",
        "is_entry_point": False,
        "is_crown_jewel": True
    })

    # 3. Discover CloudGoat Users & Policies
    try:
        users = iam.list_users().get('Users', [])
        for u in users:
            u_name = u['UserName']
            u_arn = u['Arn']

            # Focus on CloudGoat user
            if "cg-" in u_name or "chris" in u_name:
                nodes.append({
                    "id": u_arn,
                    "label": u_name,
                    "type": "IAM_USER",
                    "is_entry_point": False,
                    "is_crown_jewel": False
                })

                # Attacker has creds to this user
                edges.append({
                    "id": f"entry->{u_name}",
                    "source": "attacker_entry",
                    "target": u_arn,
                    "action": "Compromised Access Key",
                    "risk_score": 85
                })

                # Check inline policies for dangerous permissions
                inline = iam.list_user_policies(UserName=u_name).get('PolicyNames', [])
                for p_name in inline:
                    pol_doc = iam.get_user_policy(UserName=u_name, PolicyName=p_name).get('PolicyDocument', {})
                    for stmt in pol_doc.get('Statement', []):
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        # Detect Privilege Escalation: iam:AttachUserPolicy
                        if "iam:AttachUserPolicy" in actions or "iam:*" in actions:
                            edges.append({
                                "id": f"{u_name}->admin-attach",
                                "source": u_arn,
                                "target": admin_arn,
                                "action": "iam:AttachUserPolicy (PrivEsc)",
                                "risk_score": 98
                            })

    except Exception as e:
        print(f"Scanner error: {e}")

    return {"nodes": nodes, "edges": edges}
