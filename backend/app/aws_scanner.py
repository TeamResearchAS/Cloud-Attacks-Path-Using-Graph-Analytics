import boto3
from typing import List, Dict, Any


def scan_cloudgoat_iam() -> Dict[str, List[Dict[str, Any]]]:
    """
    Scans live AWS IAM environment via boto3 for:
    - lab-intern-user and test IAM users
    - Inline policies with iam:AttachUserPolicy
    - Roles like lab-admin-role with sts:AssumeRole trust relationships
    - Crown jewel AdministratorAccess
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    # 1. Entry Point: Public Internet / Attacker
    nodes.append({
        "id": "attacker_entry",
        "label": "Attacker (Compromised Creds)",
        "type": "INTERNET",
        "is_entry_point": True,
        "is_crown_jewel": False,
        "metadata": {"notes": "Compromised Access Key"}
    })

    # 2. Crown Jewel: AdministratorAccess
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    nodes.append({
        "id": admin_arn,
        "label": "AdministratorAccess",
        "type": "ADMIN_ACCESS",
        "is_entry_point": False,
        "is_crown_jewel": True,
        "metadata": {"notes": "Full administrative permissions *:*"}
    })

    try:
        session = boto3.Session()
        iam = session.client('iam')

        # 3. Discover Users (Find lab-intern-user or any test user)
        users = iam.list_users().get('Users', [])
        scanned_user_arns = []

        for u in users:
            u_name = u['UserName']
            u_arn = u['Arn']

            # Detect lab-intern-user, cg- users, or test accounts
            is_target = any(k in u_name.lower() for k in ["lab-", "cg-", "chris", "intern", "test"])
            if is_target:
                scanned_user_arns.append(u_arn)
                nodes.append({
                    "id": u_arn,
                    "label": u_name,
                    "type": "IAM_USER",
                    "is_entry_point": False,
                    "is_crown_jewel": False,
                    "metadata": {"arn": u_arn}
                })

                # Attacker credential connection
                edges.append({
                    "id": f"entry->{u_name}",
                    "source": "attacker_entry",
                    "target": u_arn,
                    "action": "Compromised Access Key",
                    "risk_score": 85
                })

                # Check inline policies for iam:AttachUserPolicy
                inline = iam.list_user_policies(UserName=u_name).get('PolicyNames', [])
                for p_name in inline:
                    pol_doc = iam.get_user_policy(UserName=u_name, PolicyName=p_name).get('PolicyDocument', {})
                    stmts = pol_doc.get('Statement', [])
                    if isinstance(stmts, dict):
                        stmts = [stmts]

                    for stmt in stmts:
                        if stmt.get('Effect') != 'Allow':
                            continue
                        actions = stmt.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]

                        if any(a in actions for a in ["iam:AttachUserPolicy", "iam:*", "*"]):
                            edges.append({
                                "id": f"{u_name}->admin-attach",
                                "source": u_arn,
                                "target": admin_arn,
                                "action": "iam:AttachUserPolicy (PrivEsc)",
                                "risk_score": 98
                            })

        # 4. Discover Roles (Find lab-admin-role)
        roles = iam.list_roles().get('Roles', [])
        for r in roles:
            r_name = r['RoleName']
            r_arn = r['Arn']

            if r_name.startswith("AWSServiceRoleFor"):
                continue

            is_target_role = any(k in r_name.lower() for k in ["lab-", "cg-", "admin", "dev", "intern"])
            if is_target_role:
                nodes.append({
                    "id": r_arn,
                    "label": r_name,
                    "type": "IAM_ROLE",
                    "is_entry_point": False,
                    "is_crown_jewel": False,
                    "metadata": {"arn": r_arn}
                })

                # Check trust policy (sts:AssumeRole)
                trust_doc = r.get('AssumeRolePolicyDocument', {})
                for stmt in trust_doc.get('Statement', []):
                    if stmt.get('Effect') == 'Allow' and stmt.get('Action') == 'sts:AssumeRole':
                        principal = stmt.get('Principal', {})
                        aws_p = principal.get('AWS', [])
                        if isinstance(aws_p, str):
                            aws_p = [aws_p]

                        for trusted_entity in aws_p:
                            for u_arn in scanned_user_arns:
                                if u_arn in trusted_entity or trusted_entity == "*":
                                    edges.append({
                                        "id": f"{u_arn.split('/')[-1]}->assume->{r_name}",
                                        "source": u_arn,
                                        "target": r_arn,
                                        "action": "sts:AssumeRole",
                                        "risk_score": 75
                                    })

                # Check if role has AdministratorAccess attached
                att_pols = iam.list_attached_role_policies(RoleName=r_name).get('AttachedPolicies', [])
                for p in att_pols:
                    if p.get('PolicyArn') == admin_arn or "Administrator" in p.get('PolicyName', ''):
                        edges.append({
                            "id": f"{r_name}->admin-access",
                            "source": r_arn,
                            "target": admin_arn,
                            "action": "Attached: AdministratorAccess",
                            "risk_score": 100
                        })

    except Exception as e:
        print(f"AWS Scan error: {e}")

    return {"nodes": nodes, "edges": edges}