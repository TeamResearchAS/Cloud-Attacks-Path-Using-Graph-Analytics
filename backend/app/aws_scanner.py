import fnmatch
from typing import Any, Dict, List

import boto3


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else [value] if value is not None else []


def _statements(policy_document: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        statement
        for statement in _as_list(policy_document.get("Statement", []))
        if isinstance(statement, dict)
    ]


def _allows_action(statement: Dict[str, Any], action: str) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    return any(
        fnmatch.fnmatchcase(action.casefold(), allowed_action.casefold())
        for allowed_action in _as_list(statement.get("Action", []))
        if isinstance(allowed_action, str)
    )


def scan_cloudgoat_iam() -> Dict[str, List[Dict[str, Any]]]:
    """Scan for IAM escalation paths using read-only user and role permissions.

    The backend AWS principal needs iam:ListUsers, iam:ListUserPolicies,
    iam:GetUserPolicy, iam:ListAttachedUserPolicies, iam:GetPolicy,
    iam:GetPolicyVersion, iam:ListRoles, and iam:ListAttachedRolePolicies.
    """
    nodes: List[Dict[str, Any]] = [
        {
            "id": "attacker_entry",
            "label": "Attacker (Compromised Creds)",
            "type": "INTERNET",
            "is_entry_point": True,
            "is_crown_jewel": False,
            "metadata": {"notes": "Compromised Access Key"},
        }
    ]
    edges: List[Dict[str, Any]] = []

    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    nodes.append(
        {
            "id": admin_arn,
            "label": "AdministratorAccess",
            "type": "ADMIN_ACCESS",
            "is_entry_point": False,
            "is_crown_jewel": True,
            "metadata": {"notes": "Full administrative permissions *:*"},
        }
    )

    iam = boto3.Session().client("iam")
    users = iam.list_users().get("Users", [])
    scanned_user_arns: List[str] = []

    for user in users:
        user_name = user["UserName"]
        user_arn = user["Arn"]
        is_target = any(
            marker in user_name.casefold()
            for marker in ("lab-", "cg-", "chris", "intern", "test")
        )
        if not is_target:
            continue

        scanned_user_arns.append(user_arn)
        nodes.append(
            {
                "id": user_arn,
                "label": user_name,
                "type": "IAM_USER",
                "is_entry_point": False,
                "is_crown_jewel": False,
                "metadata": {"arn": user_arn},
            }
        )
        edges.append(
            {
                "id": f"entry->{user_name}",
                "source": "attacker_entry",
                "target": user_arn,
                "action": "Compromised Access Key",
                "risk_score": 85,
            }
        )

        policy_documents = []
        for policy_name in iam.list_user_policies(UserName=user_name).get(
            "PolicyNames", []
        ):
            policy_documents.append(
                iam.get_user_policy(
                    UserName=user_name, PolicyName=policy_name
                ).get("PolicyDocument", {})
            )

        for attached_policy in iam.list_attached_user_policies(
            UserName=user_name
        ).get("AttachedPolicies", []):
            policy_arn = attached_policy["PolicyArn"]
            policy = iam.get_policy(PolicyArn=policy_arn).get("Policy", {})
            version_id = policy.get("DefaultVersionId")
            if version_id is not None:
                policy_documents.append(
                    iam.get_policy_version(
                        PolicyArn=policy_arn, VersionId=version_id
                    )
                    .get("PolicyVersion", {})
                    .get("Document", {})
                )

        if any(
            _allows_action(statement, "iam:AttachUserPolicy")
            for document in policy_documents
            for statement in _statements(document)
        ):
            edges.append(
                {
                    "id": f"{user_name}->admin-attach",
                    "source": user_arn,
                    "target": admin_arn,
                    "action": "iam:AttachUserPolicy (PrivEsc)",
                    "risk_score": 98,
                }
            )

    roles = iam.list_roles().get("Roles", [])
    for role in roles:
        role_name = role["RoleName"]
        role_arn = role["Arn"]
        if role_name.startswith("AWSServiceRoleFor"):
            continue

        is_target_role = any(
            marker in role_name.casefold()
            for marker in ("lab-", "cg-", "admin", "dev", "intern")
        )
        if not is_target_role:
            continue

        nodes.append(
            {
                "id": role_arn,
                "label": role_name,
                "type": "IAM_ROLE",
                "is_entry_point": False,
                "is_crown_jewel": False,
                "metadata": {"arn": role_arn},
            }
        )

        trust_policy = role.get("AssumeRolePolicyDocument", {})
        for statement in _statements(trust_policy):
            if not _allows_action(statement, "sts:AssumeRole"):
                continue
            principal = statement.get("Principal", {})
            aws_principals = _as_list(
                principal.get("AWS", []) if isinstance(principal, dict) else []
            )
            for trusted_entity in aws_principals:
                if not isinstance(trusted_entity, str):
                    continue
                for user_arn in scanned_user_arns:
                    if trusted_entity == "*" or user_arn in trusted_entity:
                        edges.append(
                            {
                                "id": f"{user_arn.rsplit('/', 1)[-1]}->assume->{role_name}",
                                "source": user_arn,
                                "target": role_arn,
                                "action": "sts:AssumeRole",
                                "risk_score": 85,
                            }
                        )

        attached_role_policies = iam.list_attached_role_policies(
            RoleName=role_name
        ).get("AttachedPolicies", [])
        if any(
            policy.get("PolicyArn") == admin_arn
            or "Administrator" in policy.get("PolicyName", "")
            for policy in attached_role_policies
        ):
            edges.append(
                {
                    "id": f"{role_name}->admin-access",
                    "source": role_arn,
                    "target": admin_arn,
                    "action": "Attached: AdministratorAccess",
                    "risk_score": 100,
                }
            )

    return {"nodes": nodes, "edges": edges}
