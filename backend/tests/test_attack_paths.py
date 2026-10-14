import unittest
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from backend.app.aws_scanner import scan_cloudgoat_iam
from backend.app.graph_engine import AttackGraphEngine
from backend.app.main import scan_endpoint


class AttackPathTests(unittest.TestCase):
    def test_scan_formats_the_requested_vulnerable_paths(self) -> None:
        user_arn = "arn:aws:iam::123456789012:user/lab-intern-user"
        role_arn = "arn:aws:iam::123456789012:role/lab-admin-role"

        iam = Mock()
        iam.list_users.return_value = {
            "Users": [{"UserName": "lab-intern-user", "Arn": user_arn}]
        }
        iam.list_user_policies.return_value = {
            "PolicyNames": ["allow-policy-attachment"]
        }
        iam.get_user_policy.return_value = {
            "PolicyDocument": {
                "Statement": {
                    "Effect": "Allow",
                    "Action": "iam:AttachUserPolicy",
                }
            }
        }
        iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        iam.list_roles.return_value = {
            "Roles": [
                {
                    "RoleName": "lab-admin-role",
                    "Arn": role_arn,
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": ["sts:AssumeRole"],
                                "Principal": {"AWS": [user_arn]},
                            }
                        ]
                    },
                }
            ]
        }
        iam.list_attached_role_policies.return_value = {
            "AttachedPolicies": [
                {
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "PolicyName": "AdministratorAccess",
                }
            ]
        }

        with patch("backend.app.aws_scanner.boto3.Session") as session_factory:
            session_factory.return_value.client.return_value = iam
            data = scan_cloudgoat_iam()

        paths = AttackGraphEngine(data["nodes"], data["edges"]).find_all_attack_paths()

        self.assertEqual(
            [path["display_path"] for path in paths],
            [
                "Path 1: attacker_entry ➔ lab-intern-user ➔ AdministratorAccess\n"
                "(via iam:AttachUserPolicy (PrivEsc) - Risk: 98/100)",
                "Path 2: attacker_entry ➔ lab-intern-user ➔ lab-admin-role "
                "➔ AdministratorAccess\n"
                "(via sts:AssumeRole - Risk: 85/100)",
            ],
        )

    def test_scan_endpoint_reports_aws_access_denied(self) -> None:
        aws_error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Denied"}},
            "ListUsers",
        )

        with patch("backend.app.main.scan_cloudgoat_iam", side_effect=aws_error):
            with self.assertRaises(HTTPException) as raised:
                scan_endpoint()

        self.assertEqual(raised.exception.status_code, 502)
        self.assertIn("ListUsers (AccessDenied)", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()
