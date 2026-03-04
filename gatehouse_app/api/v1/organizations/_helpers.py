"""Shared helpers for organization endpoints."""
import os


def _get_system_ca_dict():
    try:
        from gatehouse_app.config.ssh_ca_config import get_ssh_ca_config
        from gatehouse_app.utils.crypto import compute_ssh_fingerprint

        priv_key = os.environ.get("SSH_CA_PRIVATE_KEY", "").strip()
        pub_key = ""

        if not priv_key:
            cfg = get_ssh_ca_config()
            key_path = cfg.get_str("ca_key_path", "").strip()
            if not key_path:
                return None
            pub_path = key_path + ".pub"
            if not os.path.exists(pub_path):
                return None
            with open(pub_path) as f:
                pub_key = f.read().strip()
        else:
            from sshkey_tools.keys import PrivateKey
            pk = PrivateKey.from_string(priv_key)
            pub_key = pk.public_key.to_string()

        fingerprint = compute_ssh_fingerprint(pub_key)
        return {
            "id": f"system-ca-{fingerprint[:16]}",
            "organization_id": None,
            "name": "System CA (config file)",
            "description": (
                "Read-only — this CA is loaded from the server's SSH_CA_PRIVATE_KEY "
                "environment variable or etc/ssh_ca.conf. Manage it on the server."
            ),
            "ca_type": "user",
            "key_type": "unknown",
            "public_key": pub_key,
            "fingerprint": fingerprint,
            "is_active": True,
            "is_system": True,
            "default_cert_validity_hours": 0,
            "max_cert_validity_hours": 0,
            "total_certs": 0,
            "active_certs": 0,
            "revoked_certs": 0,
            "created_at": None,
            "updated_at": None,
        }
    except Exception:
        return None
