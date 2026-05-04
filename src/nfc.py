import hashlib

class NFC:

    def __init__(self):
        self.identity = None
        return

    def create_identity(self, id, ca_pub, pub_key, priv_key, signature):
        nfc_credential = {
        "version": 1,
        "credential_type": "NFC_Asymmetric_Authenticator",

        "subject": {
            "tag_id": hashlib.sha_512(id.encode('utf-8')).digest(),
            "tag_public_key": hashlib.sha_512(pub_key.public_bytes()).digest(),
            "tag_private-key": hashlib.sha_512(priv_key.private_bytes()).digest()
        },

        "issuer": {
            "ca_id": "Ecosystem-Root-CA",
            "key_id": "CA-2026-A",
            "pub_key": hashlib.sha_512(ca_pub.public_bytes()).digest(),
            "signature": signature
        },

        "scope": {
            "ecosystem_id": "NIPRO-DIALYSIS-SKANE",
            "allowed_operations": [
                "enter_service_mode",
                "authorize_calibration"
            ],
            "edge_groups": ["EDGE-GROUP-A"]
        },

        "validity": {
            "not_before": "2026-01-01T00:00:00Z",
            "not_after":  "2026-05-31T23:59:59Z"
        },

        "policy": {
            "offline_allowed": True,
            "user_presence_required": True
        }
        }
        self.identity = nfc_credential
        return nfc_credential
    
        


   