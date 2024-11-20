from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from app.uzi_jwt_decoder import UZIJWTDecoder


def _create_sample_jwt(payload: dict[str, Any], secret: str = 'secret'):
    encoded = jwt.encode(payload, secret)
    
    return encoded


def test_decode():
    jwt_expiry = datetime.now(tz=timezone.utc) + timedelta(minutes=1)
        
    jwt_payload = {
        "aud": "test-audience",
        "bsn": "958310828",
        "exp": jwt_expiry,
        "initials": "R.M.A.",
        "iss": "https://max.proeftuin.uzi-online.irealisatie.nl",
        "loa_authn": "http://eidas.europa.eu/LoA/high",
        "loa_uzi": "http://eidas.europa.eu/LoA/high",
        "nbf": 1731663196,
        "relations": [
            {
                "entity_name": "De Ziekenboeg",
                "roles": [
                    "01.010"
                ],
                "ura": "42424242"
            }
        ],
        "revocation_token": "40fcf1b4-348c-4dcc-8b17-dc1af7acc559",
        "sub": "fc3a47226732eade29029aab42257bb7e86767ac8f7cef5f5186a9ef61a5adaa",
        "surname": "Laar",
        "surname_prefix": "van",
        "uzi_id": "999991772",
        "x5c": "test",
        "acme_tokens": ['test-123']
    }
    jwt = _create_sample_jwt(jwt_payload)
    
    UZIJWTDecoder().decode(jwt)