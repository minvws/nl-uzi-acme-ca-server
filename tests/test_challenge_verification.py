from datetime import datetime, timedelta, timezone
import json
from fastapi.testclient import TestClient
import httpx
from jwcrypto import jwk, jws
import jwt

from tests.utils import (
    create_account_response,
    create_authorization_code_response,
    create_new_order_response,
    create_nonce,
)
from jwcrypto.common import json_encode

from unittest import mock


def _create_sample_jwt(challenge_tokens: list[str]):
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
        "acme_tokens": challenge_tokens
    }
    encoded = jwt.encode(jwt_payload, 'secret')
    
    return encoded


def test_challenge_fulfill(fastapi_testclient: TestClient, jwk_key: jwk.JWK):
    account_nonce = create_nonce(fastapi_testclient)
    account_response = create_account_response(
        fastapi_testclient, account_nonce, jwk_key
    )
    account_location_header = account_response.headers.get('location')

    response = create_new_order_response(fastapi_testclient, jwk_key, account_response)

    auth_response = create_authorization_code_response(
        fastapi_testclient, jwk_key, account_response, response
    )
    assert auth_response.is_success

    auth_codes_json = auth_response.json()
    challenges = auth_codes_json['challenges']

    # Retrieve the first challenge and it's URL
    first_challenge = challenges[0]
    challenge_url = first_challenge['url']
    challenge_token = first_challenge['token']
    
    
    sample_jwt = _create_sample_jwt([challenge_token])

    challenge_nonce = create_nonce(fastapi_testclient)

    protected = {
        'alg': 'ES256',
        'nonce': challenge_nonce,
        'url': challenge_url,
        'kid': account_location_header,
    }
    payload_encoded = json_encode(None).encode('utf-8')

    jws_object = jws.JWS(payload_encoded)
    jws_object.add_signature(jwk_key, protected=json_encode(protected), alg='ES256')

    jws_serialized = json.loads(jws_object.serialize(compact=False))

    response = fastapi_testclient.post(
        challenge_url,
        headers={'Content-Type': 'application/jose+json', 'X-Acme-Jwt': sample_jwt},
        json=jws_serialized,
    )
    assert response.is_success