

from datetime import datetime, timedelta, timezone
from typing import Any
from jsonschema import ValidationError
import jwt
import pytest
from app.jwt_validator import JWTPayload, UZIJWTValidator
from jwt.exceptions import DecodeError

DEFAULT_JWT_SECRET = 'badsecret'

def _create_sample_jwt(payload: dict[str, Any], secret: str = DEFAULT_JWT_SECRET):
    encoded = jwt.encode(payload, secret)
    
    return encoded

def test_jwt_validate_unparsable_token():
    payload = JWTPayload('badtoken', '123', '123')
    
    with pytest.raises(DecodeError):
        UZIJWTValidator().validate(payload, '123')
        
        
def test_jwt_actual_jwt_empty_payload():
    sample_jwt = _create_sample_jwt({
        'aud': 'test-audience'
    })
    payload = JWTPayload(sample_jwt, '123', '123')
    
    with pytest.raises(ValidationError):
        UZIJWTValidator().validate(payload, '123')
    
    
def test_jwt_actual_jwt_with_payload_token_not_present():
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
    sample_jwt = _create_sample_jwt(jwt_payload)
    payload = JWTPayload(sample_jwt, '123', '123')
    
    with pytest.raises(LookupError):
        UZIJWTValidator().validate(payload, '123')
    
def test_jwt_token_found():
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
    sample_jwt = _create_sample_jwt(jwt_payload)
    payload = JWTPayload(sample_jwt, '123', '123')
    

    UZIJWTValidator().validate(payload, 'test-123')
    