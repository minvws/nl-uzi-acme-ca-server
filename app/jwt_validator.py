# While this file would fit better in the an 'acme/challenge' directory, this currently
# throws errors, since __init__ modules expect environment variables to be set before the application even runs.
# Decoupling this from the application run time is something that should do, but should not be under the scope of this PR.

from dataclasses import dataclass
from typing import Any
from jsonschema import validate

import jwt


@dataclass
class JWTPayload:
    # These will be coming in via headers
    token: str
    certificate: str
    f9_certificate: str


class UZIJWTValidator:
    def _decode_jwt(self, token: str):
        # When this is implemented in production, verify the token key, audience and issuer.
        return jwt.decode(token, algorithms=['HS256'], options={'verify_signature': False})

    def _validate_payload_schema(self, payload: dict[str, Any]) -> None:
        props = {
            'acme_tokens': {
                'type': 'array',
                'minItems': 1,
                'items': {'type': 'string'},
                'uniqueItems': True,
            },
            'relations': {
                'type': 'array',
                'items': {
                    'type': 'object',
                    'properties': {
                        'entity_name': {'type': 'string'},
                        'roles': {
                            'type': 'array',
                            'items': {'type': 'string'},
                        },
                        'ura': {'type': 'string'},
                    },
                },
            },
            'aud': {'type': 'string'},
            'exp': {'type': 'integer'},
            'initials': {'type': 'string'},
            'iss': {'type': 'string'},
            'loa_authn': {'type': 'string'},
            'loa_uzi': {'type': 'string'},
            'nbf': {'type': 'integer'},
            'sub': {'type': 'string'},
            'surname': {'type': 'string'},
            'surname_prefix': {'type': 'string'},
            'uzi_id': {'type': 'string'},
            'x5c': {'type': 'string'},
        }
        all_property_names = list(props.keys())

        schema = {
            'type': 'object',
            'properties': props,
            'additionalProperties': True,
            'required': all_property_names,
        }
        # If no exception is raised by validate(), the instance is valid.
        validate(instance=payload, schema=schema)

    def _validate_acme_token(self, payload: list[str], token: str):
        if token not in payload:
            raise LookupError(f'Token "{token}" was not found in the JWT payload')

    def validate(self, jwt_payload: JWTPayload, token: str) -> None:
        decoded_jwt_payload: dict[str, Any] = self._decode_jwt(
            jwt_payload.token,
        )
        self._validate_payload_schema(decoded_jwt_payload)
        acme_tokens: list[str] = decoded_jwt_payload.get('acme_tokens', [])

        # Validate if challenge token is present
        self._validate_acme_token(acme_tokens, token)
