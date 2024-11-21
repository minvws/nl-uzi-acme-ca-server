from typing import Any
from app.uzi_record import UZIRecord
import jwt


class UZIJWTDecoder:
    _CARD_TYPE_NAMED_EMPLOYEE = 'N'
    _VERSION_DEFAULT = '1'
    _DEFAULT_ABG_CODE = '00000000'

    def _decode_jwt(self, value: str):
        # When this is implemented in production, verify the token key, audience and issuer.
        return jwt.decode(value, algorithms=['HS256'], options={'verify_signature': False})

    def _resolve_record(self, data: dict[str, Any]) -> UZIRecord:
        given_name = data.get('surname_prefix')
        surname = data.get('surname')
        uzi_nr = data.get('uzi_id')

        first_relation = data.get('relations', [])[0]
        subscription_number = first_relation['ura']
        entity = first_relation['entity_name']

        role = (first_relation['roles'][0],)

        record = UZIRecord(
            surname=surname,
            given_name=given_name,
            uzi_nr=uzi_nr,
            version=self._VERSION_DEFAULT,
            card_type=self._CARD_TYPE_NAMED_EMPLOYEE,
            subscription_nr=subscription_number,
            abg_code=self._DEFAULT_ABG_CODE,
            entity=entity,
            role=role,
        )
        return record

    def decode(self, value: str) -> UZIRecord:
        decoded: dict[str, Any] = self._decode_jwt(value)
        return self._resolve_record(decoded)
