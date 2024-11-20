from dataclasses import dataclass

@dataclass
class UZIRecord:
    surname: str
    given_name: str
    uzi_nr: str
    version: str
    card_type: str
    subscription_nr: str
    role: str
    abg_code: str
    entity: str