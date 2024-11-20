from pyasn1.type import univ, char, namedtype

class UziSequence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "Upn",
            univ.Sequence(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType("Id", univ.ObjectIdentifier()),
                    namedtype.NamedType("Tag", char.UTF8String()),
                )
            ),
        ),
        namedtype.NamedType(
            "Uzi",
            univ.Sequence(
                componentType=namedtype.NamedTypes(
                    namedtype.NamedType("Id", univ.ObjectIdentifier()),
                    namedtype.NamedType("Tag", char.UTF8String()),
                )
            ),
        ),
    )