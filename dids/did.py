from dataclasses import dataclass

from did_resolver import Resolver, DIDResolutionResult
from jwt.jwe import create_jwe
from jwt.jwt import verify_jws
from jwt.types import JWE
from cacao.src.cacao import Cacao, CacaoBlock
from cacao.src.verification import EIP191Verifier
from cid import cid
from utils import *
from .types import DIDProviderClient


@dataclass
class DID:
    _client: Optional[DIDProviderClient] = None
    _id: Optional[str] = None
    _resolver: Optional[Resolver] = None
    _capability: Optional[Cacao] = None
    _parent_id: Optional[str] = None

    def __init__(self, resolver: Resolver, client: DIDProviderClient = None, capability: Cacao = None, parent_id: Optional[str] = None):
        if client:
            self._client = client
        if capability:
            self._capability = capability
            self._parent_id = self._capability.p.iss
            if self._parent_id.startswith("did:pkh:eip155:1:"):
                self._parent_id = self._parent_id.lower()
        if parent_id:
            if parent_id != self._parent_id:
                raise ValueError("Capability issuer and parent not equal")
            self._parent_id = parent_id
        self._resolver = resolver

    def capability(self) -> Cacao:
        if self._capability is None:
            raise ValueError("DID has no capability attached")
        return self._capability

    def has_capability(self) -> bool:
        return self._capability is not None

    def parent(self) -> str:
        if self._parent_id is None:
            raise ValueError("DID has no parent DID")
        return self._parent_id

    def has_parent(self) -> bool:
        return self._parent_id is not None

    def id(self):
        if self._id is None:
            raise ValueError("DID is not authenticated")
        return self._id

    def authenticated(self) -> bool:
        return self._id is not None
