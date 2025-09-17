from collections import defaultdict

from capa.render.result_document import Metadata
from pydantic import BaseModel, ConfigDict
from tenrec.plugins.models import FunctionData, HexEA


class FunctionResults(BaseModel):
    total: int = 0
    function: FunctionData
    capabilities: dict[str, int] = defaultdict(int)


class MatchResults(BaseModel):
    address: HexEA
    function: FunctionData | None = None


class CapaResults(BaseModel):
    matches: dict[str, list[MatchResults]]
    meta: Metadata

    model_config = ConfigDict(arbitrary_types_allowed=True)
