"""Brand registry — single lookup point for all configured brands."""
from .base import BrandConfig
from .mary_kay import MARY_KAY

BRANDS: dict[str, BrandConfig] = {
    "mary_kay": MARY_KAY,
    # "avon": AVON,      ← add when ready
    # "tupperware": ...,
}

_DEFAULT = MARY_KAY


def get_brand(name: str) -> BrandConfig:
    """Return BrandConfig for name; falls back to default if unknown."""
    return BRANDS.get(name, _DEFAULT)
