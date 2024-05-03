from typing_extensions import TypedDict
from typing import List


Platform = TypedDict(
    "Platform",
    {
        "architecture": str,
        "os": str,
        "os.version": str,
        "os.features": List[str],
        "variant": str,
        "features": List[str],
    },
)


class Manifest(TypedDict):
    """Typed dict use dto store manifest data."""

    mediaType: str
    size: int
    digest: str
    platform: Platform


class ManifestList(TypedDict):
    """Typed dict use dto store manifest list data."""

    schemaVersion: int
    mediaType: str
    manifests: List[Manifest]
    platform: Platform
