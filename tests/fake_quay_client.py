import json
import logging

from pubtools._quay.quay_client import QuayClient

LOG = logging.getLogger("pubtools.quay")


class FakeQuayClient(QuayClient):
    """Class for performing Docker HTTP API operations with the Quay registry."""

    MANIFEST_LIST_TYPE = "application/vnd.docker.distribution.manifest.list.v2+json"
    MANIFEST_V2S2_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
    MANIFEST_V2S1_TYPE = "application/vnd.docker.distribution.manifest.v1+json"
    MANIFEST_OCI_LIST_TYPE = "application/vnd.oci.image.index.v1+json"
    MANIFEST_OCI_V2S2_TYPE = "application/vnd.oci.image.manifest.v1+json"

    def __init__(self):
        """Initialize the FakeQuayClient."""
        self._manifests_image_media_type = {}
        self._digests = {}

    def f_add_manifest(self, image, manifest, media_type, digest):
        """Register manifest to fake client.

        Args:
            image (str): Image address to register the manifest to.
            manifest (dict): Manifest to register.
            media_type (str): Media type of the manifest to register.
        """
        self._manifests_image_media_type.setdefault(image, {})
        self._manifests_image_media_type[image][media_type] = manifest
        self._digests.setdefault(image, {})
        self._digests[image][media_type] = digest

    def get_manifest(self, image, raw=False, media_type=None, return_headers=False):
        """Get manifest form the registry.

        Args:
            image (str): Image address to get the manifest from.
            raw (bool): Whether to return the raw manifest string or a Python dictionary.
            media_type (str): Media type of the manifest to get.
        Returns:
            dict or str: Manifest as a Python dictionary.
        """
        if not return_headers:
            if raw:
                return json.dumps(self._manifests_image_media_type[image][media_type])
            else:
                return self._manifests_image_media_type[image][media_type]
        else:
            if raw:
                return (
                    json.dumps(self._manifests_image_media_type[image][media_type]),
                    {"docker-content-digest": self._digests[image][media_type]},
                )
            else:
                return (
                    self._manifests_image_media_type[image][media_type],
                    {"docker-content-digest": self._digests[image][media_type]},
                )

    def upload_manifest(self, manifest, image, raw=False):
        """
        Simulate upload of manifest to a specified image.

        Uploaded manifest is stored locally and can be later download.
        All manifest types are supported (manifest, manifest list).

        Args:
            manifest (dict):
                Manifest to be uploaded.
            image (str):
                Image address to upload the manifest to.
            raw (bool):
                Whether the given manifest is a string (raw) or a Python dictionary
        """
        self._manifests_image_media_type.setdefault(image, {})
        manifest_json = json.loads(manifest)
        self._manifests_image_media_type[image][manifest_json["mediaType"]] = manifest
