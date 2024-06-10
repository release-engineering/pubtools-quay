from __future__ import annotations

import logging
import requests
import tempfile
from collections.abc import Iterable

from .quay_client import QuayClient
from .quay_api_client import QuayApiClient
from .security_manifest_pusher import SecurityManifestPusher
from .types import Manifest, ManifestList

from typing import cast, List, Dict, Optional, Tuple, Union

LOG = logging.getLogger("pubtools.quay")


class ImageUntagger:
    """Class containing logic for untagging images and deciding if they should be untagged."""

    def __init__(
        self,
        references: List[str],
        quay_api_token: str,
        remove_last: bool = False,
        quay_user: Optional[str] = None,
        quay_password: Optional[str] = None,
        host: Optional[str] = None,
    ) -> None:
        """
        Initialize.

        Args:
            references ([str]):
                List of image references to untag.
            quay_api_token (str):
                OAuth token for authentication of Quay REST API.
            remove_last (bool):
                Whether to remove a tag when it's the last reference of an image (in that repo).
            quay_user (str):
                Quay username for Docker HTTP API.
            quay_password (str):
                Quay password for Docker HTTP API.
            host (str):
                Custom Quay hostname (if required).
        """
        for reference in references:
            if "@" in reference:
                raise ValueError(
                    "Reference '{0}' must be specified via tag, not digest".format(reference)
                )

        if isinstance(host, str) and host[-1] == "/":
            host = host[:-1]
        self.host = host or "quay.io"

        self.references = references
        self.remove_last = remove_last

        if quay_user and quay_password:
            self._quay_client: Optional[QuayClient] = QuayClient(
                quay_user, quay_password, self.host
            )
        else:
            self._quay_client = None
        self._quay_api_client = QuayApiClient(quay_api_token, self.host)

    def set_quay_client(self, quay_client: QuayClient) -> None:
        """
        Set client instance to be used for the HTTP API operations.

        Args:
            quay_client (QuayClient):
                Instance of QuayClient.
        """
        self._quay_client = quay_client

    def get_repository_tags_mapping(self) -> Dict[str, List[str]]:
        """
        Get a mapping of which tags would be removed from given repos based on provided refs.

        Returns ({str: [str]}):
            Mapping of repository->tags.
        """
        repo_tag_mapping: Dict[str, List[str]] = {}
        for reference in self.references:
            tag = reference.split(":")[-1]
            repo_path = reference.split(":")[0]
            # Take only last two parts of the url, which are namespace + repo
            repository = "/".join(repo_path.split("/")[-2:])
            repo_tag_mapping.setdefault(repository, []).append(tag)

        return repo_tag_mapping

    def construct_tag_digest_mappings(
        self, repository: str
    ) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
        """
        Create a mappings of tags->digests as well as digests->tags.

        Tags->digests mapping answers the question "Which digests does a given tag reference?".
        Digests->tags mapping answers the question "Which tags reference a given digest?".
        Tag may reference one digest (if image manifest), or multiple (if manifest list).

        Args:
            repository (str):
                Quay repository.

        Returns (({str: [str]}), ({str: [str]})):
            Tuple of dictionaries mapping tags->digests and digests->tags.
        """
        LOG.info("Gathering tags and digests of repository '{0}'".format(repository))
        tag_digest_mapping: Dict[str, List[str]] = {}
        digest_tag_mapping: Dict[str, List[str]] = {}
        image_schema = "{0}/{1}:{2}"
        repo_tags = cast(
            Dict[str, List[str]],
            cast(QuayClient, self._quay_client).get_repository_tags(repository),
        )

        for tag in repo_tags["tags"]:
            image = image_schema.format(self.host, repository, tag)
            try:
                manifest = cast(
                    Union[ManifestList, Manifest],
                    cast(QuayClient, self._quay_client).get_manifest(image),
                )
            except requests.exceptions.HTTPError as e:
                # Just removed tags could still be in tags list while manifests are removed
                if e.response.status_code == 404:
                    continue
                else:
                    raise
            digest = cast(QuayClient, self._quay_client).get_manifest_digest(image)

            # Option 1: No manifest list, only manifest
            if manifest.get("mediaType", None) in (
                QuayClient.MANIFEST_V2S2_TYPE,
                QuayClient.MANIFEST_OCI_V2S2_TYPE,
                QuayClient.MANIFEST_V2S1_TYPE,
                None,
            ):
                tag_digest_mapping[tag] = [digest]
                digest_tag_mapping.setdefault(digest, []).append(tag)

            # Option 2: We need to get digests of all architectures
            else:
                tag_digest_mapping[tag] = [digest]
                digest_tag_mapping.setdefault(digest, []).append(tag)

                for arch_manifest in cast(ManifestList, manifest)["manifests"]:
                    tag_digest_mapping[tag].append(arch_manifest["digest"])
                    digest_tag_mapping.setdefault(arch_manifest["digest"], []).append(tag)

        return (tag_digest_mapping, digest_tag_mapping)

    def get_lost_digests(
        self,
        tags: List[str],
        tag_digest_mapping: Dict[str, List[str]],
        digest_tag_mapping: Dict[str, List[str]],
    ) -> List[str]:
        """
        Calculate a list of digests that would be lost if the provided tags were removed.

        Args:
            tags ([str]):
                List of tags that would be removed from a repo.
            tag_digest_mapping ({str: [str]}):
                Mapping of which digests are referenced by a given tag.
            digest_tag_mapping ({str: [str]}):
                Mapping of which tags reference a given digest.

        Returns ([str]):
            Digests that would be lost if given tags were removed.
        """
        remove_digests = []
        lost_digests = []
        for tag in tags:
            for digest in tag_digest_mapping.get(tag, []):
                if digest not in remove_digests:
                    remove_digests.append(digest)

        for digest in remove_digests:
            # which tags would remain referencing a given digest?
            remaining_tags = set(digest_tag_mapping[digest]) - set(tags)
            if len(remaining_tags) == 0:
                lost_digests.append(digest)

        return lost_digests

    def get_repo_cosign_images(
        self,
        repo_images: List[str],
        repo_tags: List[str],
        image_types: Optional[Iterable[str]] = None,
    ) -> set[str]:
        """
        Get a list of images generated by cosign associated with the provided images.

        The provided images are expected to be specified by digest (as tag can point to
        multiple images). This method will return associated "secondary" images likely generated by
        cosign. They can be attestations, sboms, or signatures. Their tag likely has format
        "sha256-<digest>.<sbom|att|sig>".

        Args:
            repo_images ([str]):
                Main images whose "cosign" images will be found.
            repo_tags ([str]):
                All tags in a repo.
            image_types ([str]):
                Which cosign image types to get (supported values are in COSIGN_TRIANGULATE_TYPES).
                If unset, all image types will be checked.
        Returns ([str]):
            List of cosign images associated with the provided images.
        """
        LOG.info(f"Getting cosign images of {len(repo_images)} images")
        if not repo_images:
            return set()

        check_types = (
            image_types if image_types else SecurityManifestPusher.COSIGN_TRIANGULATE_TYPES
        )
        types_found = [t in SecurityManifestPusher.COSIGN_TRIANGULATE_TYPES for t in check_types]
        if not all(types_found):
            raise ValueError(f"Unknown cosign image types in {image_types}")

        # check if all images are specified by digest
        nondigest_images = [i for i in repo_images if "@sha256:" not in i]
        if nondigest_images:
            raise ValueError(f"Images {nondigest_images} are not specified by digest")
        # check if all images belong to the same repo
        repos = set([i.split("@")[0] for i in repo_images])
        if len(repos) > 1:
            raise ValueError("Specified images belong to multiple repos")

        set_repo_tags = set(repo_tags)
        cosign_images = set()

        with tempfile.TemporaryDirectory(prefix="security_manifest_") as tmp_dir:
            for image in repo_images:
                for image_type in check_types:
                    cosign_image = SecurityManifestPusher.cosign_triangulate_image(
                        image, tmp_dir, image_type
                    )
                    if cosign_image.split(":")[-1] in set_repo_tags:
                        cosign_images.add(cosign_image)

        LOG.info(f"{len(cosign_images)} cosign images were found for the {len(repo_images)} images")
        return cosign_images

    def untag_images(self) -> List[str]:
        """
        Determine if the specified tags may be removed and remove them.

        Returns ([str]):
            List of image references lost by the untagging.
        """
        if not self._quay_client:
            raise RuntimeError("QuayClient instance must be set")

        repo_tag_mapping = self.get_repository_tags_mapping()
        schema = "{0}/{1}@{2}"
        lost_imgs = []
        lost_cosign_imgs = set()

        for repo in repo_tag_mapping:
            tag_digest_mapping, digest_tag_mapping = self.construct_tag_digest_mappings(repo)

            lost_digests = self.get_lost_digests(
                repo_tag_mapping[repo], tag_digest_mapping, digest_tag_mapping
            )
            if len(lost_digests) > 0:
                lost_repo_images = [
                    schema.format(self.host, repo, digest) for digest in lost_digests
                ]
                lost_imgs += lost_repo_images

                repo_tags: List[str] = cast(
                    Dict[str, List[str]], self._quay_client.get_repository_tags(repo)
                )["tags"]
                # We need to run this twice to get all secondary cosign images.
                # First, we find sbom, att, sig images of normal images.
                # Second, we find sig images of sbom and att images.
                repo_lost_cosign_imgs = self.get_repo_cosign_images(lost_repo_images, repo_tags)
                cosign_imgs_by_digest = sorted(
                    [
                        f"{i.split(':')[0]}@{self._quay_client.get_manifest_digest(i)}"
                        for i in repo_lost_cosign_imgs
                    ]
                )
                repo_lost_cosign_imgs |= self.get_repo_cosign_images(
                    cosign_imgs_by_digest, repo_tags, ["signature"]
                )
                lost_cosign_imgs |= repo_lost_cosign_imgs

        if not self.remove_last and lost_imgs:
            raise ValueError(
                "Following images would no longer be referencable by tag after"
                " the untagging operation: '{0}'. Please specify --remove-last"
                " if this is not a concern.".format(lost_imgs)
            )

        if lost_imgs and self.remove_last:
            LOG.warning("Following images won't be referencable by tag: {0}".format(lost_imgs))
        if not lost_imgs:
            LOG.info("No images will be lost by this untagging operation")
        if lost_cosign_imgs:
            LOG.warning(
                "Following cosign images won't be referecable by tag: "
                f"{sorted(list(lost_cosign_imgs))}"
            )

        for reference in sorted(list(set(self.references) | lost_cosign_imgs)):
            tag = reference.split(":")[-1]
            repo_path = reference.split(":")[0]
            # Take only last two parts of the url, which are namespace + repo
            repository = "/".join(repo_path.split("/")[-2:])
            LOG.info("Removing tag '{0}' from repository '{1}'".format(tag, repository))
            self._quay_api_client.delete_tag(repository, tag)

        return sorted(list(set(lost_imgs) | lost_cosign_imgs))
