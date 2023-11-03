from dataclasses import dataclass
import hashlib
from typing import List, Dict, Any
import requests
import time
import json

from .quay_client import QuayClient
from .exceptions import ManifestTypeError


@dataclass
class VirtualPushItem:
    """Virtual push item used for operations which doens't take push item on the input."""

    metadata: Dict[str, Any]
    repos: Dict[str, Any]


@dataclass
class ManifestArchDigest:
    """Data structure to hold information about container manifest."""

    manifest: Dict[str, Any]
    digest: str
    arch: str
    type_: str


@dataclass
class ContentExtractor:
    """Class is used to extract specific content from container registry based on provided input."""

    _MEDIA_TYPES_PRIORITY = {
        QuayClient.MANIFEST_LIST_TYPE: 30,
        QuayClient.MANIFEST_V2S2_TYPE: 20,
        QuayClient.MANIFEST_V2S1_TYPE: 10,
    }
    quay_client: QuayClient
    sleep_time: int = 5
    timeout: int = 60
    poll_rate: int = 5

    def _extract_ml_manifest(self, image_ref, _manifest, mtype):
        digests = []
        manifest = json.loads(_manifest)
        for arch_manifest in manifest["manifests"]:
            manifest = self.quay_client.get_manifest(
                f"{image_ref.rsplit(':')[0]}@{arch_manifest['digest']}",
                media_type=QuayClient.MANIFEST_V2S2_TYPE,
                raw=True,
            )
            digests.append(
                ManifestArchDigest(
                    manifest=manifest,
                    digest=arch_manifest["digest"],
                    arch=arch_manifest["platform"]["architecture"],
                    type_=QuayClient.MANIFEST_V2S2_TYPE,
                )
            )
        return digests

    def _extract_manifest(self, repo, manifest, mtype):
        hasher = hashlib.sha256()
        hasher.update(manifest.encode("utf-8"))
        digest = hasher.hexdigest()
        return ManifestArchDigest(manifest=manifest, digest=digest, arch="amd64", type_=mtype)

    _MEDIA_TYPES_PROCESS = {
        QuayClient.MANIFEST_LIST_TYPE: _extract_ml_manifest,
        QuayClient.MANIFEST_V2S2_TYPE: _extract_manifest,
        QuayClient.MANIFEST_V2S1_TYPE: _extract_manifest,
    }

    def extract_manifests(self, image_ref, media_types, tolerate_missing=True):
        """Extract manifests from container registry.

        Method fetches manifests for all provided media types. If HTTPErrors is raised when
        fetching for manifest and status code is 404 or 401, it's retried as there can be delay
        in registry if manifest was just pushed to it.
        When manifest is not found for given media type, it's not included in the result.

        Args:
            image_ref (str): Image reference in format <registry>/<repo>:<tag>
            media_types (list): List of media types to be extracted.
            tolerate_missing (bool): If True, missing manifests are tolerated and
            empty list is returned.

        Returns:
            list: List of ManifestArchDigest objects.
        """
        mtypes = media_types or self._MEDIA_TYPES_PRIORITY.keys()
        results = []
        for mtype in mtypes:
            for i in range(self.timeout // self.poll_rate):
                try:
                    manifest = self.quay_client.get_manifest(image_ref, media_type=mtype, raw=True)
                except requests.exceptions.HTTPError as e:
                    # When robot account is used, 401 may be returned instead of 404
                    if (
                        e.response.status_code == 404 or e.response.status_code == 401
                    ) and tolerate_missing:
                        manifest = None
                    else:
                        raise
                except ManifestTypeError:
                    manifest = None
                    break
                else:
                    break
                time.sleep(self.sleep_time)
            if not manifest:
                continue
            else:
                ret = self._MEDIA_TYPES_PROCESS[mtype](self, image_ref, manifest, mtype)
                if isinstance(ret, list):
                    results.extend(ret)
                else:
                    results.append(ret)
        return results

    def extract_tags(self, image_ref, tolerate_missing=True):
        """Fetch list of tags for given image reference.

        Args:
            image_ref (str): Image reference in format <registry>/<repo>:<tag>
            tolerate_missing (bool): If True, missing manifests are tolerated and empty list
            is returned.
        Returns:
            list: List of tags.
        """
        try:
            repo_tags = self.quay_client.get_repository_tags(image_ref)
        except requests.exceptions.HTTPError as e:
            # When robot account is used, 401 is returned instead of 404
            if tolerate_missing:
                if e.response.status_code == 404 or e.response.status_code == 401:
                    repo_tags = {"tags": []}
                else:
                    raise
            else:
                raise
        return repo_tags["tags"]


@dataclass
class ReferenceProcessorNOP:
    """Class is used to produce full image reference from input."""

    def __call__(self, registry, repo, tag):
        """Produce full image reference from input.

        Args:
            registry (str): Registry where image is located.
            repo (str): Repository name.
            tag (str): Tag name.
        Returns:
            tuple: Tuple containing repository name and full image reference.
        """
        if tag:
            return (repo, f"{registry}/{repo}:{tag}")
        else:
            return (repo, f"{registry}/{repo}")


@dataclass
class ReferenceProcessorInternal:
    """Class is used to produce full internal image reference from input."""

    INTERNAL_DELIMITER = "----"
    quay_namespace: str

    def __call__(self, registry, repo, tag=None):
        """Produce full internal image reference from input.

        Args:
            registry (str): Registry where image is located.
            repo (str): Repository name.
        Returns:
            tuple: Tuple containing repository name and full image reference.
        """
        if repo.count("/") == 0:
            if tag:
                return (
                    f"{self.quay_namespace}/{repo}",
                    f"{registry}/{self.quay_namespace}/{repo}:{tag}",
                )
            else:
                return (f"{self.quay_namespace}/{repo}", f"{registry}/{self.quay_namespace}/{repo}")
        if repo.count("/") > 1 or repo[0] == "/" or repo[-1] == "/":
            raise ValueError(
                "Input repository containing a delimeter should "
                "have the format '<namespace>/<product>'",
                repo,
            )
        replaced = repo.replace("/", self.INTERNAL_DELIMITER)
        if tag:
            return (
                f"{self.quay_namespace}/{replaced}",
                f"{registry}/{self.quay_namespace}/{replaced}:{tag}",
            )
        else:
            return (
                f"{self.quay_namespace}/{replaced}",
                f"{registry}/{self.quay_namespace}/{replaced}",
            )

    def replace_repo(self, repo):
        """Convert repo to internal format.

        Args:
            repo (str): Repository in format <namespace>/<product>
        Returns:
            str: Repository in format <quay_namespace>/<namespace>----<product>
        """
        if repo.count("/") == 0:
            return f"{self.quay_namespace}/{repo}"
        if repo.count("/") > 1 or repo[0] == "/" or repo[-1] == "/":
            raise ValueError(
                "Input repository containing a delimeter should "
                "have the format '<namespace>/<product>'",
                repo,
            )
        replaced = repo.replace("/", self.INTERNAL_DELIMITER)
        return f"{self.quay_namespace}/{replaced}"


@dataclass
class ItemProcesor:
    """Class is used to process push item and extract various data from it."""

    extractor: ContentExtractor
    reference_processor: ReferenceProcessorNOP
    reference_registries: List[str]
    source_registry: str

    INTERNAL_DELIMITER = "----"

    def _generate_dest_repo(self, item):
        for registry in self.reference_registries:
            for repo, _ in item.metadata["tags"].items():
                yield registry, repo

    def _generate_src_repo(self, item):
        for repo, _ in item.repos.items():
            yield repo

    def _generate_src_repo_tag(self, item):
        for repo, tags in item.metadata["tags"].items():
            for tag in tags:
                yield (repo, tag)

    def generate_repo_dest_tags(self, item):
        """Generate list of destination repositories and tags.

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of tuples containing registry, repository and tag.
        """
        ret = []
        for registry, repo in self._generate_dest_repo(item):
            for repo, tags in item.metadata["tags"].items():
                for tag in tags:
                    ret.append((registry, repo, tag))
        return ret

    def generate_repo_untags(self, item):
        """Generate list of repositories and tags which are destined to be untag.

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of tuples containing repository and tag.
        """
        ret = []
        for repo in self._generate_src_repo(item):
            for tag in item.metadata["remove_tags"]:
                ret.append((repo, tag))
        return ret

    def generate_repo_dest_tag_map(self, item):
        """Generate map of destination repositories and tags.

        Args:
            item (PushItem): Push item.
        Returns:
            dict: Dict of {registry: {repo: [tags]}}
        """
        ret = {}
        for registry, repo in self._generate_dest_repo(item):
            for repo, tags in item.metadata["tags"].items():
                for tag in tags:
                    ret.setdefault(registry, {}).setdefault(repo, []).append(tag)
        return ret

    def generate_to_sign(self, item):
        """Generate list of images to sign.

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of dictionaries containing reference, digest, repository and architecture.
        """
        to_sign = []
        media_types = (
            item.metadata.get("build", {}).get("extra", {}).get("image", {}).get("media_types", [])
        )

        for registry, repo, tag in self.generate_repo_dest_tags(item):
            ref_repo, reference = self.reference_processor(registry, repo, tag)
            man_arch_digs = self.extractor.extract_manifests(item.metadata["pull_url"], media_types)
            for mad in man_arch_digs:
                to_sign.append(
                    {"reference": reference, "digest": mad.digest, "repo": repo, "arch": mad.arch}
                )
        return to_sign

    def generate_to_unsign(self, item):
        """Generate list of images to unsign.

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of dictionaries containing reference, digest, repository and architecture.
        """
        to_sign = []
        media_types = (
            item.metadata.get("build", {}).get("extra", {}).get("image", {}).get("media_types", [])
        )

        for repo, tag in self.generate_repo_untags(item):
            ref_repo, reference = self.reference_processor(None, repo, tag)
            man_arch_digs = self.extractor.extract_manifests(
                f"{self.source_registry}/{ref_repo}:{tag}", media_types
            )
            for mad in man_arch_digs:
                to_sign.append(
                    {"reference": reference, "digest": mad.digest, "repo": repo, "arch": mad.arch}
                )
        return to_sign

    def generate_existing_tags(self, item, tolerate_missing=True):
        """Generate list of existing tags for given push item.

        Args:
            item (PushItem): Push item.
            tolerate_missing (bool): If True, tolerate missing tags.
        Returns:
            list: List of tuples containing registry, repository and tag.
        """
        to_sign = []
        for repo in self._generate_src_repo(item):
            ref_repo, reference = self.reference_processor(self.source_registry, repo, tag=None)
            tags = self.extractor.extract_tags(ref_repo, tolerate_missing=tolerate_missing)
            for tag in tags:
                yield (self.source_registry, repo, tag)
            if not tags:
                yield (self.source_registry, repo, None)
        return to_sign

    def _generate_existing_manifests(self, item, only_media_types=None):
        if not only_media_types:
            media_types = [
                QuayClient.MANIFEST_LIST_TYPE,
                QuayClient.MANIFEST_V2S2_TYPE,
                QuayClient.MANIFEST_V2S1_TYPE,
            ]
        else:
            media_types = only_media_types
        for repo, tag in self._generate_src_repo_tag(item):
            ref_repo, full_ref = self.reference_processor(self.source_registry, repo, tag=tag)
            man_arch_digs = self.extractor.extract_manifests(full_ref, media_types)
            for mad in man_arch_digs:
                yield (repo, tag, mad)
            if not man_arch_digs:
                yield (repo, tag, None)

    def generate_existing_manifests_map(self, item, only_media_types=None):
        """Genereate existing manifests map for given push item.

        Args:
            item (PushItem): Push item.
            only_media_types (list): List of media types to check.
        Returns:
            dict: Dict of {registry: {repo: {tag: [<ManifestArchDigest>]}}}
        """
        mapping_existing = {}
        for repo, tag, mad in self._generate_existing_manifests(
            item, only_media_types=only_media_types
        ):
            if mad:
                mapping_existing.setdefault(self.source_registry, {}).setdefault(
                    repo, {}
                ).setdefault(tag, []).append(mad)
            else:
                mapping_existing.setdefault(self.source_registry, {}).setdefault(
                    repo, {}
                ).setdefault(tag, mad)
        return mapping_existing

    def generate_existing_manifests(self, item, only_media_types=None):
        """Generate list of existing manifests for given push item.

        Args:
            item (PushItem): Push item.
            only_media_types (list): Restrict to specific media types.
        Returns:
            list: List of tuples containing repository, tag and ManifestArchDigest.
        """
        for repo, tag, mad in self._generate_existing_manifests(
            item, only_media_types=only_media_types
        ):
            yield (repo, tag, mad)
