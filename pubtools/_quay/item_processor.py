from dataclasses import dataclass
import hashlib
from typing import List, Dict, Any, Optional, TypeAlias
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

    def __post_init__(self):
        """Post init validation of the instance."""
        if "tags" not in self.metadata:
            raise ValueError("VirtualPushItem is missing 'tags' in metadata")


PushItem: TypeAlias = VirtualPushItem


@dataclass
class SignEntry:
    """Data structure to hold signing related information.

    Args:
        signing_key (str): Signing key.
        repo (str): Repo reference in format <registry>/<repo>
        reference (str): Reference in format <registry>/<repo>:<tag>
        digest (str): Digest of the manifest.
        arch (str): Architecture of the manifest.
    """

    repo: str
    reference: str
    digest: str
    signing_key: str
    arch: str


@dataclass
class ManifestArchDigest:
    """Data structure to hold information about container manifest."""

    manifest: str
    digest: str
    arch: str
    type_: str


@dataclass
class ContentExtractor:
    """Class is used to extract specific content from container registry based on provided input.

    Args:
        quay_client (QuayClient): Quay client used to communicate with container registry.
        sleep_time (int): Time to sleep between retries.
        timeout (int): Timeout for HTTP requests.
        poll_rate (int): Poll rate for HTTP requests.
    """

    _MEDIA_TYPES_PRIORITY = {
        QuayClient.MANIFEST_LIST_TYPE: 30,
        QuayClient.MANIFEST_V2S2_TYPE: 20,
        QuayClient.MANIFEST_V2S1_TYPE: 10,
    }
    quay_client: QuayClient
    sleep_time: int = 5
    timeout: int = 60
    poll_rate: int = 5

    def _extract_ml_manifest(
        self, image_ref: str, _manifest: str, mtype: str
    ) -> List[ManifestArchDigest]:
        """Extract manifests from manifest list.

        Args:
            image_ref (str): Image reference in format <registry>/<repo>:<tag>
            _manifest (str): Manifest list in JSON format.
            mtype (str): NOT USED
        Returns:
            list: List of ManifestArchDigest objects.
        """
        mads = []
        manifest = json.loads(_manifest)
        for arch_manifest in manifest["manifests"]:
            manifest = self.quay_client.get_manifest(
                f"{image_ref.rsplit(':')[0]}@{arch_manifest['digest']}",
                media_type=QuayClient.MANIFEST_V2S2_TYPE,
                raw=True,
            )
            mads.append(
                ManifestArchDigest(
                    manifest=manifest,
                    digest=arch_manifest["digest"],
                    arch=arch_manifest["platform"]["architecture"],
                    type_=QuayClient.MANIFEST_V2S2_TYPE,
                )
            )
        return mads

    def _extract_manifest(self, repo: str, manifest: str, mtype: str) -> ManifestArchDigest:
        """Calculate information from given manifest.

        Args:
            repo (str): Repo reference in format <registry>/<repo>
            manifest (str): Manifest
            mtype (str): Media type of the manifest.
        Returns:
            ManifestArchDigest: ManifestArchDigest object.
        """
        hasher = hashlib.sha256()
        hasher.update(manifest.encode("utf-8"))
        digest = f"sha256:{hasher.hexdigest()}"
        return ManifestArchDigest(manifest=manifest, digest=digest, arch="amd64", type_=mtype)

    _MEDIA_TYPES_PROCESS = {
        QuayClient.MANIFEST_LIST_TYPE: _extract_ml_manifest,
        QuayClient.MANIFEST_V2S2_TYPE: _extract_manifest,
        QuayClient.MANIFEST_V2S1_TYPE: _extract_manifest,
    }

    def extract_manifests(
        self, image_ref: str, media_types: Optional[List[str]], tolerate_missing: bool = True
    ):
        """Extract manifests from container registry.

        Method fetches manifests for all provided media types. If HTTPErrors is raised when
        fetching for manifest and status code is 404 or 401, it's retried as there can be delay
        in registry if manifest was just pushed to it.
        When manifest is not found for given media type, it's not included in the result.
        media_types can be also empty and it that case all container media types are used

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

    def extract_tags(self, repo_ref: str, tolerate_missing: bool = True):
        """Fetch list of tags for given image reference.

        Args:
            repo_ref (str): Repo reference in format <registry>/<repo>
            tolerate_missing (bool): If True, missing repo is tolerated and empty list
            is returned.
        Returns:
            list: List of tags.
        """
        try:
            repo_tags = self.quay_client.get_repository_tags(repo_ref)
        except requests.exceptions.HTTPError as e:
            # When robot account is used, 401 is returned instead of 404
            if tolerate_missing and e.response.status_code == 404 or e.response.status_code == 401:
                repo_tags = {"tags": []}
            else:
                raise
        return repo_tags["tags"]


@dataclass
class ReferenceProcessorExternal:
    """Class is used to produce full image reference or repo reference from input."""

    def __call__(self, registry: str, repo: str, tag: Optional[str] = None):
        """Produce full image reference from input.

        Args:
            registry (str): Registry where image is located.
            repo (str): Repository name.
            tag (Optional[str]): Tag name, if not set only repo reference is returned
        Returns:
            tuple: Tuple containing repository name and full image reference if tag is set repo
            reference otherwise.
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

    def __call__(self, registry: str, repo: str, tag: Optional[str] = None):
        """Produce full internal image reference from input.

        Args:
            registry (str): Registry where image is located.
            repo (str): Repository name.
            tag (Optional[str]): Tag name.
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
                "have the format '<namespace>/<product>' or '<repository>'",
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

    def replace_repo(self, repo: str):
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
                "have the format '<namespace>/<product>' or '<repository>'",
                repo,
            )
        replaced = repo.replace("/", self.INTERNAL_DELIMITER)
        return f"{self.quay_namespace}/{replaced}"


@dataclass
class ItemProcesor:
    """Class is used to process push item and extract various data from it.

    Args:
        extractor (ContentExtractor): Content extractor which is used when container metadata for
        processed push item is needed.
        reference_processor (ReferenceProcessor): Reference processor to produce reference from
        provided push item. Based on used reference processor it can produce reference to internal
        or external push item.
        reference_registries (List[str]): List of destination registries where push item should be
        available when pushed. Can be empty if there's no need to generate destination data.
        source_registry (str): Source registry where source container image is located.
        Can be empty if there's no need to generate source data.
    """

    extractor: ContentExtractor
    reference_processor: ReferenceProcessorExternal
    reference_registries: List[str]
    source_registry: str

    INTERNAL_DELIMITER = "----"

    def _generate_dest_repo(self, item: PushItem):
        """Return list of (<dest-registry>, <dest-repository>) tuples for given push item.

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of tuples containing registry and repository.
        """
        dest_registry_repos = []
        for registry in self.reference_registries:
            for repo in item.metadata["tags"].keys():
                dest_registry_repos.append((registry, repo))
        return dest_registry_repos

    def _generate_src_repo(self, item: PushItem):
        """Return list of source repos for given push item.

        Returns:
            list: List of source repositories.
        """
        return item.repos.keys()

    def _generate_src_repo_tag(self, item: PushItem):
        """Return list of tuples of (<source-repo>, <tag>).

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of tuples containing source repository and tag.
        """
        src_repo_tag = []
        for repo, tags in item.metadata["tags"].items():
            for tag in tags:
                src_repo_tag.append((repo, tag))
        return src_repo_tag

    def generate_repo_dest_tags(self, item: PushItem):
        """Return list of destination repositories and tags.

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

    def generate_repo_untags(self, item: PushItem):
        """Return list of repositories and tags which are destined to be untag.

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

    def generate_repo_dest_tag_map(self, item: PushItem):
        """Return map of destination repositories and tags.

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

    def generate_to_sign(self, item: PushItem, sign_only_arches: List[str] = []) -> List[SignEntry]:
        """Generate list of images to sign.

        Args:
            item (PushItem): Push item.
            sign_only_arches(List[str]): List of architectures to sign.
            If empty, all sign architectures.
        Returns:
            list: List of dictionaries containing reference, digest, repository and architecture.
        """
        to_sign = []
        media_types = (
            item.metadata.get("build", {}).get("extra", {}).get("image", {}).get("media_types", [])
        )

        for registry, repo, tag in self.generate_repo_dest_tags(item):
            _, reference = self.reference_processor(registry, repo, tag)
            man_arch_digs = self.extractor.extract_manifests(item.metadata["pull_url"], media_types)
            for mad in man_arch_digs:
                if sign_only_arches and mad.arch not in sign_only_arches:
                    continue
                to_sign.append(
                    SignEntry(
                        repo=repo,
                        reference=reference,
                        digest=mad.digest,
                        arch=mad.arch,
                        signing_key=item.claims_signing_key,
                    )
                )
        return to_sign

    def generate_to_unsign(self, item: PushItem):
        """Generate list of images to unsign.

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of dictionaries containing reference, digest, repository and architecture.
        """
        to_unsign = []
        media_types = (
            item.metadata.get("build", {}).get("extra", {}).get("image", {}).get("media_types", [])
        )

        for repo, tag in self.generate_repo_untags(item):
            ref_repo, reference = self.reference_processor(None, repo, tag)
            man_arch_digs = self.extractor.extract_manifests(
                f"{self.source_registry}/{ref_repo}:{tag}", media_types
            )
            for mad in man_arch_digs:
                to_unsign.append(
                    {"reference": reference, "digest": mad.digest, "repo": repo, "arch": mad.arch}
                )
        return to_unsign

    def generate_existing_tags(self, item: PushItem, tolerate_missing: bool = True):
        """Generate list of existing tags for given push item.

        Args:
            item (PushItem): Push item.
            tolerate_missing (bool): If True, tolerate missing tags.
        Returns:
            list: List of tuples containing registry, repository and tag.
        """
        existing_tag_entries = []
        for repo in self._generate_src_repo(item):
            ref_repo, _ = self.reference_processor(self.source_registry, repo, tag=None)
            tags = self.extractor.extract_tags(ref_repo, tolerate_missing=tolerate_missing)
            for tag in tags:
                existing_tag_entries.append((self.source_registry, repo, tag))
            if not tags:
                existing_tag_entries.append((self.source_registry, repo, None))
        return existing_tag_entries

    def _generate_existing_manifests(self, item: PushItem, only_media_types=None):
        existing_manifests = []
        if not only_media_types:
            media_types = [
                QuayClient.MANIFEST_LIST_TYPE,
                QuayClient.MANIFEST_V2S2_TYPE,
                QuayClient.MANIFEST_V2S1_TYPE,
            ]
        else:
            media_types = only_media_types
        for repo, tag in self._generate_src_repo_tag(item):
            _, full_ref = self.reference_processor(self.source_registry, repo, tag=tag)
            man_arch_digs = self.extractor.extract_manifests(full_ref, media_types)
            for mad in man_arch_digs:
                if (repo, tag, mad) not in existing_manifests:
                    existing_manifests.append((repo, tag, mad))
            if not man_arch_digs:
                # If no manifest found, set tag to None
                if (repo, tag, None) not in existing_manifests:
                    existing_manifests.append((repo, tag, None))
        return existing_manifests

    def generate_existing_manifests_map(self, item: PushItem, only_media_types=None):
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

    def generate_existing_manifests(self, item: PushItem, only_media_types=None):
        """Generate list of existing manifests for given push item.

        Args:
            item (PushItem): Push item.
            only_media_types (list): Restrict to specific media types.
        Returns:
            list: List of tuples containing repository, tag and ManifestArchDigest.
        """
        existing_manifests = []
        for repo, tag, mad in self._generate_existing_manifests(
            item, only_media_types=only_media_types
        ):
            existing_manifests.append((repo, tag, mad))
        return existing_manifests

    def generate_all_existing_manifests(self, item: PushItem):
        """Return manifests for all existing tags in all repositories for given push item.

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of tuples containing repository, tag and ManifestArchDigest.
        """
        repo_tags_map = {}
        for registry, repo, tag in self.generate_existing_tags(item):
            repo_tags_map.setdefault(repo, []).append(tag)
        item2 = VirtualPushItem(
            metadata={"tags": repo_tags_map},
            repos={repo: [] for repo in repo_tags_map.keys()},
        )
        return self.generate_existing_manifests(item2)


def item_processor_for_external_data(quay_client, external_registries, retry_sleep_time):
    """Get instance of item processor configured to produce destination data.

    Args:
        quay_client (QuayClient): Quay client.
        external_registries (list): List of external registries.
        retry_sleep_time (int): sleep time bewteen retries for fetching data from registry.
    Returns:
        ItemProcessor: Instance of item processor.
    """
    extractor = ContentExtractor(quay_client=quay_client, sleep_time=retry_sleep_time)
    return ItemProcesor(
        extractor=extractor,
        reference_processor=ReferenceProcessorExternal(),
        reference_registries=external_registries,
        source_registry=None,
    )


def item_processor_for_internal_data(
    quay_client, internal_registry, retry_sleep_time, internal_namespace
):
    """Get instance of item processor configured to produce internal data.

    Args:
        quay_client (QuayClient): Quay client.
        internal_registry (str): Docker registry where containers are stored
        retry_sleep_time (int): sleep time bewteen retries for fetching data from registry.
        internal_namespace (str): Namespace of internal organization in the registry.
    Returns:
        ItemProcessor: Instance of item processor.
    """
    extractor = ContentExtractor(quay_client=quay_client, sleep_time=retry_sleep_time)
    reference_processor = ReferenceProcessorInternal(internal_namespace)
    return ItemProcesor(
        extractor=extractor,
        reference_processor=reference_processor,
        reference_registries=[],
        source_registry=internal_registry,
    )
