from dataclasses import dataclass
import hashlib
import logging
from typing import List, Dict, Any, Optional, Tuple, cast, Callable, Union
from typing_extensions import TypeAlias
import requests
import time
import json

from .quay_client import QuayClient
from .exceptions import ManifestTypeError
from .utils.misc import run_in_parallel, FData

LOG = logging.getLogger("pubtools.quay")


@dataclass
class VirtualPushItem:
    """Virtual push item used for operations which doens't take push item on the input."""

    metadata: Dict[str, Any]
    repos: Dict[str, Any]

    def __post_init__(self) -> None:
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
        pub_reference (str): Public repo reference in format <registry>/repo
        digest (str): Digest of the manifest.
        arch (str): Architecture of the manifest.
    """

    repo: str
    reference: str
    pub_reference: str
    digest: str
    signing_key: str
    arch: str


@dataclass(frozen=True)
class ManifestArchDigest:
    """Data structure to hold information about container manifest."""

    manifest: str
    digest: str
    arch: str
    type_: str


class ContentExtractor:
    """Class is used to extract specific content from container registry based on provided input."""

    _MEDIA_TYPES_PRIORITY = {
        QuayClient.MANIFEST_LIST_TYPE: 30,
        QuayClient.MANIFEST_V2S2_TYPE: 20,
        QuayClient.MANIFEST_V2S1_TYPE: 10,
    }

    def __init__(
        self,
        quay_client: QuayClient,
        sleep_time: int = 5,
        timeout: int = 10,
        poll_rate: int = 5,
        full_extract: bool = False,
    ):
        """Initialize the class.

        Args:
            quay_client (QuayClient): Quay client used to communicate with container registry.
            sleep_time (int): Time to sleep between retries.
            timeout (int): Timeout for HTTP requests.
            poll_rate (int): Poll rate for HTTP requests.
        """
        self.quay_client = quay_client
        self.sleep_time: int = sleep_time
        self.timeout: int = timeout
        self.poll_rate: int = poll_rate
        self.full_extract = full_extract

    def _extract_ml_manifest_full(
        self, image_ref: str, _manifest_list: str, mtype: str, ret_headers: Dict[str, Any]
    ) -> List[ManifestArchDigest]:
        """Extract manifests from manifest list.

        Args:
            image_ref (str): Image reference in format <registry>/<repo>:<tag>
            _manifest_list (str): Manifest list in JSON format.
            mtype (str): NOT USED
        Returns:
            list: List of ManifestArchDigest objects.
        """
        mads = []
        manifest = json.loads(_manifest_list)
        mads.append(
            ManifestArchDigest(
                manifest=_manifest_list,
                digest=ret_headers.get("docker-content-digest", ""),
                arch="",
                type_=QuayClient.MANIFEST_LIST_TYPE,
            )
        )
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

    def _extract_ml_manifest(
        self, image_ref: str, _manifest_list: str, mtype: str, ret_headers: Dict[str, Any]
    ) -> List[ManifestArchDigest]:
        """Extract manifests from manifest list.

        Args:
            image_ref (str): Image reference in format <registry>/<repo>:<tag>
            _manifest_list (str): Manifest list in JSON format.
            mtype (str): NOT USED
        Returns:
            list: List of ManifestArchDigest objects.
        """
        mads = []
        mads.append(
            ManifestArchDigest(
                manifest=_manifest_list,
                digest=ret_headers.get("docker-content-digest", ""),
                arch="",
                type_=QuayClient.MANIFEST_LIST_TYPE,
            )
        )
        return mads

    def _extract_manifest(
        self, unused: str, manifest: str, mtype: str, ret_headers: Dict[str, Any]
    ) -> ManifestArchDigest:
        """Calculate information from given manifest.

        Args:
            unused (str): This parameter is unused for this specific method.
            It's definied like this to simply  keep same signature as similar
            method `_extract_ml_manifest`
            manifest (str): Manifest
            mtype (str): Media type of the manifest.
        Returns:
            ManifestArchDigest: ManifestArchDigest object.
        """
        hasher = hashlib.sha256()
        hasher.update(manifest.encode("utf-8"))
        digest = f"sha256:{hasher.hexdigest()}"
        return ManifestArchDigest(manifest=manifest, digest=digest, arch="amd64", type_=mtype)

    _MEDIA_TYPES_PROCESS: Dict[
        str,
        Callable[
            [Any, str, str, str, Dict[str, Any]],
            Union[ManifestArchDigest, List[ManifestArchDigest]],
        ],
    ] = {
        QuayClient.MANIFEST_LIST_TYPE: _extract_ml_manifest,
        QuayClient.MANIFEST_V2S2_TYPE: _extract_manifest,
        QuayClient.MANIFEST_V2S1_TYPE: _extract_manifest,
    }

    _MEDIA_TYPES_PROCESS_FULL: Dict[
        str,
        Callable[
            [Any, str, str, str, Dict[str, Any]],
            Union[ManifestArchDigest, List[ManifestArchDigest]],
        ],
    ] = {
        QuayClient.MANIFEST_LIST_TYPE: _extract_ml_manifest_full,
        QuayClient.MANIFEST_V2S2_TYPE: _extract_manifest,
        QuayClient.MANIFEST_V2S1_TYPE: _extract_manifest,
    }

    def extract_manifests(
        self, image_ref: str, media_types: Optional[List[str]], tolerate_missing: bool = True
    ) -> List[ManifestArchDigest]:
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
        mtypes = (
            sorted(media_types or [], key=lambda x: self._MEDIA_TYPES_PRIORITY[x], reverse=True)
            or self._MEDIA_TYPES_PRIORITY.keys()
        )
        if self.full_extract:
            MEDIA_TYPES_PROCESS = self._MEDIA_TYPES_PROCESS_FULL
        else:
            MEDIA_TYPES_PROCESS = self._MEDIA_TYPES_PROCESS
        results = []
        for mtype in mtypes:
            ret_headers: Dict[str, Any] = {}
            for i in range(self.timeout // self.poll_rate):
                try:
                    ret = cast(
                        Tuple[str, Dict[str, Any]],
                        self.quay_client.get_manifest(
                            image_ref, media_type=mtype, raw=True, return_headers=True
                        ),
                    )
                    if ret:
                        manifest, ret_headers = ret
                    else:
                        manifest = None
                except requests.exceptions.HTTPError as e:
                    # When robot account is used, 401 may be returned instead of 404
                    if (
                        e.response.status_code == 404 or e.response.status_code == 401
                    ) and tolerate_missing:
                        manifest = None
                    # tolerate too many requests from client
                    elif e.response.status_code == 429:
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
                mret: Union[ManifestArchDigest, List[ManifestArchDigest]] = MEDIA_TYPES_PROCESS[
                    mtype
                ](self, image_ref, manifest, mtype, ret_headers)
                if isinstance(mret, list):
                    results.extend(mret)
                else:
                    results.append(mret)
        seen = set()
        return [x for x in results if all([x not in seen, not (seen.add(x))])]  # type: ignore

    def extract_tags(self, repo_ref: str, tolerate_missing: bool = True) -> List[str]:
        """Fetch list of tags for given repo reference.

        Args:
            repo_ref (str): Repo reference in format <registry>/<repo>
            tolerate_missing (bool): If True, missing repo is tolerated and empty list
            is returned.
        Returns:
            list: List of tags.
        """
        try:
            repo_tags = cast(Dict[str, List[str]], self.quay_client.get_repository_tags(repo_ref))
        except requests.exceptions.HTTPError as e:
            # When robot account is used, 401 is returned instead of 404
            if tolerate_missing and e.response.status_code == 404 or e.response.status_code == 401:
                repo_tags = {"tags": []}
            else:
                raise
        return repo_tags["tags"]


class ReferenceProcessorExternal:
    """Class is used to produce full image reference or repo reference from input."""

    def full_reference(self, registry: str, repo: str, tag: Optional[str] = None) -> str:
        """Produce full image reference from input.

        Args:
            registry (str): Registry where image is located.
            repo (str): Repository name.
            tag (Optional[str]): Tag name, if not set only repo reference is returned
        Returns:
            str: full image reference.
        """
        if tag:
            return f"{registry}/{repo}:{tag}"
        else:
            return f"{registry}/{repo}"

    def replace_repo(self, repo: str) -> str:
        """Return repo unmodified.

        External reference processor does not modify repo.

        Args:
            repo (str): Repository in format <namespace>/<product>
        Returns:
            str: Repository
        """
        return repo


@dataclass
class ReferenceProcessorInternal:
    """Class is used to produce full internal image reference from input."""

    INTERNAL_DELIMITER = "----"
    quay_namespace: str

    def full_reference(self, registry: str, repo: str, tag: Optional[str] = None) -> str:
        """Produce full internal image reference from input.

        Args:
            registry (str): Registry where image is located.
            repo (str): Repository name.
            tag (Optional[str]): Tag name.
        Returns:
            str: full image reference.
        """
        if repo.count("/") == 0:
            if tag:
                return f"{registry}/{self.quay_namespace}/{repo}:{tag}"
            else:
                return f"{registry}/{self.quay_namespace}/{repo}"
        if repo.count("/") > 1 or repo[0] == "/" or repo[-1] == "/":
            raise ValueError(
                "Input repository containing a delimeter should "
                "have the format '<namespace>/<product>' or '<repository>'",
                repo,
            )
        replaced = repo.replace("/", self.INTERNAL_DELIMITER)
        if tag:
            return f"{registry}/{self.quay_namespace}/{replaced}:{tag}"
        else:
            return f"{registry}/{self.quay_namespace}/{replaced}"

    def replace_repo(self, repo: str) -> str:
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
    reference_processor: Union[ReferenceProcessorExternal, ReferenceProcessorInternal]
    reference_registries: List[str]
    source_registry: Optional[str]
    public_registries: List[str]

    INTERNAL_DELIMITER = "----"

    def _generate_dest_repo(self, item: PushItem) -> List[Tuple[str, str]]:
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

    def _generate_src_repo(self, item: PushItem) -> List[str]:
        """Return list of source repos for given push item.

        Returns:
            list: List of source repositories.
        """
        return list(item.repos.keys())

    def _generate_src_repo_tag(self, item: PushItem) -> List[Tuple[str, str]]:
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

    def generate_repo_dest_tags(self, item: PushItem) -> List[Tuple[str, str, str]]:
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

    def generate_repo_untags(self, item: PushItem) -> List[Tuple[str, str]]:
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

    def generate_repo_dest_tag_map(self, item: PushItem) -> Dict[str, Dict[str, List[str]]]:
        """Return map of destination repositories and tags.

        Args:
            item (PushItem): Push item.
        Returns:
            dict: Dict of {registry: {repo: [tags]}}
        """
        ret: dict[str, Dict[str, list[str]]] = {}
        for registry, repo in self._generate_dest_repo(item):
            for repo, tags in item.metadata["tags"].items():
                for tag in tags:
                    ret.setdefault(registry, {}).setdefault(repo, []).append(tag)
        return ret

    def generate_to_sign(self, item: Any, include_manifest_lists: bool = False) -> List[SignEntry]:
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

        full_extract_orig = self.extractor.full_extract
        self.extractor.full_extract = True
        man_arch_digs = self.extractor.extract_manifests(item.metadata["pull_url"], media_types)
        self.extractor.full_extract = full_extract_orig

        for registry, repo, tag in self.generate_repo_dest_tags(item):
            reference = self.reference_processor.full_reference(registry, repo, tag)
            for mad in man_arch_digs:
                if mad.type_ == QuayClient.MANIFEST_LIST_TYPE and not include_manifest_lists:
                    continue
                public_registries = self.public_registries if registry == "quay.io" else [registry]
                for public_registry in public_registries:
                    to_sign.append(
                        SignEntry(
                            repo=repo,
                            reference=reference,
                            pub_reference=f"{public_registry}/{repo}:{tag}",
                            digest=mad.digest,
                            arch=mad.arch,
                            signing_key=item.claims_signing_key,
                        )
                    )
        return to_sign

    def generate_to_unsign(self, item: PushItem) -> List[Dict[str, Any]]:
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
        references = []
        for repo, tag in self.generate_repo_untags(item):
            references.append(
                self.reference_processor.full_reference(cast(str, self.source_registry), repo, tag)
            )

        full_extract_orig = self.extractor.full_extract
        self.extractor.full_extract = True
        man_arch_digs_map = run_in_parallel(
            self.extractor.extract_manifests, [FData(args=(ref, media_types)) for ref in references]
        )
        self.extractor.full_extract = full_extract_orig

        for ref_index, man_arch_digs in man_arch_digs_map.items():
            for mad in man_arch_digs:
                to_unsign.append(
                    {
                        "reference": references[ref_index],
                        "digest": mad.digest,
                        "repo": repo,
                        "arch": mad.arch,
                    }
                )
        return to_unsign

    def generate_existing_tags(
        self, item: PushItem, tolerate_missing: bool = True
    ) -> List[Tuple[str, str, Union[str, None]]]:
        """Generate list of existing tags for given push item.

        Args:
            item (PushItem): Push item.
            tolerate_missing (bool): If True, tolerate missing tags.
        Returns:
            list: List of tuples containing registry, repository and tag.
        """
        existing_tag_entries: List[Tuple[str, str, Union[str, None]]] = []
        for repo in self._generate_src_repo(item):
            ref_repo = self.reference_processor.replace_repo(repo)
            tags = self.extractor.extract_tags(ref_repo, tolerate_missing=tolerate_missing)
            for tag in tags:
                existing_tag_entries.append((cast(str, self.source_registry), repo, tag))
            if not tags:
                existing_tag_entries.append((cast(str, self.source_registry), repo, None))
        return existing_tag_entries

    def _generate_existing_manifests(
        self, item: PushItem, only_media_types: Union[List[str], None] = None
    ) -> List[Tuple[str, str, Optional[ManifestArchDigest]]]:
        """Generate list of existing manifests data for given push item.

        Args:
            item (PushItem): Push item.
            only_media_types (list): Restrict to specific media types.
        Returns:
            list: List of tuples containing repository, tag and ManifestArchDigest.
        """
        existing_manifests: List[Tuple[str, str, Union[ManifestArchDigest, None]]] = []
        if not only_media_types:
            media_types = [
                QuayClient.MANIFEST_LIST_TYPE,
                QuayClient.MANIFEST_V2S2_TYPE,
                QuayClient.MANIFEST_V2S1_TYPE,
            ]
        else:
            media_types = only_media_types

        references = []
        for repo, tag in self._generate_src_repo_tag(item):
            full_ref = self.reference_processor.full_reference(
                cast(str, self.source_registry), repo, tag=tag
            )
            references.append((full_ref, repo, tag))

        man_arch_digs_map = run_in_parallel(
            self.extractor.extract_manifests,
            [FData(args=(ref_meta[0], media_types)) for ref_meta in references],
        )
        for ref_index, man_arch_digs in man_arch_digs_map.items():
            reference, repo, tag = references[ref_index]
            for mad in man_arch_digs:
                if (repo, tag, mad) not in existing_manifests:
                    existing_manifests.append((repo, tag, mad))
            if not man_arch_digs:
                # If no manifest found, set tag to None
                if (repo, tag, None) not in existing_manifests:
                    existing_manifests.append((repo, tag, None))
        return existing_manifests

    def generate_existing_manifests_map(
        self, item: PushItem, only_media_types: Union[List[str], None] = None
    ) -> Dict[str, Dict[str, Dict[str, Union[List[ManifestArchDigest], None]]]]:
        """Generate existing manifests map for given push item.

        Args:
            item (PushItem): Push item.
            only_media_types (list): List of media types to check.
        Returns:
            dict: Dict of {registry: {repo: {tag: [<ManifestArchDigest>]}}}
        """
        mapping_existing: Dict[str, Dict[str, dict[str, Union[List[ManifestArchDigest], None]]]] = (
            {}
        )
        for repo, tag, mad in self._generate_existing_manifests(
            item, only_media_types=only_media_types
        ):
            if mad:
                cast(
                    List[ManifestArchDigest],
                    mapping_existing.setdefault(cast(str, self.source_registry), {})
                    .setdefault(repo, {})
                    .setdefault(tag, []),
                ).append(mad)
            else:
                mad = cast(None, mad)
                mapping_existing.setdefault(cast(str, self.source_registry), {}).setdefault(
                    repo, {}
                ).setdefault(tag, mad)
        return mapping_existing

    def generate_existing_manifests_metadata(
        self, item: PushItem, only_media_types: Union[List[str], None] = None
    ) -> List[Tuple[str, str, Union[ManifestArchDigest, None]]]:
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

    def generate_all_existing_manifests_metadata(
        self, item: PushItem
    ) -> List[Tuple[str, str, Union[ManifestArchDigest, None]]]:
        """Return manifests for all existing tags in all repositories for given push item.

        Args:
            item (PushItem): Push item.
        Returns:
            list: List of tuples containing repository, tag and ManifestArchDigest.
        """
        repo_tags_map: dict[str, List[Union[str, None]]] = {}
        for registry, repo, tag in self.generate_existing_tags(item):
            repo_tags_map.setdefault(repo, []).append(tag)
        item2 = VirtualPushItem(
            metadata={"tags": repo_tags_map},
            repos={repo: [] for repo in repo_tags_map.keys()},
        )
        return self.generate_existing_manifests_metadata(item2)


def item_processor_for_external_data(
    quay_client: QuayClient, external_registries: List[str], retry_sleep_time: int
) -> ItemProcesor:
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
        public_registries=external_registries,
    )


def item_processor_for_internal_data(
    quay_client: QuayClient,
    internal_registry: str,
    external_registries: List[str],
    retry_sleep_time: int,
    internal_namespace: str,
) -> ItemProcesor:
    """Get instance of item processor configured to produce internal data.

    Args:
        quay_client (QuayClient): Quay client.
        internal_registry (str): Docker registry where containers are stored
        external registries (str): List of external registries used for container identity.
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
        reference_registries=["quay.io"],
        source_registry=internal_registry,
        public_registries=external_registries,
    )
