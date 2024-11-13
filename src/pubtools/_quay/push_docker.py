from collections import namedtuple
import logging
import sys
import json
from typing import Tuple, List, Dict, Any, cast, Optional

import requests
import urllib3

from .exceptions import BadPushItem, InvalidTargetSettings, InvalidRepository
from .utils.misc import get_internal_container_repo_name, log_step
from .quay_api_client import QuayApiClient
from .quay_client import QuayClient
from .iib_operations import _sign_index_image
from .container_image_pusher import ContainerImagePusher
from .security_manifest_pusher import SecurityManifestPusher

from .operator_pusher import OperatorPusher
from .item_processor import (
    item_processor_for_external_data,
    item_processor_for_internal_data,
    SignEntry,
    ManifestArchDigest,
)
from .utils.misc import parse_index_image
from .signer_wrapper import SIGNER_BY_LABEL

from .utils.misc import (
    get_external_container_repo_name,
    timestamp,
    pyxis_get_repo_metadata,
    set_aws_kms_environment_variables,
    run_in_parallel,
    FData,
)

# TODO: do we want this, or should I remove it?
from urllib3.exceptions import InsecureRequestWarning

urllib3.disable_warnings(InsecureRequestWarning)

LOG = logging.getLogger("pubtools.quay")


class PushDocker:
    """Handle full Docker push workflow."""

    ImageData = namedtuple(
        "ImageData", ["repo", "tag", "v2list_digest", "v2s2_digest", "v2s1_digest"]
    )

    def __init__(
        self,
        push_items: List[Any],
        hub: Any,
        task_id: str,
        target_name: str,
        target_settings: Dict[str, Any],
    ) -> None:
        """
        Initialize.

        Args:
            push_items ([_PushItem]):
                List of push items.
            hub (HubProxy):
                Instance of XMLRPC pub-hub proxy.
            task_id (str):
                task id
            target_name (str):
                Name of the target.
            target_settings (dict):
                Target settings.
        """
        self.push_items = push_items
        self.hub = hub
        self.task_id = task_id
        self.target_name = target_name
        self.target_settings = target_settings

        self.verify_target_settings()

        self.quay_host = self.target_settings.get("quay_host", "quay.io").rstrip("/")

        self._src_quay_client: Optional[QuayClient] = None
        self._dest_quay_client: Optional[QuayClient] = None
        self._dest_operator_quay_client: Optional[QuayClient] = None
        self._dest_quay_api_client: Optional[QuayApiClient] = None
        self._index_image_quay_client = None
        self.dest_registries = self.target_settings["docker_settings"]["docker_reference_registry"]
        self.dest_registries = (
            self.dest_registries
            if isinstance(self.dest_registries, list)
            else [self.dest_registries]
        )

    @property
    def dest_quay_client(self) -> QuayClient:
        """Create and access QuayClient for dest image."""
        if self._dest_quay_client is None:
            self._dest_quay_client = QuayClient(
                self.target_settings["dest_quay_user"],
                self.target_settings["dest_quay_password"],
                self.quay_host,
            )
        return self._dest_quay_client

    @property
    def src_quay_client(self) -> QuayClient:
        """Create and access QuayClient for source image."""
        if self._src_quay_client is None:
            self._src_quay_client = QuayClient(
                self.target_settings["source_quay_user"],
                self.target_settings["source_quay_password"],
                self.target_settings.get("source_quay_host") or self.quay_host,
            )
        return self._src_quay_client

    @property
    def dest_operator_quay_client(self) -> QuayClient:
        """Create and access QuayClient for dest image."""
        if self._dest_operator_quay_client is None:
            self._dest_operator_quay_client = QuayClient(
                self.target_settings.get(
                    "index_image_quay_user", self.target_settings["dest_quay_user"]
                ),
                self.target_settings.get(
                    "index_image_quay_password", self.target_settings["dest_quay_password"]
                ),
                self.quay_host,
            )
        return self._dest_operator_quay_client

    @property
    def dest_quay_api_client(self) -> QuayApiClient:
        """Create and access QuayApiClient for dest image."""
        if self._dest_quay_api_client is None:
            self._dest_quay_api_client = QuayApiClient(
                self.target_settings["dest_quay_api_token"], self.quay_host
            )
        return self._dest_quay_api_client

    def verify_target_settings(self) -> None:
        """Verify that target settings contains all the necessary data."""
        LOG.info("Verifying the necessary target settings")
        required_settings = [
            "source_quay_user",
            "source_quay_password",
            "dest_quay_user",
            "dest_quay_password",
            "dest_quay_api_token",
            "pyxis_server",
            "quay_namespace",
            "iib_krb_principal",
            "iib_organization",
            "iib_index_image",
            "quay_operator_repository",
            "skopeo_image",
            "docker_settings",
        ]
        for setting in required_settings:
            if setting not in self.target_settings:
                raise InvalidTargetSettings(
                    "'{0}' must be present in the target settings.".format(setting)
                )

        required_docker_settings = ["umb_urls", "docker_reference_registry"]
        for setting in required_docker_settings:
            if setting not in self.target_settings["docker_settings"]:
                raise InvalidTargetSettings(
                    "'{0}' must be present in the docker settings.".format(setting)
                )

    @log_step("Get container push items")
    def get_docker_push_items(self) -> List[Any]:
        """
        Filter push items to only include docker ones.

        Also, Check the validity of these items and raise an exception in case of incorrect data.

        For items having the same pull_url, only one of them is returned to avoid duplication.

        Returns ([ContainerPushItem]):
            Docker push items.
        """
        docker_push_items = []
        url_items: Dict[str, Any] = {}
        for item in self.push_items:
            if item.file_type != "docker":
                LOG.warning("Push item {0} doesn't have 'docker' type, skipping.".format(item))
                continue
            if item.errors:
                raise BadPushItem("Push item {0} contains errors: {1}".format(item, item.errors))
            if not item.metadata.get("pull_data"):
                raise BadPushItem("Push item {0} doesn't contain pull data.".format(item))
            LOG.info("Docker push item found: {0}".format(item))
            pull_url = item.metadata["pull_url"]
            if pull_url in url_items:
                url_items[pull_url].append(item)
            else:
                url_items[pull_url] = [item]
        for _, items in url_items.items():
            non_amd64 = True
            for item in items:
                if item.metadata["arch"] in ["amd64", "x86_64"]:
                    docker_push_items.append(item)
                    non_amd64 = False
                    break
            if non_amd64:
                docker_push_items.append(items[0])

        return docker_push_items

    @log_step("Get operator push items")
    def get_operator_push_items(self) -> List[Any]:
        """
        Filter out push items to only include operator ones.

        Also, Check the validity of these items and raise an exception in case of incorrect data.

        Returns ([ContainerPushItem]):
            Operator push items.
        """
        operator_push_items = []
        for item in self.push_items:
            if item.file_type != "operator":
                LOG.warning("Push item {0} doesn't have 'operator' type, skipping.".format(item))
                continue
            if item.errors:
                raise BadPushItem("Push item {0} contains errors: {1}".format(item, item.errors))
            if not item.metadata.get("op_type"):
                raise BadPushItem("Push item {0} doesn't contain 'op_type'".format(item))
            if item.metadata["op_type"] == "appregistry":
                LOG.warning(
                    "Push item {0} is unsupported legacy (appregistry), skipping".format(item)
                )
                continue
            if item.metadata["op_type"] != "bundle":
                message = "Push item {0} has unknown op_type: '{1}'.".format(
                    item, item.metadata["op_type"]
                )
                raise BadPushItem(message)
            if not item.metadata.get("com.redhat.openshift.versions"):
                msg = "Push item {0} doesn't specify 'com.redhat.openshift.versions'".format(item)
                raise BadPushItem(msg)
            LOG.info("Operator push item found: {0}".format(item))
            operator_push_items.append(item)

        return operator_push_items

    @classmethod
    def check_repos_validity(
        cls, push_items: List[Any], hub: Any, target_settings: Dict[str, Any]
    ) -> None:
        """
        Check if specified repos are valid and pushing to them is allowed.

        Specifically, this method checks if the repo exists in Comet and if it's not deprecated
        If pushing to prod, also check if the repo already exists in stage.

        Args:
            push_items ([ContainerPushItem]):
                Container push items containing the repositories.
            hub (HubProxy):
                Instance of XMLRPC pub-hub proxy.
            target_settings (dict):
                Target settings.
        """
        repos = []
        for item in push_items:
            if item.external_repos:
                repos += item.external_repos.keys()
            else:
                repos += item.repos.keys()

        repos = sorted(list(set(repos)))
        repo_schema = "{namespace}/{repo}"

        # we'll need to get stage namespace from stage target settings
        if "propagated_from" in target_settings:
            stage_target_info = hub.worker.get_target_info(target_settings["propagated_from"])
            stage_namespace = stage_target_info["settings"]["quay_namespace"]
            stage_quay_client = QuayClient(
                stage_target_info["settings"]["dest_quay_user"],
                stage_target_info["settings"]["dest_quay_password"],
            )

        for repo in repos:
            # Only check Pyxis if the option is enabled in target settings
            if target_settings.get("do_repo_deprecation_check", False):
                LOG.info("Checking validity of repository metadata '{0}'".format(repo))
                # Check if repo exists in Pyxis
                try:
                    metadata = pyxis_get_repo_metadata(repo, target_settings)
                    # Check if repo is not deprecated
                    if "Deprecated" in metadata.get("release_categories", []):
                        raise InvalidRepository("Repository {0} is deprecated".format(repo))
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 404:
                        LOG.warning(
                            "Metadata of repository '{0}' don't exist in Pyxis".format(repo)
                        )
                    else:
                        raise

            # if we're pushing to prod target, check if repo exists on stage as well
            if "propagated_from" in target_settings:
                internal_repo = get_internal_container_repo_name(repo)
                full_repo = repo_schema.format(namespace=stage_namespace, repo=internal_repo)
                try:
                    stage_quay_client.get_repository_tags(full_repo)
                except requests.exceptions.HTTPError as e:
                    # strangely, if repo doesn't exist, 401 is returned if a robot account is used
                    if e.response.status_code == 404 or e.response.status_code == 401:
                        raise InvalidRepository(
                            "Repository {0} doesn't exist on stage".format(repo)
                        )
                    else:
                        raise

    @log_step("Generate backup mapping")
    def generate_backup_mapping(
        self, push_items: List[Any], all_arches: bool = False
    ) -> Tuple[Dict[ImageData, Tuple[str, str]], List[ImageData]]:
        """
        Create resources which will be used for rollback if something goes wrong during the push.

        Specifically, create two resources: 'backup_tags' and 'rollback_tags'.
        - 'backup_tags' is a mapping of ImageData->manifest, and consists of images which will
        be overwritten. During rollback, tag is made to re-reference the old manifest.
        - 'rollback_tags' is a list of ImageData which don't yet exist. During rollback, they
        will be removed to preserve pre-push state.
        If all_arches is set to true, return all arches for v2s2 and v2s1 manifests

        ImageData is a namedtuple used to assign and access parts of an image in a formatted way.

        Args:
            push_items ([ContainerPushItem]):
                Container push items.
            all_arches: bool
                If set to True include all manifests in results. If False only amd64 are included

        Returns (({ImageData: Tuple[str,str]}, [ImageData])):
            Tuple of backup_tags and rollback_tags
        """
        backup_tags = {}
        rollback_tags = []
        internal_item_processor = item_processor_for_internal_data(
            self.dest_quay_client,
            self.target_settings["quay_host"].rstrip("/"),
            self.dest_registries,
            self.target_settings.get("retry_sleep_time", 5),
            self.target_settings["quay_namespace"],
        )
        external_item_processor = item_processor_for_external_data(
            self.dest_quay_client,
            self.dest_registries,
            self.target_settings.get("retry_sleep_time", 5),
        )
        existing_manifests_for_items = run_in_parallel(
            internal_item_processor.generate_existing_manifests_map,
            [FData(args=[item]) for item in push_items],
            threads=self.target_settings.get("quay_parallelism", 10),
        )

        for item, existing_manifests in zip(push_items, existing_manifests_for_items.values()):
            destination_tags = external_item_processor.generate_repo_dest_tag_map(item)

            for registry, repos in existing_manifests.items():
                for e_repo, _ in repos.items():
                    full_repo = internal_item_processor.reference_processor.replace_repo(e_repo)
                    for d_tag in destination_tags[list(destination_tags.keys())[0]][e_repo]:
                        if (
                            d_tag in existing_manifests[registry][e_repo]
                            and existing_manifests[registry][e_repo][d_tag]
                        ):
                            man_arch_digs = existing_manifests[registry][e_repo][d_tag]
                            if not all_arches:
                                arch_mads = [
                                    m
                                    for m in cast(List[ManifestArchDigest], man_arch_digs)
                                    if m.arch == "amd64"
                                ]
                            else:
                                arch_mads = cast(List[ManifestArchDigest], man_arch_digs)
                            v2list_mads: List[Optional[ManifestArchDigest]] = cast(
                                List[Optional[ManifestArchDigest]],
                                [
                                    m
                                    for m in cast(List[ManifestArchDigest], man_arch_digs)
                                    if m.type_ == QuayClient.MANIFEST_LIST_TYPE
                                ]
                                or [None],
                            )
                            v2s1_mads: List[Optional[ManifestArchDigest]] = cast(
                                List[Optional[ManifestArchDigest]],
                                [m for m in arch_mads if m.type_ == QuayClient.MANIFEST_V2S1_TYPE]
                                or [None],
                            )
                            v2s2_mads: List[Optional[ManifestArchDigest]] = cast(
                                List[Optional[ManifestArchDigest]],
                                [m for m in arch_mads if m.type_ == QuayClient.MANIFEST_V2S2_TYPE]
                                or [None],
                            )
                            for mads in (v2s1_mads, v2s2_mads, v2list_mads):
                                for mad in mads:
                                    if not mad:
                                        continue
                                    image_data = PushDocker.ImageData(
                                        full_repo,
                                        d_tag,
                                        (
                                            mad.digest
                                            if mad.type_ == QuayClient.MANIFEST_LIST_TYPE
                                            else ""
                                        ),
                                        (
                                            mad.digest
                                            if mad.type_ == QuayClient.MANIFEST_V2S2_TYPE
                                            else ""
                                        ),
                                        (
                                            mad.digest
                                            if mad.type_ == QuayClient.MANIFEST_V2S1_TYPE
                                            else ""
                                        ),
                                    )
                                    backup_tags[image_data] = (
                                        json.loads(mad.manifest),
                                        mad.arch,
                                    )
                        else:
                            rollback_tags.append(
                                PushDocker.ImageData(full_repo, d_tag, None, None, None)
                            )
        rollback_tags = sorted(list(set(rollback_tags)))
        return (backup_tags, rollback_tags)

    @log_step("Perform rollback")
    def rollback(self, backup_tags: Dict[ImageData, str], rollback_tags: List[ImageData]) -> None:
        """
        Perform a rollback.

        Args:
            backup_tags ({ImageData: str}):
                Dictionary mapping of ImageData and a manifest before it was overwritten.
            rollback_tags ([ImageData]):
                List of newly added ImageData.
        """
        # restore overwritten tags to their original values
        schema = "{host}/{repo}:{tag}"
        LOG.info("Restoring tags to their original values")
        for image_data, manifest in sorted(backup_tags.items()):
            image_ref = schema.format(host=self.quay_host, repo=image_data.repo, tag=image_data.tag)
            LOG.info("Restoring tag '{0}'".format(image_ref))
            self.dest_quay_client.upload_manifest(manifest, image_ref)

        # delete tags that didn't previously exist
        LOG.info("Removing newly introduced tags")
        for image_data in rollback_tags:
            image_ref = schema.format(host=self.quay_host, repo=image_data.repo, tag=image_data.tag)
            LOG.info("Removing tag '{0}'".format(image_ref))
            try:
                self.dest_quay_api_client.delete_tag(image_data.repo, image_data.tag)
            except requests.exceptions.HTTPError as e:
                # if error occurred before tag was copied, it may not exist
                # deleting a non-existent tag shouldn't be an error
                if e.response.status_code != 404 and e.response.status_code != 401:
                    raise

    def get_outdated_manifests(
        self, backup_tags: Dict[ImageData, str]
    ) -> List[Tuple[str, str, str]]:
        """Return list of existing manifests which are being replaced with new ones.

        Args:
            backup_tags (dict({ImageData: str}): backup tags generated with generate_backup_mapping.
        Returns:
            List of tuples containing digest, tag, repo identifying manifests
        """
        outdated_signatures = []
        for image_data, manifest in backup_tags.items():
            ext_repo = get_external_container_repo_name(image_data.repo.split("/")[1])
            if image_data.v2s2_digest:
                outdated_signatures.append((image_data.v2s2_digest, image_data.tag, ext_repo))
            if image_data.v2s1_digest:
                outdated_signatures.append((image_data.v2s1_digest, image_data.tag, ext_repo))
        return outdated_signatures

    def fetch_missing_push_items_digests(
        self, push_items: List[Any]
    ) -> Dict[str, Dict[str, Dict[str, Dict[str, Tuple[str, Any]]]]]:
        """Fetch digests for media types which weren't originally pushed.

        In order to be able to sign v2s1 for images which were pushed as
        v2s2 or to sign v2s2 for images which were pushed as v2s1
        fetch digests of those missing media types from quay and
        set it to item metadata into 'new_digests' mapping.

        Args:
            push_items(list): List of push items.
            target_settings(dict): Target settings.
        """
        item_processor = item_processor_for_internal_data(
            self.dest_quay_client,
            self.target_settings["quay_host"].rstrip("/"),
            self.dest_registries,
            self.target_settings.get("retry_sleep_time", 5),
            self.target_settings["quay_namespace"],
        )

        new_digests: Dict[str, Dict[str, Dict[str, Dict[str, Tuple[str, Any]]]]] = {}
        for item in push_items:
            missing_media_types = set(
                [QuayClient.MANIFEST_V2S2_TYPE, QuayClient.MANIFEST_V2S1_TYPE]
            ) - set(item.metadata["build"]["extra"]["image"]["media_types"])
            # Always add v2s1 due to possible digest change
            missing_media_types.add(QuayClient.MANIFEST_V2S1_TYPE)
            existing_manifests = item_processor.generate_existing_manifests_map(
                item, only_media_types=list(missing_media_types)
            )
            for reference, repos in existing_manifests.items():
                new_digests.setdefault(reference, {})
                for repo, tags in repos.items():
                    new_digests.setdefault(reference, {}).setdefault(repo, {})
                    for tag, man_arch_digs in tags.items():
                        if not man_arch_digs:
                            continue
                        new_digests[reference][repo].setdefault(tag, {})
                        for mad in man_arch_digs:
                            new_digests[reference][repo][tag][mad.type_] = (
                                mad.digest,
                                item.claims_signing_key,
                            )
        return new_digests

    def sign_new_manifests(self, docker_push_items: List[Any]) -> List[Tuple[str, str, Any]]:
        """Sign newly pushed images with signers enabled in target settings.

        Args:
            docker_push_items(List[PushItem]): list of docker push items.
        Returns:
            List of tuple (reference, digest, key) representing currently signed images.
        """
        current_signatures = []
        to_sign_new_entries = self.fetch_missing_push_items_digests(docker_push_items)
        to_sign_entries = []
        to_sign_entries_internal = []
        for internal_reg, repo_tags in to_sign_new_entries.items():
            for repo, tag_digests in repo_tags.items():
                for tag, digests in tag_digests.items():
                    for type_, digest_key in digests.items():
                        digest, key = digest_key
                        internal_reference = (
                            f"{internal_reg}/"
                            + self.target_settings["quay_namespace"]
                            + "/"
                            + get_internal_container_repo_name(repo)
                            + ":"
                            + tag
                        )
                        for registry in self.dest_registries:
                            pub_reference = f"{registry}/{repo}:{tag}"
                            # add entries in internal format for cosign
                            to_sign_entries_internal.append(
                                SignEntry(
                                    reference=internal_reference,
                                    pub_reference=pub_reference,
                                    repo=repo,
                                    digest=digest,
                                    signing_key=key,
                                    arch="amd64",
                                )
                            )
                            reference = f"{registry}/{repo}:{tag}"
                            to_sign_entries.append(
                                SignEntry(
                                    reference=reference,
                                    pub_reference="",
                                    repo=repo,
                                    digest=digest,
                                    signing_key=key,
                                    arch="amd64",
                                )
                            )
                            current_signatures.append((reference, digest, key))

        for signer in self.target_settings["signing"]:
            if signer["enabled"]:
                signercls = SIGNER_BY_LABEL[signer["label"]]
                signer = signercls(config_file=signer["config_file"], settings=self.target_settings)
                if signercls.pre_push is True:
                    signer.sign_containers(to_sign_entries, self.task_id)
                else:
                    signer.sign_containers(to_sign_entries_internal, self.task_id)

        return current_signatures

    def run(self) -> None:
        """
        Perform the full push-docker workflow.

        The workflow can be summarized as:
        - Filter out push items to only include container image items
        - Check if the destination repos may be pushed to (using Pyxis)
        - Generate backup mapping that will be used for rollback if something goes wrong.
        - Sign container images using RADAS and upload signatures to Pyxis
        - Push container images to their destinations
        - Generate and push container security manifests for pushed images
        - Fetch digests for missing media types of pushed items
        - Sign manifests for missing media types (has to be done after pushing)
        - Filter out push items to only include operator image items
        - Add operator bundles to index images by using IIB
        - Sign index images using RADAS and upload signatures to Pyxis
        - Push the index images to Quay
        - Remove outdated container signatures
        - (in case of failure) Rollback destination repos to the pre-push state
        """
        # TODO: Do we need to manage push item state?
        # Filter out non-docker push items
        docker_push_items = self.get_docker_push_items()
        # Get operator push items (done early so that possible issues are detected)
        operator_push_items = self.get_operator_push_items()
        # Check if we may push to destination repos
        self.check_repos_validity(docker_push_items, self.hub, self.target_settings)
        # Generate resources for rollback in case there are errors during the push
        backup_tags, rollback_tags = self.generate_backup_mapping(
            docker_push_items, all_arches=True
        )
        # Restore manifest list if it exists, otherwise restore v2s2 or v2s1 manifest
        backup_tags_restore = {}
        repo_tag_group: dict[Tuple[str, str], dict[str, PushDocker.ImageData]] = {}
        for image_data in backup_tags.keys():
            repo_tag_group.setdefault((image_data.repo, image_data.tag), {})
            for t in ["v2list", "v2s2", "v2s1"]:
                if getattr(image_data, t + "_digest"):
                    repo_tag_group[(image_data.repo, image_data.tag)][t] = image_data
                    break
        for images in repo_tag_group.values():
            for t in ["v2list", "v2s2", "v2s1"]:
                if t in images.keys():
                    backup_tags_restore[images[t]] = backup_tags[images[t]][0]
                    break
        all_backup_tags = {k: bt[0] for k, bt in backup_tags.items()}

        existing_index_images = []
        iib_results = None
        successful_iib_results = dict()
        index_stamp = timestamp()
        item_processor = item_processor_for_external_data(
            self.src_quay_client,
            self.dest_registries,
            self.target_settings.get("retry_sleep_time", 5),
        )
        to_sign_entries = []
        current_signatures = []
        to_sign_map = run_in_parallel(
            item_processor.generate_to_sign,
            [FData(args=(item,), kwargs={}) for item in docker_push_items],
        )
        for _to_sign_entries in to_sign_map.values():
            to_sign_entries.extend(_to_sign_entries)

        for sign_entry in to_sign_entries:
            current_signatures.append(
                (sign_entry.reference, sign_entry.digest, sign_entry.signing_key)
            )
        # Sign containers with signers that doesn't need have pushed containers
        # in destination registry
        set_aws_kms_environment_variables(self.target_settings, "cosign_signer")
        for signer in self.target_settings["signing"]:
            if signer["enabled"] and SIGNER_BY_LABEL[signer["label"]].pre_push:
                signercls = SIGNER_BY_LABEL[signer["label"]]
                signer = signercls(config_file=signer["config_file"], settings=self.target_settings)
                signer.sign_containers(to_sign_entries, self.task_id)

        # Push container images
        container_pusher = ContainerImagePusher(docker_push_items, self.target_settings)
        container_pusher.push_container_images()

        # Sign containers with signers which requires pushed containers in destination registry
        to_sign_entries = []
        item_processor = item_processor_for_internal_data(
            self.src_quay_client,
            self.target_settings["quay_host"].rstrip("/"),
            self.dest_registries,
            self.target_settings.get("retry_sleep_time", 5),
            self.target_settings["quay_namespace"],
        )
        to_sign_map = run_in_parallel(
            item_processor.generate_to_sign,
            [
                FData(args=(item,), kwargs={"include_manifest_lists": True})
                for item in docker_push_items
            ],
        )
        for _to_sign_entries in to_sign_map.values():
            to_sign_entries.extend(_to_sign_entries)

        for signer in self.target_settings["signing"]:
            if signer["enabled"] and not SIGNER_BY_LABEL[signer["label"]].pre_push:
                signercls = SIGNER_BY_LABEL[signer["label"]]
                signer = signercls(config_file=signer["config_file"], settings=self.target_settings)
                signer.sign_containers(to_sign_entries, self.task_id)

        self.sign_new_manifests(docker_push_items)

        if self.target_settings.get("push_security_manifests_enabled", False):
            # Generate and push security manifests (if enabled in target settings)
            set_aws_kms_environment_variables(self.target_settings, "security_manifest_signer")
            sec_manifest_pusher = SecurityManifestPusher(docker_push_items, self.target_settings)
            sec_manifest_pusher.push_security_manifests()

        failed = False

        if operator_push_items:
            # Build index images
            operator_pusher = OperatorPusher(
                operator_push_items, self.task_id, self.target_settings
            )
            existing_index_images = operator_pusher.get_existing_index_images(
                self.dest_operator_quay_client
            )
            if operator_pusher.ensure_bundles_present():
                bundles_presence_check_failed = False
                iib_results = operator_pusher.build_index_images()
            else:
                bundles_presence_check_failed = True
                iib_results = {}

            # Sign operator images
            failed_items = [item for item in operator_push_items if item.errors]
            successful_iib_results = dict(
                [(key, val) for key, val in iib_results.items() if val["iib_result"]]
            )

            image_schema = "{host}/{namespace}/{repo}:{tag}"

            for version, iib_details in sorted(successful_iib_results.items()):
                iib_result = iib_details["iib_result"]
                _, iib_namespace, iib_intermediate_repo = parse_index_image(iib_result)
                permanent_index_image = image_schema.format(
                    host=self.target_settings.get("quay_host", "quay.io").rstrip("/"),
                    namespace=iib_namespace,
                    repo=iib_intermediate_repo,
                    tag=iib_result.build_tags[0],
                )
                timestamp_tags = [f"{tag}-{index_stamp}" for tag in iib_details["destination_tags"]]
                current_signatures.extend(
                    _sign_index_image(
                        permanent_index_image,
                        iib_details["destination_tags"] + timestamp_tags,
                        iib_details["signing_keys"],
                        self.task_id,
                        self.target_settings,
                        pre_push=True,
                    )
                )

            # If there are any failed items, skip pushing
            if not failed_items:
                # Push index images to Quay
                operator_pusher.push_index_images(successful_iib_results, index_stamp)

            for version, iib_details in sorted(successful_iib_results.items()):
                iib_result = iib_details["iib_result"]
                _, iib_namespace, iib_intermediate_repo = parse_index_image(iib_result)
                permanent_index_image = image_schema.format(
                    host=self.target_settings.get("quay_host", "quay.io").rstrip("/"),
                    namespace=iib_namespace,
                    repo=iib_intermediate_repo,
                    tag=iib_result.build_tags[0],
                )
                timestamp_tags = [f"{tag}-{index_stamp}" for tag in iib_details["destination_tags"]]
                current_signatures.extend(
                    _sign_index_image(
                        permanent_index_image,
                        iib_details["destination_tags"] + timestamp_tags,
                        iib_details["signing_keys"],
                        self.task_id,
                        self.target_settings,
                        pre_push=False,
                    )
                )

            # Rollback only when all index image builds fails or there are failed items
            # Empty iib_results is not an error and shouldn't fail the push. The only exception is
            # when bundles presence check failed.
            if (
                (iib_results or bundles_presence_check_failed)
                and (not any([x["iib_result"] for x in iib_results.values()]))
                or failed_items
            ):
                if failed_items:
                    LOG.error("There are failed push items. Cannot continue, running rollback.")
                else:
                    LOG.error("Push of all index images failed, running rollback.")
                self.rollback(backup_tags_restore, rollback_tags)
                sys.exit(1)
            if successful_iib_results != iib_results:
                LOG.error("Push of some index images failed")
                failed = True

        # Remove old signatures
        # run generate backup mapping again to fetch new digests of pushed containers
        backup_tags2, _ = self.generate_backup_mapping(docker_push_items, all_arches=True)
        # if new backup tag has differnet digest, it means it was overwritten during the push
        # and old signature should be removed. If the digest is the same it means, same item
        # was just repushed
        outdated_tags = {}
        backup_tags2_shared = {}

        # Backup tags can contain new tags which were orignally rollback_tags
        # limit the comparision for outdated manifests to original backup_tags only
        for bt2 in backup_tags2.items():
            if (bt2[0].tag, bt2[0].repo) in [(x.tag, x.repo) for x in all_backup_tags.keys()]:
                backup_tags2_shared[bt2[0]] = bt2[1]

        for bt1, bt2 in zip(
            sorted(
                backup_tags.items(),
                key=lambda x: (
                    x[0].tag,
                    x[0].repo,
                    x[0].v2list_digest or "",
                    x[0].v2s2_digest or "",
                    x[0].v2s1_digest or "",
                ),
            ),
            sorted(
                backup_tags2_shared.items(),
                key=lambda x: (
                    x[0].tag,
                    x[0].repo,
                    x[0].v2list_digest or "",
                    x[0].v2s2_digest or "",
                    x[0].v2s1_digest or "",
                ),
            ),
        ):
            list_test = (
                bt1[0].v2list_digest
                and bt2[0].v2list_digest
                and bt1[0].v2list_digest != bt2[0].v2list_digest
            )
            s2_test = (
                bt1[0].v2s2_digest
                and bt2[0].v2s2_digest
                and bt1[0].v2s2_digest != bt2[0].v2s2_digest
            )
            s1_test = (
                bt1[0].v2s1_digest
                and bt2[0].v2s1_digest
                and bt1[0].v2s1_digest != bt2[0].v2s1_digest
            )
            outdated = False
            if list_test:
                d1 = bt1[0].v2list_digest
                d2 = bt2[0].v2list_digest
                name = "manifest list"
                outdated = True
            elif s2_test:
                d1 = bt1[0].v2s2_digest
                d2 = bt2[0].v2s2_digest
                name = "v2s2"
                outdated = True
            elif s1_test:
                d1 = bt1[0].v2s1_digest  # noqa: F841
                d2 = bt2[0].v2s1_digest  # noqa: F841
                name = "v2s1"  # noqa: F841
                outdated = True
            if outdated:
                LOG.debug(
                    f"Marking manifest {bt1[0].tag} as outdated, {name} "
                    f"digests don't match {d1} != {d2}"
                )
                outdated_tags[bt1[0]] = bt1[1]

        outdated_manifests = self.get_outdated_manifests(outdated_tags)
        outdated_manifests.extend(existing_index_images)

        for signer in self.target_settings["signing"]:
            if signer["enabled"] and outdated_manifests:
                signercls = SIGNER_BY_LABEL[signer["label"]]
                signer = signercls(config_file=signer["config_file"], settings=self.target_settings)
                signer.remove_signatures(outdated_manifests, _exclude=current_signatures)

        if failed:
            # Why???
            sys.exit(1)


def mod_entry_point(
    push_items: List[Any], hub: Any, task_id: str, target_name: str, target_settings: Dict[str, Any]
) -> None:
    """Entry point for use in another python code."""
    push = PushDocker(push_items, hub, task_id, target_name, target_settings)
    push.run()
