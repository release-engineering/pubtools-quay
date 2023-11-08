from collections import namedtuple
import logging
import sys
import json

import requests

from .exceptions import BadPushItem, InvalidTargetSettings, InvalidRepository
from .utils.misc import get_internal_container_repo_name, log_step
from .quay_api_client import QuayApiClient
from .quay_client import QuayClient
from .container_image_pusher import ContainerImagePusher
from .security_manifest_pusher import SecurityManifestPusher

from .operator_pusher import OperatorPusher
from .item_processor import (
    item_processor_for_external_data,
    item_processor_for_internal_data,
    SignEntry,
)
from .utils.misc import parse_index_image
from .signer_wrapper import SIGNER_BY_LABEL

from .utils.misc import (
    get_external_container_repo_name,
    timestamp,
    pyxis_get_repo_metadata,
    set_aws_kms_environment_variables,
)

# TODO: do we want this, or should I remove it?
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG = logging.getLogger("pubtools.quay")


class PushDocker:
    """Handle full Docker push workflow."""

    ImageData = namedtuple(
        "ImageData", ["repo", "tag", "v2list_digest", "v2s2_digest", "v2s1_digest"]
    )

    def __init__(self, push_items, hub, task_id, target_name, target_settings):
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

        self._dest_quay_client = None
        self._dest_operator_quay_client = None
        self._dest_quay_api_client = None
        self._index_image_quay_client = None
        self.dest_registries = self.target_settings["docker_settings"]["docker_reference_registry"]
        self.dest_registries = (
            self.dest_registries
            if isinstance(self.dest_registries, list)
            else [self.dest_registries]
        )

    @property
    def dest_quay_client(self):
        """Create and access QuayClient for dest image."""
        if self._dest_quay_client is None:
            self._dest_quay_client = QuayClient(
                self.target_settings["dest_quay_user"],
                self.target_settings["dest_quay_password"],
                self.quay_host,
            )
        return self._dest_quay_client

    @property
    def dest_operator_quay_client(self):
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
    def dest_quay_api_client(self):
        """Create and access QuayApiClient for dest image."""
        if self._dest_quay_api_client is None:
            self._dest_quay_api_client = QuayApiClient(
                self.target_settings["dest_quay_api_token"], self.quay_host
            )
        return self._dest_quay_api_client

    @property
    def index_image_quay_client(self):
        """Create and access QuayClient for dest image."""
        if self._index_image_quay_client is None:
            index_image_credential = self.target_settings["iib_overwrite_from_index_token"].split(
                ":"
            )
            self._index_image_quay_client = QuayClient(
                index_image_credential[0],
                index_image_credential[1],
                self.quay_host,
            )
        return self._index_image_quay_client

    def verify_target_settings(self):
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
    def get_docker_push_items(self):
        """
        Filter push items to only include docker ones.

        Also, Check the validity of these items and raise an exception in case of incorrect data.

        For items having the same pull_url, only one of them is returned to avoid duplication.

        Returns ([ContainerPushItem]):
            Docker push items.
        """
        docker_push_items = []
        url_items = {}
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
    def get_operator_push_items(self):
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
    def check_repos_validity(cls, push_items, hub, target_settings):
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
    def generate_backup_mapping(self, push_items):
        """
        Create resources which will be used for rollback if something goes wrong during the push.

        Specifically, create two resources: 'backup_tags' and 'rollback_tags'.
        - 'backup_tags' is a mapping of ImageData->manifest, and consists of images which will
        be overwritten. During rollback, tag is made to re-reference the old manifest.
        - 'rollback_tags' is a list of ImageData which don't yet exist. During rollback, they
        will be removed to preserve pre-push state.

        ImageData is a namedtuple used to assign and access parts of an image in a formatted way.

        Args:
            push_items ([ContainerPushItem]):
                Container push items.

        Returns (({ImageData: str}, [ImageData])):
            Tuple of backup_tags and rollback_tags
        """
        backup_tags = {}
        rollback_tags = []
        internal_item_processor = item_processor_for_internal_data(
            self.dest_quay_client,
            self.target_settings["quay_host"].rstrip("/"),
            self.target_settings.get("retry_sleep_time", 5),
            self.target_settings["quay_namespace"],
        )
        external_item_processor = item_processor_for_external_data(
            self.dest_quay_client,
            self.dest_registries,
            self.target_settings.get("retry_sleep_time", 5),
        )
        for item in push_items:
            destination_tags = external_item_processor.generate_repo_dest_tag_map(item)
            existing_manifests = internal_item_processor.generate_existing_manifests_map(item)
            for registry, repos in existing_manifests.items():
                for e_repo, e_tags in repos.items():
                    full_repo = internal_item_processor.reference_processor.replace_repo(e_repo)
                    for d_tag in destination_tags[list(destination_tags.keys())[0]][e_repo]:
                        if (
                            d_tag in existing_manifests[registry][e_repo]
                            and existing_manifests[registry][e_repo][d_tag]
                        ):
                            man_arch_digs = existing_manifests[registry][e_repo][d_tag]
                            amd64_mads = [m for m in man_arch_digs if m.arch == "amd64"]
                            v2list_mad = (
                                [
                                    m
                                    for m in man_arch_digs
                                    if m.type_ == QuayClient.MANIFEST_LIST_TYPE
                                ]
                                or [None]
                            )[0]
                            v2s1_mad = (
                                [m for m in amd64_mads if m.type_ == QuayClient.MANIFEST_V2S1_TYPE]
                                or [None]
                            )[0]
                            v2s2_mad = (
                                [m for m in amd64_mads if m.type_ == QuayClient.MANIFEST_V2S2_TYPE]
                                or [None]
                            )[0]
                            mad = v2s2_mad or v2s1_mad or v2list_mad
                            image_data = PushDocker.ImageData(
                                full_repo,
                                d_tag,
                                v2list_mad.digest if v2list_mad else None,
                                v2s2_mad.digest if v2s2_mad else None,
                                v2s1_mad.digest if v2s1_mad else None,
                            )
                            if mad:
                                backup_tags[image_data] = json.loads(mad.manifest)
                        else:
                            rollback_tags.append(
                                PushDocker.ImageData(full_repo, d_tag, None, None, None)
                            )
        rollback_tags = sorted(list(set(rollback_tags)))
        return (backup_tags, rollback_tags)

    @log_step("Perform rollback")
    def rollback(self, backup_tags, rollback_tags):
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

    def get_outdated_manifests(self, backup_tags):
        """Return list of existing manifests which are being replaced with new ones."""
        outdated_signatures = []
        for image_data, manifest in backup_tags.items():
            ext_repo = get_external_container_repo_name(image_data.repo.split("/")[1])
            if image_data.v2s2_digest:
                outdated_signatures.append((image_data.v2s2_digest, image_data.tag, ext_repo))
            if image_data.v2list_digest:
                outdated_signatures.append((image_data.v2list_digest, image_data.tag, ext_repo))
            if image_data.v2s1_digest:
                outdated_signatures.append((image_data.v2s1_digest, image_data.tag, ext_repo))
        return outdated_signatures

    def fetch_missing_push_items_digests(self, push_items, target_settings):
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
            self.target_settings.get("retry_sleep_time", 5),
            self.target_settings["quay_namespace"],
        )

        new_digests = {}
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
                            new_digests[reference][repo][tag][mad.type_] = mad.digest
        return new_digests

    def run(self):
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
        backup_tags, rollback_tags = self.generate_backup_mapping(docker_push_items)
        existing_index_images = []
        iib_results = None
        successful_iib_results = dict()
        index_stamp = timestamp()

        item_processor = item_processor_for_external_data(
            self.dest_quay_client,
            self.dest_registries,
            self.target_settings.get("retry_sleep_time", 5),
        )
        to_sign_entries = []
        current_signatures = []
        for item in docker_push_items:
            to_sign_entries.extend(
                item_processor.generate_to_sign(item, sign_only_arches=["amd64", "x86_64"])
            )
        for sign_entry in to_sign_entries:
            current_signatures.append(
                (sign_entry.reference, sign_entry.digest, sign_entry.signing_key)
            )
        for signer in self.target_settings["signing"]:
            if signer["enabled"]:
                signercls = SIGNER_BY_LABEL[signer["label"]]
                signer = signercls(config_file=signer["config_file"], settings=self.target_settings)
                signer.sign_containers(to_sign_entries, self.task_id)

        # Push container images
        container_pusher = ContainerImagePusher(docker_push_items, self.target_settings)
        container_pusher.push_container_images()

        # fetch missing digests
        to_sign_new_entries = self.fetch_missing_push_items_digests(
            docker_push_items, self.target_settings
        )
        to_sign_entries = []
        for reference, repo_tags in to_sign_new_entries.items():
            for repo, tag_digests in repo_tags.items():
                for tag, digests in tag_digests.items():
                    for type_, digest in digests.items():
                        to_sign_entries.append(
                            SignEntry(
                                reference=reference,
                                repo=repo,
                                digest=digest,
                                signing_key=item.claims_signing_key,
                                arch="amd64",
                            )
                        )
                        current_signatures.append((reference, digest, item.claims_signing_key))

        # sign missing images
        for signer in self.target_settings["signing"]:
            if signer["enabled"]:
                signercls = SIGNER_BY_LABEL[signer["label"]]
                signer = signercls(config_file=signer["config_file"], settings=self.target_settings)
                signer.sign_containers(to_sign_entries, self.task_id)

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
                iib_results = operator_pusher.build_index_images()
            else:
                iib_results = {}

            # Sign operator images
            failed_items = [item for item in operator_push_items if item.errors]
            successful_iib_results = dict(
                [(key, val) for key, val in iib_results.items() if val["iib_result"]]
            )

            image_schema = "{host}/{namespace}/{repo}:{tag}"

            for version, iib_details in sorted(successful_iib_results.items()):
                iib_result = iib_details["iib_result"]
                # Index image used to fetch manifest list. This image will never be overwritten
                _, iib_namespace, iib_intermediate_repo = parse_index_image(iib_result)
                permanent_index_image = image_schema.format(
                    host=self.target_settings.get("quay_host", "quay.io").rstrip("/"),
                    namespace=iib_namespace,
                    repo=iib_intermediate_repo,
                    tag=iib_result.build_tags[0],
                )
                manifest_list = self.index_image_quay_client.get_manifest(
                    permanent_index_image, media_type=QuayClient.MANIFEST_LIST_TYPE
                )
                index_image_digests = [
                    m["digest"]
                    for m in manifest_list["manifests"]
                    if m["platform"]["architecture"] in ("x86_64", "amd64")
                ]
                # Version acts as a tag of the index image
                # use hotfix tag if it exists

                to_sign_entries = []
                iib_repo = self.target_settings["quay_operator_repository"]
                for registry in self.dest_registries:
                    for dest_tag in iib_details["destination_tags"]:
                        for digest in index_image_digests:
                            for key in iib_details["signing_keys"]:
                                reference = f"{registry}/{iib_namespace}/{iib_repo}:{dest_tag}"
                                to_sign_entries.append(
                                    SignEntry(
                                        repo=iib_repo,
                                        reference=reference,
                                        digest=digest,
                                        signing_key=key,
                                        arch="amd64",
                                    )
                                )
                                current_signatures.append((reference, digest, key))

                for signer in self.target_settings["signing"]:
                    if signer["enabled"]:
                        signercls = SIGNER_BY_LABEL[signer["label"]]
                        signer = signercls(
                            config_file=signer["config_file"], settings=self.target_settings
                        )
                        signer.sign_containers(to_sign_entries, self.task_id)

            # If there are any failed items, skip pushing
            if not failed_items:
                # Push index images to Quay
                operator_pusher.push_index_images(successful_iib_results, index_stamp)

            # Rollback only when all index image builds fails or there are failed items
            if not any([x["iib_result"] for x in iib_results.values()]) or failed_items:
                if failed_items:
                    LOG.error("There are failed push items. Cannot continue, running rollback.")
                else:
                    LOG.error("Push of all index images failed, running rollback.")
                self.rollback(backup_tags, rollback_tags)
                sys.exit(1)
            if successful_iib_results != iib_results:
                LOG.error("Push of some index images failed")
                failed = True

        # Remove old signatures
        outdated_manifests = self.get_outdated_manifests(backup_tags)
        outdated_manifests.extend(existing_index_images)

        for signer in self.target_settings["signing"]:
            if signer["enabled"]:
                signercls = SIGNER_BY_LABEL[signer["label"]]
                signer = signercls(config_file=signer["config_file"], settings=self.target_settings)
                signer.remove_signatures(outdated_manifests, _exclude=current_signatures)

        if failed:
            # Why???
            sys.exit(1)


def mod_entry_point(push_items, hub, task_id, target_name, target_settings):
    """Entry point for use in another python code."""
    push = PushDocker(push_items, hub, task_id, target_name, target_settings)
    push.run()
