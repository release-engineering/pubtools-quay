from collections import namedtuple
import logging

import requests

from .exceptions import BadPushItem, InvalidTargetSettings, InvalidRepository
from .utils.misc import run_entrypoint, get_internal_container_repo_name, log_step
from .quay_api_client import QuayApiClient
from .quay_client import QuayClient
from .container_image_pusher import ContainerImagePusher
from .signature_handler import ContainerSignatureHandler, OperatorSignatureHandler
from .signature_remover import SignatureRemover
from .operator_pusher import OperatorPusher
from .utils.misc import get_external_container_repo_name

# TODO: do we want this, or should I remove it?
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG = logging.getLogger("pubtools.quay")


class PushDocker:
    """Handle full Docker push workflow."""

    ImageData = namedtuple("ImageData", ["repo", "tag", "digest"])

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
        self._dest_quay_api_client = None

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
    def dest_quay_api_client(self):
        """Create and access QuayApiClient for dest image."""
        if self._dest_quay_api_client is None:
            self._dest_quay_api_client = QuayApiClient(
                self.target_settings["dest_quay_api_token"], self.quay_host
            )
        return self._dest_quay_api_client

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
        if (
            "iib_overwrite_from_index_token" in self.target_settings
            and "iib_overwrite_from_index" not in self.target_settings
        ) or (
            "iib_overwrite_from_index_token" not in self.target_settings
            and "iib_overwrite_from_index" in self.target_settings
        ):
            msg = (
                "Either both or neither of 'iib_overwrite_from_index' and "
                "'iib_overwrite_from_index_token' should be specified in target settings."
            )
            LOG.error(msg)
            raise InvalidTargetSettings(msg)

    @log_step("Get container push items")
    def get_docker_push_items(self):
        """
        Filter push items to only include docker ones.

        Also, Check the validity of these items and raise an exception in case of incorrect data.

        Returns ([ContainerPushItem]):
            Docker push items.
        """
        docker_push_items = []
        for item in self.push_items:
            if item.file_type != "docker":
                LOG.warning("Push item {0} doesn't have 'docker' type, skipping.".format(item))
                continue
            if item.errors:
                raise BadPushItem("Push item {0} contains errors: {1}".format(item, item.errors))
            if not item.metadata.get("pull_data"):
                raise BadPushItem("Push item {0} doesn't contain pull data.".format(item))
            LOG.info("Docker push item found: {0}".format(item))
            docker_push_items.append(item)

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
    def get_repo_metadata(cls, repo, target_settings):
        """
        Invoke the 'get-repo-metadata' entrypoint from pubtools-pyxis.

        Args:
            repo (str):
                Repository to get the metadata of.
            target_settings (dict):
                Settings used for setting the values of the entrypoint parameters.

        Returns (dict):
            Parsed response from Pyxis.
        """
        args = ["--pyxis-server", target_settings["pyxis_server"]]
        args += ["--pyxis-krb-principal", target_settings["iib_krb_principal"]]
        if "iib_krb_ktfile" in target_settings:
            args += ["--pyxis-krb-ktfile", target_settings["iib_krb_ktfile"]]
        args += ["--repo-name", repo]

        env_vars = {}
        metadata = run_entrypoint(
            ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-repo-metadata"),
            "pubtools-pyxis-get-repo-metadata",
            args,
            env_vars,
        )
        return metadata

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
            LOG.info("Checking validity of Comet repository '{0}'".format(repo))
            # Check if repo exists in Comet
            try:
                metadata = cls.get_repo_metadata(repo, target_settings)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    raise InvalidRepository("Repository {0} doesn't exist in Comet".format(repo))
                else:
                    raise

            # Check if repo is not deprecated
            # TODO: check with Comet team if this is a reliable way of checking
            if "Deprecated" in metadata["release_categories"]:
                raise InvalidRepository("Repository {0} is deprecated".format(repo))

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
        repo_schema = "{namespace}/{repo}"
        image_schema = "{host}/{repo}@{digest}"
        image_schema_tag = "{host}/{repo}:{tag}"
        namespace = self.target_settings["quay_namespace"]

        for item in push_items:
            for repo, tags in sorted(item.metadata["tags"].items()):
                internal_repo = get_internal_container_repo_name(repo)
                full_repo = repo_schema.format(namespace=namespace, repo=internal_repo)
                LOG.info("Generating backup mapping for repository '{0}'".format(repo))
                # try to get repo data
                try:
                    repo_tags = self.dest_quay_client.get_repository_tags(full_repo)
                except requests.exceptions.HTTPError as e:
                    # When robot account is used, 401 is returned instead of 404
                    if e.response.status_code == 404 or e.response.status_code == 401:
                        repo_tags = None
                    else:
                        raise

                for tag in tags:
                    # repo doesn't exist, add to rollback tags
                    if not repo_tags:
                        # for rollback tags digest is not known
                        rollback_tags.append(PushDocker.ImageData(full_repo, tag, None))
                        continue
                    # tag exists in the repo, add to backup tags
                    if tag in repo_tags.get("tags", {}):
                        image_tag = image_schema_tag.format(
                            host=self.quay_host, repo=full_repo, tag=tag
                        )
                        digest = self.dest_quay_client.get_manifest_digest(image_tag)
                        # for backup tags store also digest
                        image_data = PushDocker.ImageData(full_repo, tag, digest)
                        image = image_schema.format(
                            host=self.quay_host,
                            repo=full_repo,
                            digest=digest,
                        )
                        manifest = self.dest_quay_client.get_manifest(image)
                        backup_tags[image_data] = manifest
                    # tag doesn't exist in the repo, add to rollback tags
                    else:
                        # for rollback tags digest is not known
                        rollback_tags.append(PushDocker.ImageData(full_repo, tag, None))

        # it's possible that rollback tags will contain duplicate entries
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

    def remove_old_signatures(
        self,
        push_items,
        operator_push_items,
        existing_index_images,
        iib_results,
        backup_tags,
        container_signature_handler,
        operator_signature_handler,
        signature_remover,
    ):
        """
        Remove signatures of containers for tags which were overwritten in the current push.

        Method fetches all existing signatures for digests in backup tags. Only signatures with
        repo, tag pairs  matching to backup tags are then processes forward as also signatures
        for different repos could be returned. From those, only signature not
        matching signatures which were just created for current push are removed.
        Mechanism is the same for index images signatures, except those are not compared to
        any backup tags.

        Args:
            push_items ([_PushItem]):
                List of container push items.
            operator_push_items ([_PushItem]):
                List of operator push items.
            existing_index_images: ([(digest, version)]):
                List of tuple of digest + version(tag) of index images which existed
                before new index image was pushed in the current task
            iib_results (({str:dict})):
                Dictionary containing IIB results and signing keys for all OPM versions.
            backup_tags ({ImageData: str}):
                Dictionary of ImageData (repo, tag, digest) -> manifest
                holding containers which were overwritten in the currently running task
            container_signature_handler (ContainerSignatureHandler):
                ContanerSignatureHandler instance.
            operator_signature_handler (OperatorSignatureHandler):
                ContanerSignatureHandler instance.
            operator_signature_handler (SignatureRemover):
                SignatureRemover instance.
        """
        claim_messages = []
        for item in push_items:
            claim_messages += container_signature_handler.construct_item_claim_messages(item)
        new_signatures = [(m["manifest_digest"], m["docker_reference"]) for m in claim_messages]
        outdated_signatures = []

        for image_data, manifest in backup_tags.items():
            ext_repo = get_external_container_repo_name(image_data.repo.split("/")[1])
            if "manifests" in manifest:
                for arch_manifest in manifest["manifests"]:
                    outdated_signatures.append((arch_manifest["digest"], image_data.tag, ext_repo))
            else:
                outdated_signatures.append((image_data.digest, image_data.tag, ext_repo))

        signatures_to_remove = []
        for esig in container_signature_handler.get_signatures_from_pyxis(
            [sig[0] for sig in outdated_signatures]
        ):
            if (
                esig["manifest_digest"],
                esig["reference"].split(":")[-1],
                esig["repository"],
            ) in outdated_signatures and (
                esig["manifest_digest"],
                esig["reference"],
            ) not in new_signatures:
                signatures_to_remove.append(esig["_id"])

        if signatures_to_remove:
            signature_remover.remove_signatures_from_pyxis(
                signatures_to_remove,
                self.target_settings["pyxis_server"],
                self.target_settings["iib_krb_principal"],
                self.target_settings["iib_krb_ktfile"],
            )

        signatures_to_remove = []
        ii_claim_messages = []
        if existing_index_images:
            for version, iib_details in sorted(iib_results.items()):
                iib_result = iib_details["iib_result"]
                signing_keys = iib_details["signing_keys"]
                image_schema = "{host}/{namespace}/{repo}@{digest}"
                iib_namespace = iib_result.index_image_resolved.split("/")[1]
                image_digest = iib_result.index_image_resolved.split("@")[1]
                intermediate_index_image = image_schema.format(
                    host=self.target_settings.get("quay_host", "quay.io").rstrip("/"),
                    namespace=iib_namespace,
                    repo="iib",
                    digest=image_digest,
                )
                ii_claim_messages += (
                    operator_signature_handler.construct_index_image_claim_messages(
                        intermediate_index_image, version, signing_keys
                    )
                )
            new_operator_signatures = [
                (m["manifest_digest"], m["docker_reference"]) for m in ii_claim_messages
            ]

            for esig in container_signature_handler.get_signatures_from_pyxis(
                [digest_version[0] for digest_version in existing_index_images]
            ):
                if (esig["manifest_digest"], esig["reference"]) not in new_operator_signatures and (
                    esig["manifest_digest"],
                    esig["reference"].split(":")[-1],
                    esig["repository"],
                ) in existing_index_images:
                    signatures_to_remove.append(esig["_id"])
            if signatures_to_remove:
                signature_remover.remove_signatures_from_pyxis(
                    signatures_to_remove,
                    self.target_settings["pyxis_server"],
                    self.target_settings["iib_krb_principal"],
                    self.target_settings["iib_krb_ktfile"],
                )

    def run(self):
        """
        Perform the full push-docker workflow.

        The workflow can be summarized as:
        - Filter out push items to only include container image items
        - Check if the destination repos may be pushed to (using Pyxis)
        - Generate backup mapping that will be used for rollback if something goes wrong.
        - Sign container images using RADAS and upload signatures to Pyxis
        - Push container images to their destinations
        - Filter out push items to only include operator image items
        - Add operator bundles to index images by using IIB
        - Sign index images using RADAS and upload signatures to Pyxis
        - Push the index images to Quay
        - Remove outdated container signatures
        - (in case of failure) Rollback destination repos to the pre-push state

        Returns ([str]):
            List of container image repos (for UD cache flush done by pub)
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

        try:
            # Sign container images
            container_signature_handler = ContainerSignatureHandler(
                self.hub, self.task_id, self.target_settings, self.target_name
            )
            operator_signature_handler = OperatorSignatureHandler(
                self.hub, self.task_id, self.target_settings, self.target_name
            )
            sig_remover = SignatureRemover()
            sig_remover.set_quay_client(self.dest_quay_client)

            container_signature_handler.sign_container_images(docker_push_items)
            # Push container images
            container_pusher = ContainerImagePusher(docker_push_items, self.target_settings)
            container_pusher.push_container_images()

            if operator_push_items:
                # Build index images
                operator_pusher = OperatorPusher(operator_push_items, self.target_settings)
                existing_index_images = operator_pusher.get_existing_index_images(
                    self.dest_quay_client
                )
                iib_results = operator_pusher.build_index_images()
                # Sign operator images
                operator_signature_handler.sign_operator_images(iib_results)
                # Push index images to Quay
                operator_pusher.push_index_images(iib_results)
        except (Exception, SystemExit):
            LOG.error("An exception has occurred during the push, starting rollback")
            self.rollback(backup_tags, rollback_tags)
            raise
        else:
            # Remove old signatures
            self.remove_old_signatures(
                docker_push_items,
                operator_push_items,
                existing_index_images,
                iib_results,
                backup_tags,
                container_signature_handler,
                operator_signature_handler,
                sig_remover,
            )

        # Return repos for UD cache flush
        repos = []
        for item in docker_push_items:
            repos += item.repos.keys()

        return sorted(list(set(repos)))


def mod_entry_point(push_items, hub, task_id, target_name, target_settings):
    """Entry point for use in another python code."""
    push = PushDocker(push_items, hub, task_id, target_name, target_settings)
    return push.run()
