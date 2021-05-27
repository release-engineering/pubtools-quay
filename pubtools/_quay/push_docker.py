from collections import namedtuple
import logging

import requests

from .exceptions import BadPushItem, InvalidTargetSettings, InvalidRepository
from .utils.misc import run_entrypoint, get_internal_container_repo_name, log_step
from .quay_api_client import QuayApiClient
from .quay_client import QuayClient
from .container_image_pusher import ContainerImagePusher
from .signature_handler import ContainerSignatureHandler, OperatorSignatureHandler
from .operator_pusher import OperatorPusher

# TODO: do we want this, or should I remove it?
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG = logging.getLogger("PubLogger")
logging.basicConfig()
LOG.setLevel(logging.INFO)


class PushDocker:
    """Handle full Docker push workflow."""

    ImageData = namedtuple("ImageData", ["repo", "tag"])

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

        # TODO: will our robot credentials be able to read from brew's build repos?
        self._quay_client = None
        self._quay_api_client = None

    @property
    def quay_client(self):
        """Create and access QuayClient."""
        if self._quay_client is None:
            self._quay_client = QuayClient(
                self.target_settings["quay_user"],
                self.target_settings["quay_password"],
                self.quay_host,
            )
        return self._quay_client

    @property
    def quay_api_client(self):
        """Create and access QuayApiClient."""
        if self._quay_api_client is None:
            self._quay_api_client = QuayApiClient(
                self.target_settings["quay_api_token"], self.quay_host
            )
        return self._quay_api_client

    def verify_target_settings(self):
        """Verify that target settings contains all the necessary data."""
        LOG.info("Verifying the necessary target settings")
        required_settings = [
            "quay_user",
            "quay_password",
            "quay_api_token",
            "pyxis_server",
            "quay_namespace",
            "iib_krb_principal",
            "iib_organization",
            "iib_index_image",
            "quay_operator_repository",
            "ssh_remote_host",
            "ssh_user",
            "ssh_password",
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

    @log_step("Translate docker push items")
    def filter_unrelated_repos(self, push_items):
        """Remove item repos from tag mapping if external_repos is set for push item.

        Args:
            push_items ([ContainerPushItem]):
                Container push items containing the repositories.
        """
        for push_item in push_items:
            if push_item.external_repos:
                #  if external repos is defined, push items was populated by ET
                #  item.repos have to be removed from tags mapping
                for repo in list(push_item.repos):
                    push_item.metadata["tags"].pop(repo)

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
    def check_repos_validity(cls, push_items, hub, target_settings, quay_api_client):
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
            quay_api_client (QuayApiClient):
                Instance of QuayApiClient.
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
                    quay_api_client.get_repository_data(full_repo)
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 404:
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
        namespace = self.target_settings["quay_namespace"]

        for item in push_items:
            for repo, tags in sorted(item.metadata["tags"].items()):
                internal_repo = get_internal_container_repo_name(repo)
                full_repo = repo_schema.format(namespace=namespace, repo=internal_repo)
                LOG.info("Generating backup mapping for repository '{0}'".format(repo))
                # try to get repo data
                try:
                    repo_data = self.quay_api_client.get_repository_data(full_repo)
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code == 404:
                        repo_data = None
                    else:
                        raise

                for tag in tags:
                    # repo doesn't exist, add to rollback tags
                    if not repo_data:
                        rollback_tags.append(PushDocker.ImageData(full_repo, tag))
                        continue
                    # tag exists in the repo, add to backup tags
                    if tag in repo_data.get("tags", {}):
                        image_data = PushDocker.ImageData(full_repo, tag)
                        image = image_schema.format(
                            host=self.quay_host,
                            repo=full_repo,
                            digest=repo_data["tags"][tag]["manifest_digest"],
                        )
                        manifest = self.quay_client.get_manifest(image)
                        backup_tags[image_data] = manifest
                    # tag doesn't exist in the repo, add to rollback tags
                    else:
                        rollback_tags.append(PushDocker.ImageData(full_repo, tag))

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
            self.quay_client.upload_manifest(manifest, image_ref)

        # delete tags that didn't previously exist
        LOG.info("Removing newly introduced tags")
        for image_data in rollback_tags:
            image_ref = schema.format(host=self.quay_host, repo=image_data.repo, tag=image_data.tag)
            LOG.info("Removing tag '{0}'".format(image_ref))
            self.quay_api_client.delete_tag(image_data.repo, image_data.tag)

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
        - (in case of failure) Rollback destination repos to the pre-push state

        Returns ([str]):
            List of container image repos (for UD cache flush done by pub)
        """
        # TODO: Do we need to manage push item state?
        # Filter out non-docker push items
        docker_push_items = self.get_docker_push_items()
        # Get operator push items (done early so that possible issues are detected)
        operator_push_items = self.get_operator_push_items()
        # Remove item.repos from tag mapping if needed
        self.filter_unrelated_repos(docker_push_items)
        # Check if we may push to destination repos
        self.check_repos_validity(
            docker_push_items, self.hub, self.target_settings, self.quay_api_client
        )
        # Generate resources for rollback in case there are errors during the push
        backup_tags, rollback_tags = self.generate_backup_mapping(docker_push_items)

        try:
            # Sign container images
            container_signature_handler = ContainerSignatureHandler(
                self.hub, self.task_id, self.target_settings, self.target_name
            )
            container_signature_handler.sign_container_images(docker_push_items)
            # Push container images
            container_pusher = ContainerImagePusher(docker_push_items, self.target_settings)
            container_pusher.push_container_images()

            if operator_push_items:
                # Build index images
                operator_pusher = OperatorPusher(operator_push_items, self.target_settings)
                iib_results = operator_pusher.build_index_images()
                # Sign operator images
                operator_signature_handler = OperatorSignatureHandler(
                    self.hub, self.task_id, self.target_settings, self.target_name
                )
                operator_signature_handler.sign_operator_images(iib_results)
                # Push index images to Quay
                operator_pusher.push_index_images(iib_results)
        except Exception:
            LOG.error("An exception has occurred during the push, starting rollback")
            self.rollback(backup_tags, rollback_tags)
            raise

        # Return repos for UD cache flush
        repos = []
        for item in docker_push_items:
            if item.external_repos:
                repos += item.external_repos.keys()
            else:
                repos += item.repos.keys()

        return sorted(list(set(repos)))


def mod_entry_point(push_items, hub, task_id, target_name, target_settings):
    """Entry point for use in another python code."""
    push = PushDocker(push_items, hub, task_id, target_name, target_settings)
    return push.run()
