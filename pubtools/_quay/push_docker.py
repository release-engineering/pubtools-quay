from collections import namedtuple
import logging
import sys
from time import sleep

import requests

from .exceptions import BadPushItem, InvalidTargetSettings, InvalidRepository
from .utils.misc import run_entrypoint, get_internal_container_repo_name, log_step
from .quay_api_client import QuayApiClient
from .quay_client import QuayClient
from .container_image_pusher import ContainerImagePusher
from .signature_handler import ContainerSignatureHandler, OperatorSignatureHandler
from .signature_remover import SignatureRemover
from .operator_pusher import OperatorPusher
from .utils.misc import get_external_container_repo_name, get_pyxis_ssl_paths, timestamp

# TODO: do we want this, or should I remove it?
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG = logging.getLogger("pubtools.quay")


class PushDocker:
    """Handle full Docker push workflow."""

    ImageData = namedtuple("ImageData", ["repo", "tag", "digest", "v2s1_digest"])

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
        cert, key = get_pyxis_ssl_paths(target_settings)

        args = ["--pyxis-server", target_settings["pyxis_server"]]
        args += ["--pyxis-ssl-crtfile", cert]
        args += ["--pyxis-ssl-keyfile", key]
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
            # Only check Pyxis if the option is enabled in target settings
            if target_settings.get("do_repo_deprecation_check", False):
                LOG.info("Checking validity of repository metadata '{0}'".format(repo))
                # Check if repo exists in Pyxis
                try:
                    metadata = cls.get_repo_metadata(repo, target_settings)
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
                        rollback_tags.append(PushDocker.ImageData(full_repo, tag, None, None))
                        continue
                    # tag exists in the repo, add to backup tags
                    if tag in repo_tags.get("tags", {}):
                        image_tag = image_schema_tag.format(
                            host=self.quay_host, repo=full_repo, tag=tag
                        )
                        # it's possible that there will be a mismatch between the two calls
                        try:
                            digest = self.dest_quay_client.get_manifest_digest(image_tag)
                        except requests.exceptions.HTTPError as e:
                            # When robot account is used, 401 may be returned instead of 404
                            if e.response.status_code == 404 or e.response.status_code == 401:
                                digest = self._poll_tag_inconsistency(full_repo, tag)
                            else:
                                raise

                        # It was determined that the image doesn't actually exist
                        if not digest:
                            rollback_tags.append(PushDocker.ImageData(full_repo, tag, None, None))
                            continue

                        # skip getting v2s1 for non-amd64 image
                        if item.metadata["arch"] in ["amd64", "x86_64"]:
                            v2s1_digest = self.dest_quay_client.get_manifest_digest(
                                image_tag, media_type=QuayClient.MANIFEST_V2S1_TYPE
                            )
                        else:
                            v2s1_digest = None
                        # for backup tags store also digest
                        image_data = PushDocker.ImageData(full_repo, tag, digest, v2s1_digest)
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
                        rollback_tags.append(PushDocker.ImageData(full_repo, tag, None, None))

        # it's possible that rollback tags will contain duplicate entries
        rollback_tags = sorted(list(set(rollback_tags)))
        return (backup_tags, rollback_tags)

    def _poll_tag_inconsistency(self, full_repo, tag, poll_rate=30, timeout=120):
        """
        Resolve an inconsistency between repo tags reported by Docker API and tag actually existing.

        This scenario occurs when Docker API claims that a tag exists, but attempting to get the
        tag's digest results in a 404. It could be caused by a delay between two data sources
        becoming consistent, or by repo tag being removed between the two calls. Attempt to
        reconcile the difference by periodically calling the two sources. If the data is still
        inconsistent after timeout, assume that the image doesn't exist and continue.

        Args:
            full_repo (str):
                Repo name to poll for tags
            tag (str):
                Tag to poll for manifest digest.
            poll_rate (int, optional):
                How many seconds to wait between polling. Defaults to 30.
            timeout (int, optional):
                How many seconds to poll before giving up and assuming that the image doesn't exist.
                Defaults to 120.

        Returns (str, None):
            Image digest, or None if digest doesn't exist (or timeout is reached).
        """
        image_schema_tag = "{host}/{repo}:{tag}"
        image_tag = image_schema_tag.format(host=self.quay_host, repo=full_repo, tag=tag)

        for i in range(timeout // poll_rate):
            sleep(poll_rate)
            repo_tags = self.dest_quay_client.get_repository_tags(full_repo)

            try:
                digest = self.dest_quay_client.get_manifest_digest(image_tag)
            except requests.exceptions.HTTPError as e:
                # When robot account is used, 401 may be returned instead of 404
                if e.response.status_code == 404 or e.response.status_code == 401:
                    digest = None
                else:
                    raise

            if tag in repo_tags.get("tags", {}) and digest:
                return digest
            if tag not in repo_tags.get("tags", {}) and digest is None:
                return None

        LOG.warning(
            "Unable to determine if image '{0}' exists, assuming it doesn't.".format(image_tag)
        )
        return None

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
        existing_index_images,
        iib_results,
        backup_tags,
        container_signature_handler,
        operator_signature_handler,
        signature_remover,
        claim_messages,
        ii_claim_messages,
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
            claims_messages (list(dict)):
                claim messages created for new container items
            ii_claims_message (list(dict)):
                claim messages created for new index image(s)

        """
        new_signatures = [(m["manifest_digest"], m["docker_reference"]) for m in claim_messages]
        outdated_signatures = []

        for image_data, manifest in backup_tags.items():
            ext_repo = get_external_container_repo_name(image_data.repo.split("/")[1])
            if "manifests" in manifest:
                for arch_manifest in manifest["manifests"]:
                    outdated_signatures.append((arch_manifest["digest"], image_data.tag, ext_repo))
            else:
                outdated_signatures.append((image_data.digest, image_data.tag, ext_repo))
            # also add V2S1 signature (only one per tag)
            if image_data.v2s1_digest:
                outdated_signatures.append((image_data.v2s1_digest, image_data.tag, ext_repo))

        signatures_to_remove = []
        for existing_signature in container_signature_handler.get_signatures_from_pyxis(
            [sig[0] for sig in outdated_signatures]
        ):
            if (
                existing_signature["manifest_digest"],
                existing_signature["reference"].split(":")[-1],
                existing_signature["repository"],
            ) in outdated_signatures and (
                existing_signature["manifest_digest"],
                existing_signature["reference"],
            ) not in new_signatures:
                signatures_to_remove.append(existing_signature["_id"])

        cert, key = get_pyxis_ssl_paths(self.target_settings)

        if signatures_to_remove:
            signature_remover.remove_signatures_from_pyxis(
                signatures_to_remove,
                self.target_settings["pyxis_server"],
                cert,
                key,
            )

        signatures_to_remove = []
        if existing_index_images:
            new_operator_signatures = [
                (m["manifest_digest"], m["docker_reference"]) for m in ii_claim_messages
            ]

            for existing_signature in container_signature_handler.get_signatures_from_pyxis(
                [digest_version[0] for digest_version in existing_index_images]
            ):
                if (
                    existing_signature["manifest_digest"],
                    existing_signature["reference"],
                ) not in new_operator_signatures and (
                    existing_signature["manifest_digest"],
                    existing_signature["reference"].split(":")[-1],
                    existing_signature["repository"],
                ) in existing_index_images:
                    signatures_to_remove.append(existing_signature["_id"])
            if signatures_to_remove:
                signature_remover.remove_signatures_from_pyxis(
                    signatures_to_remove,
                    self.target_settings["pyxis_server"],
                    cert,
                    key,
                )

    def _fetch_digest(self, repo, tag, media_type):
        """Fetch digest of repo and tag for given media type.

        Args:
            repo(str):
                Repository name.
            tag(str):
                Image tag.
            mtype(str):
                Media type for requested digest.
                (can be only application/vnd.docker.distribution.manifest.v2+json,
                application/vnd.docker.distribution.manifest.v1+json)

        Returns(str): Manifest digest of the container.
        """
        image_schema = "{host}/{namespace}/{repo}:{tag}"
        dest_ref = image_schema.format(
            host=self.quay_host,
            namespace=self.target_settings["quay_namespace"],
            repo=repo,
            tag=tag,
        )
        digest = self.dest_quay_client.get_manifest_digest(dest_ref, media_type=media_type)
        return digest

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
        for item in push_items:
            item.metadata["new_digests"] = {}
            missing_media_types = set(
                [QuayClient.MANIFEST_V2S2_TYPE, QuayClient.MANIFEST_V2S1_TYPE]
            ) - set(item.metadata["build"]["extra"]["image"]["media_types"])

            # Always add v2s1 due to possible digest change
            missing_media_types.add(QuayClient.MANIFEST_V2S1_TYPE)
            for repo, tags in item.metadata["tags"].items():
                internal_repo = get_internal_container_repo_name(repo)
                v2_sch2_cache = {}
                for tag in tags:
                    for mtype in missing_media_types:
                        if mtype == QuayClient.MANIFEST_V2S2_TYPE:
                            if repo not in v2_sch2_cache:
                                v2_sch2_cache[repo] = self._fetch_digest(internal_repo, tag, mtype)
                            item.metadata["new_digests"].setdefault((repo, tag), {})[
                                mtype
                            ] = v2_sch2_cache[repo]
                        # Fetch v2s1 only for amd64 image
                        elif item.metadata["arch"] in ["amd64", "x86_64"]:
                            item.metadata["new_digests"].setdefault((repo, tag), {})[
                                mtype
                            ] = self._fetch_digest(internal_repo, tag, mtype)

    def run(self):
        """
        Perform the full push-docker workflow.

        The workflow can be summarized as:
        - Filter out push items to only include container image items
        - Check if the destination repos may be pushed to (using Pyxis)
        - Generate backup mapping that will be used for rollback if something goes wrong.
        - Sign container images using RADAS and upload signatures to Pyxis
        - Push container images to their destinations
        - Fetching digests for missing media types of pushed items
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
        # Sign container images
        container_signature_handler = ContainerSignatureHandler(
            self.hub, self.task_id, self.target_settings, self.target_name
        )
        operator_signature_handler = OperatorSignatureHandler(
            self.hub, self.task_id, self.target_settings, self.target_name
        )
        sig_remover = SignatureRemover()
        sig_remover.set_quay_client(self.dest_quay_client)

        manifest_claims = container_signature_handler.sign_container_images(docker_push_items)
        # Push container images
        container_pusher = ContainerImagePusher(docker_push_items, self.target_settings)
        container_pusher.push_container_images()

        # fetch missing digests
        self.fetch_missing_push_items_digests(docker_push_items, self.target_settings)

        # sign missing images
        manifest_claims += container_signature_handler.sign_container_images_new_digests(
            docker_push_items
        )

        failed = False

        ii_manifest_claims = []
        if operator_push_items:
            # Build index images
            operator_pusher = OperatorPusher(
                operator_push_items, self.task_id, self.target_settings
            )
            existing_index_images = operator_pusher.get_existing_index_images(self.dest_quay_client)
            iib_results = operator_pusher.build_index_images()
            # Sign operator images
            successful_iib_results = dict(
                [(key, val) for key, val in iib_results.items() if val["iib_result"]]
            )
            ii_manifest_claims += operator_signature_handler.sign_operator_images(
                successful_iib_results, index_stamp
            )
            # Push index images to Quay
            operator_pusher.push_index_images(successful_iib_results, index_stamp)
            # Rollback only when all index image builds fails
            if not any([x["iib_result"] for x in iib_results.values()]):
                LOG.error("Push of all index images failed, running rollback.")
                self.rollback(backup_tags, rollback_tags)
                failed = True
            if successful_iib_results != iib_results:
                LOG.error("Push of some index images failed")
                failed = True

        # Remove old signatures
        self.remove_old_signatures(
            docker_push_items,
            existing_index_images,
            dict([(k, v) for k, v in successful_iib_results.items() if v["iib_result"]]),
            backup_tags,
            container_signature_handler,
            operator_signature_handler,
            sig_remover,
            manifest_claims,
            ii_manifest_claims,
        )
        if failed:
            # Why???
            sys.exit(1)


def mod_entry_point(push_items, hub, task_id, target_name, target_settings):
    """Entry point for use in another python code."""
    push = PushDocker(push_items, hub, task_id, target_name, target_settings)
    push.run()
