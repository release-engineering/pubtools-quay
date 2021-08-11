from collections import namedtuple
from copy import deepcopy
import json
import logging

import requests

from .command_executor import ContainerExecutor
from .exceptions import (
    BadPushItem,
    InvalidTargetSettings,
)
from .utils.misc import get_internal_container_repo_name
from .quay_client import QuayClient
from .container_image_pusher import ContainerImagePusher
from .signature_handler import SignatureHandler, BasicSignatureHandler
from .manifest_list_merger import ManifestListMerger
from .untag_images import untag_images
from .push_docker import PushDocker
from .signature_remover import SignatureRemover

# TODO: do we want this, or should I remove it?
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOG = logging.getLogger("pubtools.quay")


class TagDocker:
    """Handle full tag-docker workflow."""

    ImageDetails = namedtuple("ImageDetails", ["reference", "manifest", "manifest_type", "digest"])
    MANIFEST_LIST_TYPE = "application/vnd.docker.distribution.manifest.list.v2+json"
    MANIFEST_V2S2_TYPE = "application/vnd.docker.distribution.manifest.v2+json"

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

        self._quay_client = None

        self.quay_host = self.target_settings.get("quay_host", "quay.io").rstrip("/")

        self.signature_remover = SignatureRemover()
        self.signature_remover.set_quay_client(self.quay_client)

        self.verify_target_settings()
        self.verify_input_data()

    @property
    def quay_client(self):
        """Create and access QuayClient for source and dest images."""
        if self._quay_client is None:
            self._quay_client = QuayClient(
                self.target_settings["dest_quay_user"],
                self.target_settings["dest_quay_password"],
                self.quay_host,
            )
        return self._quay_client

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
            "iib_index_image",
            "iib_krb_principal",
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

    def verify_input_data(self):
        """Verify that the data specified for the TagDocker operation are correct."""
        LOG.info("Verifying the input data")
        for item in self.push_items:
            if item.file_type != "docker":
                raise BadPushItem("Push items must be of 'docker' type")
            if len(item.repos) != 1:
                raise BadPushItem("In tag-docker, push items must have precisely one repository.")
            if item.metadata["add_tags"] and not item.metadata["tag_source"]:
                raise BadPushItem("Source must be provided if tags were requested to be added.")
            if not item.metadata["new_method"]:
                raise BadPushItem("Only new method is supported for tag-docker in Quay.")
            if item.metadata["tag_source"] and ":" in item.metadata["tag_source"]:
                raise BadPushItem("Specifying source via digest is not allowed.")

    def check_input_validity(self):
        """
        Check if input data satisfies tag-docker specific constraints.

        The constraints are following:
        1. If adding tags to prod target, these tags must already exist in stage target.
        2. If removing tags from prod target, these tags must already not exist in stage target.
        """
        if "propagated_from" in self.target_settings:
            full_repo_schema = "{host}/{namespace}/{repo}"
            stage_target_info = self.hub.worker.get_target_info(
                self.target_settings["propagated_from"]
            )
            stage_namespace = stage_target_info["settings"]["quay_namespace"]
            stage_quay_client = QuayClient(
                stage_target_info["settings"]["dest_quay_user"],
                stage_target_info["settings"]["dest_quay_password"],
                self.quay_host,
            )

            for item in self.push_items:
                internal_repo = get_internal_container_repo_name(list(item.repos.keys())[0])
                stage_repo = full_repo_schema.format(
                    host=self.quay_host, namespace=stage_namespace, repo=internal_repo
                )

                # all to-be-added tags must already exist in stage repo
                for tag in item.metadata["add_tags"]:
                    stage_image = "{0}:{1}".format(stage_repo, tag)
                    try:
                        stage_quay_client.get_manifest(stage_image)
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 404 or e.response.status_code == 401:
                            raise BadPushItem(
                                "To-be-added tag {0} must already exist in stage repo".format(tag)
                            )
                        else:
                            raise

                # all to-be-removed tags must already be removed from stage
                for tag in item.metadata["remove_tags"]:
                    stage_image = "{0}:{1}".format(stage_repo, tag)
                    try:
                        stage_quay_client.get_manifest(stage_image)
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 404 or e.response.status_code == 401:
                            # 404/401 -> all good
                            pass
                        else:
                            raise
                    else:
                        raise BadPushItem(
                            "To-be-removed tag {0} must already be removed from stage repo".format(
                                tag
                            )
                        )

    def get_image_details(self, reference, executor):
        """
        Create an ImageDetails namedtuple for the given image reference.

        Args:
            reference (str):
                Image reference.
            executor (Executor):
                Instance of Executor subclass used for skopeo inspect.
        Returns (ImageDetails|None):
            Namedtuple filled with images data, or None if image doesn't exist.
        """
        LOG.info("Getting image details of {0}".format(reference))
        try:
            manifest = self.quay_client.get_manifest(reference)
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404 or e.response.status_code == 401:
                LOG.info("Image '{0}' doesn't exist".format(reference))
                return None
            else:
                raise

        manifest_type = manifest["mediaType"]
        if manifest_type not in [TagDocker.MANIFEST_V2S2_TYPE, TagDocker.MANIFEST_LIST_TYPE]:
            raise BadPushItem("Image {0} has manifest type different than V2S2 or manifest list")

        # Check arch if the image is V2S2 manifest
        if manifest["mediaType"] == TagDocker.MANIFEST_V2S2_TYPE:
            arch = executor.skopeo_inspect(reference)["Architecture"]
            # Arch check is not a great way to verify that this is a source image, but there are
            # no better options without having build details
            if arch != "amd64":
                raise BadPushItem(
                    "Image {0} has V2S2 manifest and contains an architecture {1}. Only source "
                    "images are supported, which have arch 'amd64'.".format(reference, arch)
                )

        digest = self.quay_client.get_manifest_digest(reference)

        return TagDocker.ImageDetails(reference, manifest, manifest["mediaType"], digest)

    def is_arch_relevant(self, push_item, arch):
        """
        Find out if an operation should be performed on a given architecture.

        Uses values of 'archs' and 'exclude_archs' in push item's metadata.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            arch (str):
                Arch to investigate.
        Returns (bool):
            True if an operation should be performed on a given arch, False otherwise.
        """
        if push_item.metadata["exclude_archs"]:
            return arch not in push_item.metadata["archs"]
        else:
            return arch in push_item.metadata["archs"]

    def tag_remove_calculate_archs(self, push_item, tag, executor):
        """
        Calculate which architectures would be removed, and which would remain from a given tag.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            tag (str):
                Tag, for which a 'remove' operation will be performed.
            executor (Executor):
                Instance of Executor subclass used for skopeo inspect.
        Returns ([str], [str]):
            Tuple where first element contains archs that will be removed, and second element
            contains archs that will remain.
        """
        full_repo_schema = "{host}/{namespace}/{repo}"
        namespace = self.target_settings["quay_namespace"]

        internal_repo = get_internal_container_repo_name(list(push_item.repos.keys())[0])
        full_repo = full_repo_schema.format(
            host=self.quay_host, namespace=namespace, repo=internal_repo
        )

        if push_item.metadata["tag_source"]:
            source_image = "{0}:{1}".format(full_repo, push_item.metadata["tag_source"])
            source_details = self.get_image_details(source_image, executor)
        else:
            source_details = None

        dest_image = "{0}:{1}".format(full_repo, tag)
        dest_details = self.get_image_details(dest_image, executor)

        if dest_details is None:
            LOG.warning("Tag '{0}' already doesn't exist, no removal necessary".format(tag))
            return ([], [])

        if source_details and source_details.manifest_type != dest_details.manifest_type:
            raise BadPushItem(
                "Mismatch between manifest types of source {0}:{1} and tag {2}:{3}".format(
                    push_item.metadata["tag_source"],
                    source_details.manifest_type,
                    tag,
                    dest_details.manifest_type,
                )
            )

        # Scenario 1: source image
        if dest_details.manifest_type == TagDocker.MANIFEST_V2S2_TYPE:
            return self.tag_remove_calculate_archs_source_image(
                push_item, source_details, dest_details
            )

        # Scenario 2: multiarch image
        if dest_details.manifest_type == TagDocker.MANIFEST_LIST_TYPE:
            return self.tag_remove_calculate_archs_multiarch_image(
                push_item, source_details, dest_details
            )

    def tag_remove_calculate_archs_source_image(self, push_item, source_details, dest_details):
        """
        Calculate which archs would be removed if the specified images were source images.

        This method is a sub-step of the 'tag_remove_calculate_archs' method.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            source_details (ImageDetails|None):
                ImageDetails of source image, or None if it wasn't specified.
            dest_details (ImageDetails):
                ImageDetails of destination image.
        Returns ([str], [str]):
            Tuple where first element contains archs that will be removed, and second element
            contains archs that will remain.
        """
        # Option A: arch is relevant, source is specified and digests correspond -> remove
        if (
            self.is_arch_relevant(push_item, "amd64")
            and source_details is not None
            and source_details.digest == dest_details.digest
        ):
            return (["amd64"], [])
        # Option B: arch is relevant, source is specified, but digests don't correspond -> keep
        elif (
            self.is_arch_relevant(push_item, "amd64")
            and source_details is not None
            and source_details.digest != dest_details.digest
        ):
            return ([], ["amd64"])
        # Option C: arch is relevant, source is not specified (no digest check) -> remove
        elif self.is_arch_relevant(push_item, "amd64") and source_details is None:
            return (["amd64"], [])
        # Option D: arch is not relevant -> keep
        else:
            return ([], ["amd64"])

    def tag_remove_calculate_archs_multiarch_image(self, push_item, source_details, dest_details):
        """
        Calculate which archs would be removed if the specified images were multiarch images.

        This method is a sub-step of the 'tag_remove_calculate_archs' method.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            source_details (ImageDetails|None):
                ImageDetails of source image, or None if it wasn't specified.
            dest_details (ImageDetails):
                ImageDetails of destination image.
        Returns ([str], [str]):
            Tuple where first element contains archs that will be removed, and second element
            contains archs that will remain.
        """
        remove_archs = []
        keep_archs = []
        dest_manifest_data = [
            (m["digest"], m["platform"]["architecture"]) for m in dest_details.manifest["manifests"]
        ]
        source_manifest_data = (
            [
                (m["digest"], m["platform"]["architecture"])
                for m in source_details.manifest["manifests"]
            ]
            if source_details
            else []
        )

        for dest_digest, dest_arch in dest_manifest_data:
            # Option A: arch is relevant, src exists, digest matches in src and dest -> remove
            if (
                self.is_arch_relevant(push_item, dest_arch)
                and source_details is not None
                and (dest_digest, dest_arch) in source_manifest_data
            ):
                remove_archs.append(dest_arch)
            # Option B: arch is relevant, src exists, no digest match in src and dest -> keep
            elif (
                self.is_arch_relevant(push_item, dest_arch)
                and source_details is not None
                and (dest_digest, dest_arch) not in source_manifest_data
            ):
                keep_archs.append(dest_arch)
            # Option C: arch is relevant, src doesn't exist (digest match not possible)-> remove
            elif self.is_arch_relevant(push_item, dest_arch) and source_details is None:
                remove_archs.append(dest_arch)
            # Option D: arch is not relevant -> keep
            else:
                keep_archs.append(dest_arch)

        return (remove_archs, keep_archs)

    def tag_add_calculate_archs(self, push_item, tag, executor):
        """
        Calculate which architectures are present in a given tag, and which ones would be added.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            tag (str):
                Tag, for which an 'add' operation will be performed.
            executor (Executor):
                Instance of Executor subclass used for skopeo inspect.
        Returns ([str]|None):
            In case of multiarch image, arches which would be copied to the destination. In case
            of a source image, None if the copy operation is relevant or [] otherwise.
        """
        full_repo_schema = "{host}/{namespace}/{repo}"
        namespace = self.target_settings["quay_namespace"]

        internal_repo = get_internal_container_repo_name(list(push_item.repos.keys())[0])
        full_repo = full_repo_schema.format(
            host=self.quay_host, namespace=namespace, repo=internal_repo
        )
        source_image = "{0}:{1}".format(full_repo, push_item.metadata["tag_source"])
        dest_image = "{0}:{1}".format(full_repo, tag)
        source_details = self.get_image_details(source_image, executor)
        dest_details = self.get_image_details(dest_image, executor)

        if source_details is None:
            raise BadPushItem("Source image must be specified if add operation was requested")

        if dest_details and source_details.manifest_type != dest_details.manifest_type:
            raise BadPushItem(
                "Mismatch between manifest types of source {0}:{1} and tag {2}:{3}".format(
                    push_item.metadata["tag_source"],
                    source_details.manifest_type,
                    tag,
                    dest_details.manifest_type,
                )
            )

        # Scenario 1: source image
        if source_details.manifest_type == TagDocker.MANIFEST_V2S2_TYPE:
            # source arch is relevant, proceed with copying the source image
            if self.is_arch_relevant(push_item, "amd64"):
                return None
            # arch is irrelevant we want no-op
            else:
                return []

        # Scenario 2: multiarch image
        if source_details.manifest_type == TagDocker.MANIFEST_LIST_TYPE:
            add_archs = [
                m["platform"]["architecture"]
                for m in source_details.manifest["manifests"]
                if self.is_arch_relevant(push_item, m["platform"]["architecture"])
            ]
            return add_archs

    def copy_tag_sign_images(self, push_item, tag, signature_handler, executor):
        """
        Copy image from source to the destination tag and sign new manifest claims.

        If destination tag already contains a manifest, it will be overwritten.
        This workflow is expected to use on single-arch source images.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            tag (str):
                Tag, which acts as a destination to the copy operation.
            signature_handler (BasicSignatureHandler):
                Instance of signature handler which will perform the signing.
            executor (Executor):
                Instance of Executor subclass used for skopeo inspect.
        """
        full_repo_schema = "{host}/{namespace}/{repo}"
        external_image_schema = "{host}/{repo}:{tag}"
        namespace = self.target_settings["quay_namespace"]

        internal_repo = get_internal_container_repo_name(list(push_item.repos.keys())[0])
        full_repo = full_repo_schema.format(
            host=self.quay_host, namespace=namespace, repo=internal_repo
        )
        source_image = "{0}:{1}".format(full_repo, push_item.metadata["tag_source"])
        dest_image = "{0}:{1}".format(full_repo, tag)

        LOG.info(
            "Source image tag '{0}' will be copied to destination '{1}'".format(
                push_item.metadata["tag_source"], tag
            )
        )

        claim_messages = []
        details = self.get_image_details(source_image, executor)
        registries = self.target_settings["docker_settings"]["docker_reference_registry"]

        if details.manifest_type == TagDocker.MANIFEST_V2S2_TYPE and push_item.claims_signing_key:
            for registry in registries:
                reference = external_image_schema.format(
                    host=registry, repo=list(push_item.repos.keys())[0], tag=tag
                )
                message = SignatureHandler.create_manifest_claim_message(
                    destination_repo=list(push_item.repos.keys())[0],
                    signature_key=push_item.claims_signing_key,
                    manifest_digest=details.digest,
                    docker_reference=reference,
                    image_name=list(push_item.repos.keys())[0],
                    task_id=self.task_id,
                )
                claim_messages.append(message)
        elif details.manifest_type == TagDocker.MANIFEST_LIST_TYPE:
            raise ValueError("Tagging workflow is not supported for multiarch images")

        self.signature_remover.remove_tag_signatures(
            reference=dest_image,
            pyxis_server=self.target_settings["pyxis_server"],
            pyxis_krb_principal=self.target_settings["iib_krb_principal"],
            pyxis_krb_ktfile=self.target_settings.get("iib_krb_ktfile", None),
            exclude_by_claims=claim_messages,
        )

        signature_handler.sign_claim_messages(claim_messages, True, True)
        ContainerImagePusher.run_tag_images(source_image, [dest_image], True, self.target_settings)

    def merge_manifest_lists_sign_images(self, push_item, tag, add_archs, signature_handler):
        """
        Merge manifest lists between source and destination tag and sign manifest claims.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            tag (str):
                Tag, which acts as a destination to the merge operation.
            add_archs ([str]):
                Architectures which should be copied to the existing manifest list.
            signature_handler (BasicSignatureHandler):
                Instance of signature handler which will perform the signing.
        """
        LOG.info(
            "Architectures {0} of tag '{1}' will be copied to destination tag '{2}'".format(
                add_archs, push_item.metadata["tag_source"], tag
            )
        )

        full_repo_schema = "{host}/{namespace}/{repo}"
        external_image_schema = "{host}/{repo}:{tag}"
        namespace = self.target_settings["quay_namespace"]

        internal_repo = get_internal_container_repo_name(list(push_item.repos.keys())[0])
        full_repo = full_repo_schema.format(
            host=self.quay_host, namespace=namespace, repo=internal_repo
        )
        source_image = "{0}:{1}".format(full_repo, push_item.metadata["tag_source"])
        dest_image = "{0}:{1}".format(full_repo, tag)

        claim_messages = []
        registries = self.target_settings["docker_settings"]["docker_reference_registry"]

        # NOTE: Arch images don't need to be copied, since they already exist in the same repo
        merger = ManifestListMerger(source_image, dest_image)
        merger.set_quay_clients(self.quay_client, self.quay_client)
        new_manifest_list = merger.merge_manifest_lists_selected_architectures(add_archs)

        if push_item.claims_signing_key:
            for manifest in new_manifest_list["manifests"]:
                for registry in registries:
                    reference = external_image_schema.format(
                        host=registry, repo=list(push_item.repos.keys())[0], tag=tag
                    )
                    message = SignatureHandler.create_manifest_claim_message(
                        destination_repo=list(push_item.repos.keys())[0],
                        signature_key=push_item.claims_signing_key,
                        manifest_digest=manifest["digest"],
                        docker_reference=reference,
                        image_name=list(push_item.repos.keys())[0],
                        task_id=self.task_id,
                    )
                    claim_messages.append(message)

        # claim messages ensure that signatures of non-modified archs won't get removed
        self.signature_remover.remove_tag_signatures(
            reference=dest_image,
            pyxis_server=self.target_settings["pyxis_server"],
            pyxis_krb_principal=self.target_settings["iib_krb_principal"],
            pyxis_krb_ktfile=self.target_settings.get("iib_krb_ktfile", None),
            exclude_by_claims=claim_messages,
        )

        signature_handler.sign_claim_messages(claim_messages, True, True)

        raw_src_manifest = self.quay_client.get_manifest(source_image, manifest_list=True, raw=True)

        # Special case: if the source manifest and the merged manifest are the same, upload the
        # raw source manifest. The reason is that otherwise the digests of the copied manifests
        # will not correspond due to Python dicitonaries randomizing the element order
        if sorted(
            new_manifest_list["manifests"], key=lambda manifest: manifest["digest"]
        ) == sorted(
            json.loads(raw_src_manifest)["manifests"], key=lambda manifest: manifest["digest"]
        ):
            self.quay_client.upload_manifest(raw_src_manifest, dest_image, raw=True)
        else:
            self.quay_client.upload_manifest(new_manifest_list, dest_image)

    @classmethod
    def run_untag_images(cls, references, remove_last, target_settings):
        """
        Prepare the "untag images" entrypoint with all the necessary arguments and run it.

        Args:
            references ([str]):
                Image references which should be untagged.
            remove_last (bool):
                Whether to remove a tag when it's the last reference of an image (in that repo).
            target_settings (dict):
                Settings used for setting the value of untag parameters.
        """
        untag_images(
            references=references,
            quay_api_token=target_settings["dest_quay_api_token"],
            remove_last=remove_last,
            quay_user=target_settings["dest_quay_user"],
            quay_password=target_settings["dest_quay_password"],
            send_umb_msg=True,
            umb_urls=target_settings["docker_settings"]["umb_urls"],
            umb_cert=target_settings["docker_settings"].get(
                "umb_pub_cert", "/etc/pub/umb-pub-cert-key.pem"
            ),
            # assumption that we'll continue using .pem format
            umb_client_key=target_settings["docker_settings"].get(
                "umb_pub_cert", "/etc/pub/umb-pub-cert-key.pem"
            ),
            umb_ca_cert=target_settings["docker_settings"].get(
                "umb_ca_cert", "/etc/pki/tls/certs/ca-bundle.crt"
            ),
        )

    def untag_image(self, push_item, tag):
        """
        Untag image specified by tag.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            tag (str):
                Tag which should be removed.
        """
        LOG.info("Tag '{0}' will be removed".format(tag))
        full_repo_schema = "{host}/{namespace}/{repo}"
        namespace = self.target_settings["quay_namespace"]

        internal_repo = get_internal_container_repo_name(list(push_item.repos.keys())[0])
        full_repo = full_repo_schema.format(
            host=self.quay_host, namespace=namespace, repo=internal_repo
        )
        dest_image = "{0}:{1}".format(full_repo, tag)

        self.signature_remover.remove_tag_signatures(
            reference=dest_image,
            pyxis_server=self.target_settings["pyxis_server"],
            pyxis_krb_principal=self.target_settings["iib_krb_principal"],
            pyxis_krb_ktfile=self.target_settings.get("iib_krb_ktfile", None),
        )

        self.run_untag_images([dest_image], True, self.target_settings)

    def manifest_list_remove_archs(self, push_item, tag, remove_archs):
        """
        Remove specified archs from a manifest list and upload a new manifest list to Quay.

        Args:
            push_item (ContainerPushItem):
                Push item to perform the workflow with.
            tag (str):
                Tag whose manifest's archs will be removed.
            remove_archs ([str]):
                Architectures to remove from the manifest list.
        """
        LOG.info("Architectures {0} of tag '{1}' will be removed".format(remove_archs, tag))
        full_repo_schema = "{host}/{namespace}/{repo}"
        namespace = self.target_settings["quay_namespace"]

        internal_repo = get_internal_container_repo_name(list(push_item.repos.keys())[0])
        full_repo = full_repo_schema.format(
            host=self.quay_host, namespace=namespace, repo=internal_repo
        )
        dest_image = "{0}:{1}".format(full_repo, tag)
        manifest_list = self.quay_client.get_manifest(dest_image, manifest_list=True)
        keep_manifests = []

        for manifest in manifest_list["manifests"]:
            if manifest["platform"]["architecture"] not in remove_archs:
                keep_manifests.append(deepcopy(manifest))

        new_manifest_list = deepcopy(manifest_list)
        new_manifest_list["manifests"] = keep_manifests

        self.signature_remover.remove_tag_signatures(
            reference=dest_image,
            pyxis_server=self.target_settings["pyxis_server"],
            pyxis_krb_principal=self.target_settings["iib_krb_principal"],
            pyxis_krb_ktfile=self.target_settings.get("iib_krb_ktfile", None),
            remove_archs=remove_archs,
        )

        self.quay_client.upload_manifest(new_manifest_list, dest_image)

    def run(self):
        """
        Perform the full tag-docker workflow.

        The workflow adds or removes images to/from given tags. It's possible to specify only
        certain architectures to be added or removed. Based on the task arguments, five different
        scenarios may occur:
        - Copying whole image to tag (if tag is unused, or all its archs will be overwritten)
        - Copying only certain archs and adding them to the destination manifest list
        - Removing certain archs from a tag
        - Removing a tag (if all archs are to be removed from it)
        - No operation (to-be-removed tag already doesn't exist, or all archs are restricted)

        The workflow may be summarized as:
        - Verify that all repos may be worked with (same conditions are in PushDocker)
        - Evaluate which archs are to be added/removed from a given tag
        - If new images were created, perform signing workflow on them
        - Perform the appropriate add/remove/merge operation
        """
        # Validate repos, same as in PushDocker
        PushDocker.check_repos_validity(self.push_items, self.hub, self.target_settings)
        # perform tag-docker-specific checks
        self.check_input_validity()
        signature_handler = BasicSignatureHandler(self.hub, self.target_settings, self.target_name)

        with ContainerExecutor(
            self.target_settings["skopeo_image"],
            self.target_settings.get("docker_host") or "unix://var/run/docker.sock",
            self.target_settings.get("docker_timeout"),
            self.target_settings.get("docker_tls_verify") or False,
            self.target_settings.get("docker_cert_path") or None,
        ) as executor:
            executor.skopeo_login(
                self.target_settings["dest_quay_user"], self.target_settings["dest_quay_password"]
            )
            for item in self.push_items:
                for tag in item.metadata["add_tags"]:
                    LOG.info("Processing add tag '{0}'".format(tag))
                    add_archs = self.tag_add_calculate_archs(item, tag, executor)
                    # If all archs were somehow excluded from being added, no-op
                    if add_archs == []:
                        LOG.warning("No archs can be added to tag '{0}', skipping".format(tag))
                        continue
                    # If None, we're dealing with a source image and we want to copy to destination
                    elif add_archs is None:
                        self.copy_tag_sign_images(item, tag, signature_handler, executor)
                    # Otherwise, merge relevant archs of source and dest
                    else:
                        self.merge_manifest_lists_sign_images(
                            item, tag, add_archs, signature_handler
                        )

                for tag in item.metadata["remove_tags"]:
                    LOG.info("Processing remove tag '{0}'".format(tag))
                    remove_archs, keep_archs = self.tag_remove_calculate_archs(item, tag, executor)
                    # If all archs were somehow excluded from removal, no-op
                    if not remove_archs:
                        LOG.warning("No archs can be removed from tag '{0}', skipping".format(tag))
                        continue
                    # If no archs will remain after removal, just perform untagging
                    elif not keep_archs:
                        self.untag_image(item, tag)
                    # if some archs will be removed and some will remain, create new manifest list
                    else:
                        self.manifest_list_remove_archs(item, tag, remove_archs)


def mod_entry_point(push_items, hub, task_id, target_name, target_settings):
    """Entry point for use in another python code."""
    tag_docker = TagDocker(push_items, hub, task_id, target_name, target_settings)
    return tag_docker.run()
