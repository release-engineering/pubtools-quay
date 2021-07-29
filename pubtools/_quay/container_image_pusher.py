import logging

import requests

from .exceptions import (
    BadPushItem,
    ManifestTypeError,
)
from .utils.misc import (
    get_internal_container_repo_name,
    log_step,
)
from .quay_client import QuayClient
from .tag_images import tag_images
from .manifest_list_merger import ManifestListMerger

LOG = logging.getLogger("pubtools.quay")


class ContainerImagePusher:
    """
    Push container images to Quay.

    No validation is performed, push items are expected to be correct.
    """

    def __init__(self, push_items, target_settings):
        """
        Initialize.

        Args:
            push_items ([ContainerPushItem]):
                List of push items.
            target_settings (dict):
                Target settings.
        """
        self.push_items = push_items
        self.target_settings = target_settings

        self.quay_host = self.target_settings.get("quay_host", "quay.io").rstrip("/")
        self._src_quay_client = None
        self._dest_quay_client = None

    @property
    def src_quay_client(self):
        """Create and access QuayClient for source image."""
        if self._src_quay_client is None:
            self._src_quay_client = QuayClient(
                self.target_settings["source_quay_user"],
                self.target_settings["source_quay_password"],
                self.quay_host,
            )
        return self._src_quay_client

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

    @classmethod
    def run_tag_images(cls, source_ref, dest_refs, all_arch, target_settings):
        """
        Prepare the "tag images" entrypoint with all the necessary arguments and run it.

        Args:
            source_ref (str):
                Source image reference.
            dest_refs ([str]):
                List of destination references.
            all_arch (bool):
                Whether all architectures should be copied.
            target_settings (dict):
                Settings used for setting the values of the function parameters.
        """
        # TODO: do we want to do some registry-proxy -> quay transformation?
        # TODO: tag-images only supports quay.io hostname, should we extend the functionality?
        # TODO: should this command always be performed remotely?
        tag_images(
            source_ref,
            dest_refs,
            all_arch=all_arch,
            quay_user=target_settings["dest_quay_user"],
            quay_password=target_settings["dest_quay_password"],
            container_exec=True,
            container_image=target_settings["skopeo_image"],
            docker_url=target_settings.get("docker_host") or "unix://var/run/docker.sock",
            docker_timeout=target_settings.get("docker_timeout"),
            docker_verify_tls=target_settings.get("docker_tls_verify") or False,
            docker_cert_path=target_settings.get("docker_cert_path") or None,
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

    def copy_source_push_item(self, push_item):
        """
        Perform the tagging operation for a push item containing a source image.

        Args:
            push_item (ContainerPushItem):
                Source container push item.
        """
        LOG.info("Copying push item '{0}' as a source image".format(push_item))
        source_ref = push_item.metadata["pull_url"]
        dest_refs = []
        image_schema = "{host}/{namespace}/{repo}:{tag}"
        namespace = self.target_settings["quay_namespace"]

        for repo, tags in sorted(push_item.metadata["tags"].items()):
            internal_repo = get_internal_container_repo_name(repo)
            for tag in tags:
                dest_ref = image_schema.format(
                    host=self.quay_host,
                    namespace=namespace,
                    repo=internal_repo,
                    tag=tag,
                )
                dest_refs.append(dest_ref)

        self.run_tag_images(source_ref, dest_refs, True, self.target_settings)

    def run_merge_workflow(self, source_ref, dest_refs):
        """
        Perform Docker push and manifest list merge workflow.

        The difference in this workflow is that all single arch images are first copied via
        digest, and then their respective manifest lists are merged.

        Args:
            source_ref (str):
                Source image reference.
            dest_refs ([str]):
                List of destination references which need manifest merging.
        """
        image_schema = "{repo}@{digest}"
        source_repo = source_ref.split(":")[0]

        # get unique destination repositories
        dest_repos = sorted(list(set([ref.split(":")[0] for ref in dest_refs])))
        source_ml = self.src_quay_client.get_manifest(source_ref, manifest_list=True)

        # copy each arch source image to all destination repos
        for manifest in source_ml["manifests"]:
            source_image = image_schema.format(repo=source_repo, digest=manifest["digest"])
            dest_images = [
                image_schema.format(repo=dest_repo, digest=manifest["digest"])
                for dest_repo in dest_repos
            ]
            self.run_tag_images(source_image, dest_images, False, self.target_settings)

        for dest_ref in dest_refs:
            LOG.info(
                "Merging manifest lists of source '{0}' and destination '{1}'".format(
                    source_ref, dest_ref
                )
            )
            merger = ManifestListMerger(source_ref, dest_ref, host=self.quay_host)
            merger.set_quay_clients(self.src_quay_client, self.dest_quay_client)
            merger.merge_manifest_lists()

    def copy_multiarch_push_item(self, push_item, source_ml):
        """
        Evaluate the correct tagging and manifest list merging strategy of multiarch push item.

        There are two workflows of multiarch images: Simple copying, or manifest list merging.
        Destination tags are sorted, and correct workflow is performed on them.

        Args:
            push_items (ContainerPushItem):
                Multiarch container push item.
            source_ml (dict):
                Manifest list of the source image.
        """
        LOG.info("Copying push item '{0}' as a multiarch image.".format(push_item))
        source_ref = push_item.metadata["pull_url"]
        simple_dest_refs = []
        merge_mls_dest_refs = []

        image_schema = "{host}/{namespace}/{repo}:{tag}"
        namespace = self.target_settings["quay_namespace"]

        for repo, tags in sorted(push_item.metadata["tags"].items()):
            internal_repo = get_internal_container_repo_name(repo)
            for tag in tags:
                dest_ref = image_schema.format(
                    host=self.quay_host,
                    namespace=namespace,
                    repo=internal_repo,
                    tag=tag,
                )
                try:
                    dest_ml = self.dest_quay_client.get_manifest(dest_ref, manifest_list=True)
                    LOG.info(
                        "Getting missing archs between images '{0}' and '{1}'".format(
                            source_ref, dest_ref
                        )
                    )
                    missing_archs = ManifestListMerger.get_missing_architectures(source_ml, dest_ml)
                    # Option 1: Destination doesn't contain extra archs, ML merging is unnecessary
                    if not missing_archs:
                        simple_dest_refs.append(dest_ref)
                    # Option 2: Destination has extra archs, MLs will be merged
                    else:
                        merge_mls_dest_refs.append(dest_ref)
                except requests.exceptions.HTTPError as e:
                    # Option 3: Destination tag doesn't exist, no ML merging
                    if e.response.status_code == 404 or e.response.status_code == 401:
                        simple_dest_refs.append(dest_ref)
                    else:
                        raise

        if simple_dest_refs:
            LOG.info(
                "Copying image {0} to {1} destinations without merging manifest lists".format(
                    source_ref, len(simple_dest_refs)
                )
            )
            self.run_tag_images(source_ref, simple_dest_refs, True, self.target_settings)
        if merge_mls_dest_refs:
            LOG.info(
                "Copying image {0} to {1} destinations and merging manifest lists".format(
                    source_ref, len(merge_mls_dest_refs)
                )
            )
            self.run_merge_workflow(source_ref, merge_mls_dest_refs)

    @log_step("Push images to Quay")
    def push_container_images(self):
        """
        Push container images to Quay.

        Two image types are supported: source images and multiarch images. Non-source, single arch
        images are not supported. In case of multiarch images, manifest list merging is performed if
        destination image contains more architectures than source.
        """
        for item in self.push_items:
            try:
                source_ml = self.src_quay_client.get_manifest(
                    item.metadata["pull_url"], manifest_list=True
                )
            except ManifestTypeError:
                source_ml = None

            # this metadata field indicates a source image
            sources_for_nvr = (
                item.metadata["build"]
                .get("extra", {})
                .get("image", {})
                .get("sources_for_nvr", None)
            )
            if not sources_for_nvr and not source_ml:
                raise BadPushItem(
                    "Push item '{0}' contains a single-arch image that's not a "
                    "source image. This use-case is not supported".format(item)
                )
            # Source image
            if sources_for_nvr:
                self.copy_source_push_item(item)
            # Multiarch images
            else:
                self.copy_multiarch_push_item(item, source_ml)
