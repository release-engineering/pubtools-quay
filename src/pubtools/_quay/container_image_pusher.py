import functools
import logging
from concurrent import futures
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Any, cast, Dict, List, Optional


import requests

from .exceptions import (
    ManifestTypeError,
)
from .utils.misc import (
    get_internal_container_repo_name,
    log_step,
    run_with_retries,
)
from .quay_client import QuayClient
from .tag_images import tag_images
from .types import ManifestList

from pubtools.tracing import get_trace_wrapper

tw = get_trace_wrapper()
LOG = logging.getLogger("pubtools.quay")


class ContainerImagePusher:
    """
    Push container images to Quay.

    No validation is performed, push items are expected to be correct.
    """

    def __init__(self, push_items: List[Any], target_settings: Dict[str, Any]) -> None:
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
        self._src_quay_client: Optional[QuayClient] = None
        self._dest_quay_client: Optional[QuayClient] = None

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
    def dest_quay_client(self) -> QuayClient:
        """Create and access QuayClient for dest image."""
        if self._dest_quay_client is None:
            self._dest_quay_client = QuayClient(
                self.target_settings["dest_quay_user"],
                self.target_settings["dest_quay_password"],
                self.quay_host,
            )
        return self._dest_quay_client

    @classmethod
    def run_tag_images(
        cls, source_ref: str, dest_refs: List[str], all_arch: bool, target_settings: Dict[str, Any]
    ) -> None:
        """
        Prepare the "tag images" entrypoint with all the necessary arguments and run it.

        NOTE: Tagging operation will run with retries to compensate for transient
              container-related issues.

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
        tag_images_partial = functools.partial(
            tag_images,
            source_ref,
            dest_refs,
            all_arch=all_arch,
            quay_user=target_settings["dest_quay_user"],
            quay_password=target_settings["dest_quay_password"],
            source_quay_host=target_settings.get("source_quay_host"),
            source_quay_user=target_settings.get("source_quay_user"),
            source_quay_password=target_settings.get("source_quay_password"),
            container_exec=target_settings.get("container_exec", True),
            container_image=target_settings["skopeo_image"],
            docker_url=target_settings.get("docker_host") or "unix://var/run/docker.sock",
            docker_timeout=target_settings.get("docker_timeout"),
            docker_verify_tls=target_settings.get("docker_tls_verify") or False,
            docker_cert_path=target_settings.get("docker_cert_path") or None,
            registry_username=target_settings.get("skopeo_executor_username") or None,
            registry_password=target_settings.get("skopeo_executor_password") or None,
        )

        run_with_retries(
            tag_images_partial,
            "Tag images",
            target_settings.get("tag_images_tries", 4),
            target_settings.get("tag_images_wait_time_increase", 10),
        )

    def _prepare_dest_refs(self, push_item: Any) -> List[str]:
        """Prepare destination references for push.

        Construct destination references based on tags and repo of push item.

        Args:
            push_item(ContainerPushItem): Container push item.

        Returns (list(str)):
            List of destination references for the push.
        """
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
        return dest_refs

    def copy_source_push_item(self, push_item: Any) -> None:
        """
        Perform the tagging operation for a push item containing a source image.

        Args:
            push_item (ContainerPushItem):
                Source container push item.
        """
        LOG.info("Copying push item '{0}' as a source image".format(push_item))

        source_ref = push_item.metadata["pull_url"]
        dest_refs = self._prepare_dest_refs(push_item)
        self.run_tag_images(source_ref, dest_refs, True, self.target_settings)

    def copy_v1_push_item(self, push_item: Any) -> None:
        """
        Perform the tagging operation for a push item containing a v1 image.

        Args:
            push_item (ContainerPushItem):
                Container push item.
        """
        LOG.info("Copying push item '{0}' as v1 container only".format(push_item))

        source_ref = push_item.metadata["pull_url"]
        dest_refs = self._prepare_dest_refs(push_item)

        self.run_tag_images(source_ref, dest_refs, True, self.target_settings)

    def copy_multiarch_push_item(self, push_item: Any, source_ml: ManifestList) -> None:
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
                simple_dest_refs.append(dest_ref)

        if simple_dest_refs:
            LOG.info(
                "Copying image {0} to {1} destinations without merging manifest lists".format(
                    source_ref, len(set(simple_dest_refs))
                )
            )
            self.run_tag_images(source_ref, list(set(simple_dest_refs)), True, self.target_settings)

    @log_step("Push images to Quay")
    def push_container_images(self) -> None:
        """
        Push container images to Quay.

        Two image types are supported: source images and multiarch images. Non-source, single arch
        images are not supported. In case of multiarch images, manifest list merging is performed if
        destination image contains more architectures than source.
        """

        @tw.instrument_func()
        def push_container_image(item: Any) -> None:
            """
            Push container images to Quay.

            Args:
                item (ContainerPushItem):
                    Multiarch container push item.
            """
            try:
                source_ml = self.src_quay_client.get_manifest(
                    item.metadata["pull_url"], media_type=QuayClient.MANIFEST_LIST_TYPE
                )
            except ManifestTypeError:
                source_ml = None
            # some registries can return 404 instead of v2s2
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    source_ml = None
                else:
                    raise

            # this metadata field indicates a source image
            sources_for_nvr = (
                item.metadata["build"]
                .get("extra", {})
                .get("image", {})
                .get("sources_for_nvr", None)
            )
            v1 = False
            if not sources_for_nvr and not source_ml:
                v1 = True
            # Source image
            if sources_for_nvr:
                self.copy_source_push_item(item)
            # v1 image
            elif v1:
                self.copy_v1_push_item(item)
            # Multiarch images
            else:
                self.copy_multiarch_push_item(item, cast(ManifestList, source_ml))

        num_thread_container_push = self.target_settings.get("num_thread_container_push", 5)

        with ThreadPoolExecutor(max_workers=num_thread_container_push) as executor:
            future_results = [
                executor.submit(push_container_image, item) for item in self.push_items
            ]
            for future in futures.as_completed(future_results):
                if future.exception():
                    raise future.exception()  # type: ignore
