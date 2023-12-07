import logging
import sys

from .container_image_pusher import ContainerImagePusher
from .exceptions import InvalidTargetSettings
from .operator_pusher import OperatorPusher

from .utils.misc import (
    get_internal_container_repo_name,
    timestamp,
    parse_index_image,
)
from .signer_wrapper import SIGNER_BY_LABEL
from .item_processor import (
    VirtualPushItem,
    SignEntry,
    item_processor_for_internal_data,
)

from .quay_client import QuayClient

LOG = logging.getLogger("pubtools.quay")


def verify_target_settings(target_settings):
    """
    Verify the presence and validity of target settings.

    Args:
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
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
        "iib_index_image",
        "quay_operator_repository",
        "skopeo_image",
        "docker_settings",
    ]

    for setting in required_settings:
        if setting not in target_settings:
            raise InvalidTargetSettings(
                "'{0}' must be present in the target settings.".format(setting)
            )

    required_docker_settings = ["umb_urls", "docker_reference_registry"]
    for setting in required_docker_settings:
        if setting not in target_settings["docker_settings"]:
            raise InvalidTargetSettings(
                "'{0}' must be present in the docker settings.".format(setting)
            )


def _get_operator_quay_client(target_settings):
    """Create and access QuayClient for dest image."""
    return QuayClient(
        target_settings.get("index_image_quay_user", target_settings["dest_quay_user"]),
        target_settings.get("index_image_quay_password", target_settings["dest_quay_password"]),
        target_settings.get("quay_host", "quay.io").rstrip("/"),
    )


def _index_image_to_sign_entries(
    src_index_image, dest_namespace, dest_tags, signing_keys, target_settings
):
    """Generate entries to sign.

    Method generates sign entries for index image with <dest_tag> and <dest_tag>-<index_stamp> tags
    and given signing_keys. Only manifests with architecture amd64 are included in the output.

    Args:
        src_index_image (str): Source index image.
        dest_namespace (str): Destination internal namespace.
        dest_tag (str): Destination tag.
        index_stamp (str): Index stamp.
        signing_keys (list): List of signing keys.
    """
    iib_repo = target_settings["quay_operator_repository"]
    dest_registries = target_settings["docker_settings"]["docker_reference_registry"]
    dest_registries = dest_registries if isinstance(dest_registries, list) else [dest_registries]
    dest_operator_quay_client = _get_operator_quay_client(target_settings)
    manifest_list = dest_operator_quay_client.get_manifest(
        src_index_image, media_type=QuayClient.MANIFEST_LIST_TYPE
    )
    index_image_digests = [
        m["digest"]
        for m in manifest_list["manifests"]
        if m["platform"]["architecture"] in ["amd64", "x86_64"]
    ]
    to_sign_entries = []
    for registry in dest_registries:
        for _dest_tag in dest_tags:
            for digest in index_image_digests:
                reference = f"{registry}/{dest_namespace}/{iib_repo}:{_dest_tag}"
                for key in signing_keys:
                    to_sign_entries.append(
                        SignEntry(
                            reference=reference,
                            repo=iib_repo,
                            digest=digest,
                            arch="amd64",
                            signing_key=key,
                        )
                    )
    return to_sign_entries


def _remove_index_image_signatures(outdated_manifests, current_signatures, target_settings):
    """Remove signatures of outdated manifests with confitured signers for the target.

    Args:
        outdated_manifests (list): List of outdated manifests.
        current_signatures (list): List of current signatures.
        target_settings (dict): Target settings.
    """
    for signer in target_settings["signing"]:
        if signer["enabled"]:
            signercls = SIGNER_BY_LABEL[signer["label"]]
            signer = signercls(config_file=signer["config_file"], settings=target_settings)
            signer.remove_signatures(outdated_manifests, _exclude=current_signatures)


def _sign_index_image(
    built_index_image, namespace, dest_tags, signing_keys, task_id, target_settings
):
    """Sign index image with configured signers for the target.

    Args:
        built_index_image (str): Index image built results.
        namespace (str): Namespace of internal organization in container registry.
        dest_tag (str): Destination tag.
        signing_keys (list): List of signing keys.
        task_id (str): Task ID.
        index_stamp (str): timestamp used as suffix in destination timestamp tag
        target_settings (dict): Target settings.
    Returns:
        list: List of current signatures.
    """
    to_sign_entries = _index_image_to_sign_entries(
        built_index_image, namespace, dest_tags, signing_keys, target_settings
    )
    current_signatures = []
    for signer in target_settings["signing"]:
        if signer["enabled"]:
            signercls = SIGNER_BY_LABEL[signer["label"]]
            signer = signercls(config_file=signer["config_file"], settings=target_settings)
            signer.sign_containers(to_sign_entries, task_id=task_id)
    return current_signatures


def task_iib_add_bundles(
    bundles,
    archs,
    index_image,
    deprecation_list,
    signing_keys,
    hub,
    task_id,
    target_settings,
    target_name,
):
    """
    Perform all the necessary actions for the 'PushAddIIBBundles' entrypoint.

    Args:
        bundles ([str]):
            Bundles to add to the index image.
        archs ([str]):
            Architectures to build the index image for.
        index_image (str):
            Index image to add the bundles to.
        deprecation_list ([str]):
            Bundles to deprecate in the index image.
        signing_keys ([str]):
            Signing keys to be used.
        hub (HubProxy):
            Instance of XMLRPC pub-hub proxy.
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
        target_name (str):
            Name of the target.
    """
    image_schema_tag = "{host}/{namespace}/{repo}:{tag}"
    verify_target_settings(target_settings)
    quay_client = QuayClient(
        target_settings["dest_quay_user"], target_settings["dest_quay_password"], "quay.io"
    )

    # Build new index image in IIB
    build_details = OperatorPusher.iib_add_bundles(
        bundles=bundles,
        archs=archs,
        index_image=index_image,
        deprecation_list=deprecation_list,
        build_tags=["{0}-{1}".format(index_image.split(":")[1], task_id)],
        target_settings=target_settings,
    )
    if not build_details:
        sys.exit(1)
    _, tag = build_details.index_image.split(":", 1)
    index_stamp = timestamp()
    iib_namespace = target_settings.get(
        "quay_operator_namespace", target_settings["quay_namespace"]
    )
    item_processor = item_processor_for_internal_data(
        quay_client,
        target_settings["quay_host"].rstrip("/"),
        target_settings.get("retry_sleep_time", 5),
        iib_namespace,
    )
    # Add bundles task doesn't work with pushitem so we create VirtualPushItem to enable
    # existing code for fetching needed data.
    vitem = VirtualPushItem(
        metadata={"tags": {target_settings["quay_operator_repository"]: tag}},
        repos={target_settings["quay_operator_repository"]: [tag]},
    )
    existing_manifests = item_processor.generate_existing_manifests_metadata(vitem)
    outdated_manifests = []
    for ref, tag, man_arch_dig in existing_manifests:
        if man_arch_dig.arch in ("amd64", "x86_64"):
            outdated_manifests.append((man_arch_dig.digest, tag, ref))

    current_signatures = _sign_index_image(
        build_details.internal_index_image_copy_resolved,
        iib_namespace,
        [tag, f"{tag}-{index_stamp}"],
        signing_keys,
        task_id,
        target_settings,
    )
    dest_image = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=iib_namespace,
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag=tag,
    )
    dest_image_stamp = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings.get("quay_operator_namespace", target_settings["quay_namespace"]),
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag="%s-%s" % (tag, index_stamp),
    )
    iib_namespace = target_settings.get(
        "quay_operator_namespace", target_settings["quay_namespace"]
    )

    # Push image to Quay
    # Copy target settings and override username and password for quay_operator_namespace
    index_image_ts = target_settings.copy()
    index_image_ts["dest_quay_user"] = index_image_ts.get(
        "index_image_quay_user", index_image_ts["dest_quay_user"]
    )
    index_image_ts["dest_quay_password"] = index_image_ts.get(
        "index_image_quay_password", index_image_ts["dest_quay_password"]
    )
    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, index_image_ts
    )
    iib_feed, iib_namespace, iib_intermediate_repo = parse_index_image(build_details)
    # Permanent index image with proxy as a host must be used because skopeo cannot handle
    # login to two Quay namespaces at the same time
    permanent_index_image_proxy = image_schema_tag.format(
        host=iib_feed,
        namespace=iib_namespace,
        repo=iib_intermediate_repo,
        tag=build_details.build_tags[0],
    )
    ContainerImagePusher.run_tag_images(
        permanent_index_image_proxy, [dest_image_stamp], True, index_image_ts
    )

    for signer in target_settings["signing"]:
        if signer["enabled"]:
            signercls = SIGNER_BY_LABEL[signer["label"]]
            signer = signercls(config_file=signer["config_file"], settings=target_settings)
            signer.remove_signatures(outdated_manifests, _exclude=current_signatures)


def task_iib_remove_operators(
    operators, archs, index_image, signing_keys, hub, task_id, target_settings, target_name
):
    """
    Perform all the necessary actions for the 'PushRemoveIIBOperators' entrypoint.

    Args:
        operators ([str]):
            Operators to remove from the index image.
        arch ([str]):
            Architectures to build the index image for.
        index_image (str):
            Index image to remove the operators from.
        signing_keys (str):
            Signing keys to be used.
        hub (HubProxy):
            Instance of XMLRPC pub-hub proxy.
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
        target_name (str):
            Name of the target.
    """
    image_schema_tag = "{host}/{namespace}/{repo}:{tag}"
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_remove_operators(
        operators=operators,
        archs=archs,
        index_image=index_image,
        build_tags=["{0}-{1}".format(index_image.split(":")[1], task_id)],
        target_settings=target_settings,
    )

    if not build_details:
        sys.exit(1)
    _, tag = build_details.index_image.split(":", 1)
    index_stamp = timestamp()
    iib_namespace = target_settings.get(
        "quay_operator_namespace", target_settings["quay_namespace"]
    )
    quay_client = QuayClient(
        target_settings["dest_quay_user"], target_settings["dest_quay_password"], "quay.io"
    )
    item_processor = item_processor_for_internal_data(
        quay_client,
        target_settings["quay_host"].rstrip("/"),
        target_settings.get("retry_sleep_time", 5),
        iib_namespace,
    )
    # Remove operators task doesn't work with pushitem so we create VirtualPushItem to enable
    # existing code for fetching needed data.
    vitem = VirtualPushItem(
        metadata={"tags": {target_settings["quay_operator_repository"]: tag}},
        repos={target_settings["quay_operator_repository"]: [tag]},
    )
    existing_manifests = item_processor.generate_existing_manifests_metadata(vitem)
    outdated_manifests = []
    for ref, tag, man_arch_dig in existing_manifests:
        if man_arch_dig.arch in ("amd64", "x86_64"):
            outdated_manifests.append((man_arch_dig.digest, tag, ref))

    current_signatures = _sign_index_image(
        build_details.internal_index_image_copy_resolved,
        iib_namespace,
        [tag, f"{tag}-{index_stamp}"],
        signing_keys,
        task_id,
        target_settings,
    )
    iib_namespace = target_settings.get(
        "quay_operator_namespace", target_settings["quay_namespace"]
    )
    dest_image = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=iib_namespace,
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag=tag,
    )

    dest_image_stamp = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings.get("quay_operator_namespace", target_settings["quay_namespace"]),
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag="%s-%s" % (tag, index_stamp),
    )

    # Push image to Quay
    # Copy target settings and override username and password for quay_operator_namespace
    index_image_ts = target_settings.copy()
    index_image_ts["dest_quay_user"] = index_image_ts.get(
        "index_image_quay_user", index_image_ts["dest_quay_user"]
    )
    index_image_ts["dest_quay_password"] = index_image_ts.get(
        "index_image_quay_password", index_image_ts["dest_quay_password"]
    )

    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, index_image_ts
    )

    iib_feed, iib_namespace, iib_intermediate_repo = parse_index_image(build_details)
    # Permanent index image with proxy as a host must be used because skopeo cannot handle
    # login to two Quay namespaces at the same time
    permanent_index_image_proxy = image_schema_tag.format(
        host=iib_feed,
        namespace=iib_namespace,
        repo=iib_intermediate_repo,
        tag=build_details.build_tags[0],
    )
    ContainerImagePusher.run_tag_images(
        permanent_index_image_proxy, [dest_image_stamp], True, index_image_ts
    )

    _remove_index_image_signatures(outdated_manifests, current_signatures, target_settings)


def task_iib_build_from_scratch(
    bundles, archs, index_image_tag, signing_keys, hub, task_id, target_settings, target_name
):
    """
    Perform all the necessary actions for the 'PushIIBBuildFromScratch' entrypoint.

    Args:
        bundles ([str]):
            Bundles to add to the index image.
        archs ([str]):
            Architectures to build the index image for.
        index_image_tag (str):
            Tag to be applied to the new index image.
        signing_keys (str):
            Signing keys to be used.
        hub (HubProxy):
            Instance of XMLRPC pub-hub proxy.
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
        target_name (str):
            Name of the target.
    """
    image_schema_tag = "{host}/{namespace}/{repo}:{tag}"
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_add_bundles(
        bundles=bundles,
        archs=archs,
        build_tags=["{0}-{1}".format(index_image_tag, task_id)],
        target_settings=target_settings,
    )
    if not build_details:
        sys.exit(1)
    _, tag = build_details.index_image.split(":", 1)
    index_stamp = timestamp()
    iib_namespace = target_settings.get(
        "quay_operator_namespace", target_settings["quay_namespace"]
    )
    quay_client = QuayClient(
        target_settings["dest_quay_user"], target_settings["dest_quay_password"], "quay.io"
    )
    item_processor = item_processor_for_internal_data(
        quay_client,
        target_settings["quay_host"].rstrip("/"),
        target_settings.get("retry_sleep_time", 5),
        iib_namespace,
    )
    # Build from scratch task doesn't work with pushitem so we create VirtualPushItem to enable
    # existing code for fetching needed data.
    vitem = VirtualPushItem(
        metadata={"tags": {target_settings["quay_operator_repository"]: [tag]}},
        repos={target_settings["quay_operator_repository"]: [tag]},
    )
    existing_manifests = item_processor.generate_existing_manifests_metadata(vitem)
    outdated_manifests = []
    for ref, tag, man_arch_dig in existing_manifests:
        if man_arch_dig.arch in ("amd64", "x86_64"):
            outdated_manifests.append((man_arch_dig.digest, tag, ref))
    current_signatures = _sign_index_image(
        build_details.internal_index_image_copy_resolved,
        iib_namespace,
        [tag, f"{tag}-{index_stamp}"],
        signing_keys,
        task_id,
        target_settings,
    )

    iib_namespace = target_settings.get(
        "quay_operator_namespace", target_settings["quay_namespace"]
    )
    dest_image = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=iib_namespace,
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag=tag,
    )
    dest_image_stamp = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings.get("quay_operator_namespace", target_settings["quay_namespace"]),
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag="%s-%s" % (tag, index_stamp),
    )
    iib_namespace = target_settings.get(
        "quay_operator_namespace", target_settings["quay_namespace"]
    )

    # Push image to Quay
    # Copy target settings and override username and password for quay_operator_namespace
    index_image_ts = target_settings.copy()
    index_image_ts["dest_quay_user"] = index_image_ts.get(
        "index_image_quay_user", index_image_ts["dest_quay_user"]
    )
    index_image_ts["dest_quay_password"] = index_image_ts.get(
        "index_image_quay_password", index_image_ts["dest_quay_password"]
    )
    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, index_image_ts
    )
    iib_feed, iib_namespace, iib_intermediate_repo = parse_index_image(build_details)
    # Permanent index image with proxy as a host must be used because skopeo cannot handle
    # login to two Quay namespaces at the same time
    permanent_index_image_proxy = image_schema_tag.format(
        host=iib_feed,
        namespace=iib_namespace,
        repo=iib_intermediate_repo,
        tag=build_details.build_tags[0],
    )
    ContainerImagePusher.run_tag_images(
        permanent_index_image_proxy, [dest_image_stamp], True, index_image_ts
    )
    _remove_index_image_signatures(outdated_manifests, current_signatures, target_settings)


def iib_add_entrypoint(
    bundles,
    archs,
    index_image,
    deprecation_list,
    signing_keys,
    hub,
    task_id,
    target_settings,
    target_name,
):
    """Entry point for use in another python code."""
    task_iib_add_bundles(
        bundles,
        archs,
        index_image,
        deprecation_list,
        signing_keys,
        hub,
        task_id,
        target_settings,
        target_name,
    )


def iib_remove_entrypoint(
    operators, archs, index_image, signing_keys, hub, task_id, target_settings, target_name
):
    """Entry point for use in another python code."""
    task_iib_remove_operators(
        operators, archs, index_image, signing_keys, hub, task_id, target_settings, target_name
    )


def iib_from_scratch_entrypoint(
    bundles, archs, index_image_tag, signing_keys, hub, task_id, target_settings, target_name
):
    """Entry point for use in another python code."""
    task_iib_build_from_scratch(
        bundles, archs, index_image_tag, signing_keys, hub, task_id, target_settings, target_name
    )
