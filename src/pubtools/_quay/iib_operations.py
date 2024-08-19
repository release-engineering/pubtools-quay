import json
import logging
import sys
from typing import Any, List, Tuple, cast, Dict

from .container_image_pusher import ContainerImagePusher
from .exceptions import InvalidTargetSettings
from .operator_pusher import OperatorPusher

from .utils.misc import (
    get_internal_container_repo_name,
    timestamp,
    parse_index_image,
    set_aws_kms_environment_variables,
)
from .signer_wrapper import SIGNER_BY_LABEL
from .item_processor import (
    VirtualPushItem,
    SignEntry,
    item_processor_for_internal_data,
)

from .quay_client import QuayClient
from .types import ManifestList

LOG = logging.getLogger("pubtools.quay")


def verify_target_settings(target_settings: Dict[str, Any]) -> None:
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


def _get_operator_quay_client(target_settings: Dict[str, Any]) -> QuayClient:
    """Create and access QuayClient for src index image."""
    index_image_credential = target_settings["iib_overwrite_from_index_token"].split(":")
    return QuayClient(
        index_image_credential[0],
        index_image_credential[1],
        target_settings.get("quay_host", "quay.io").rstrip("/"),
    )


def _index_image_to_sign_entries(
    src_index_image: str,
    dest_tags: List[str],
    signing_keys: List[str],
    target_settings: Dict[str, Any],
    internal: bool = False,
) -> List[SignEntry]:
    """Generate entries to sign.

    Method generates sign entries for index image with <dest_tags> tags
    and given signing_keys. Only manifests with architecture amd64 are included in the output.

    Args:
        src_index_image (str): Source index image.
        dest_tags (List[str]): Destination tags.
        index_stamp (str): Index stamp.
        signing_keys (list): List of signing keys.
        internal (bool): indicates if to sign registries should be generated with iternal/external
            reference
    """
    iib_repo = target_settings["quay_operator_repository"]
    pub_iib_repo = target_settings["quay_operator_repository"]
    dest_registries = target_settings["docker_settings"]["docker_reference_registry"]
    dest_registries = dest_registries if isinstance(dest_registries, list) else [dest_registries]
    if internal:
        iib_repo = (
            target_settings.get("quay_operator_namespace", target_settings["quay_namespace"])
            + "/"
            + get_internal_container_repo_name(iib_repo)
        )

    dest_operator_quay_client = _get_operator_quay_client(target_settings)
    ret = cast(
        Tuple[str, Dict[str, str]],
        dest_operator_quay_client.get_manifest(
            src_index_image, media_type=QuayClient.MANIFEST_LIST_TYPE, return_headers=True, raw=True
        ),
    )
    manifest_list_str, headers = ret
    manifest_list = cast(ManifestList, json.loads(manifest_list_str))

    index_image_digests = [
        m["digest"]
        for m in manifest_list["manifests"]
        if m["platform"]["architecture"] in ["amd64", "x86_64"]
    ]
    to_sign_entries = []
    # if signing external images, sign also manifest list
    if internal:
        for _dest_tag in dest_tags:
            for registry in dest_registries:
                for key in signing_keys:
                    to_sign_entries.append(
                        SignEntry(
                            reference=f"quay.io/{iib_repo}:{_dest_tag}",
                            pub_reference=f"{registry}/{pub_iib_repo}:{_dest_tag}",
                            repo=iib_repo,
                            digest=headers["docker-content-digest"],
                            arch="amd64",
                            signing_key=key,
                        )
                    )

    for registry in dest_registries:
        for _dest_tag in dest_tags:
            for digest in index_image_digests:
                if internal:
                    reference = f"quay.io/{iib_repo}:{_dest_tag}"
                else:
                    reference = f"{registry}/{iib_repo}:{_dest_tag}"
                for key in signing_keys:
                    to_sign_entries.append(
                        SignEntry(
                            reference=reference,
                            pub_reference=f"{registry}/{pub_iib_repo}:{_dest_tag}",
                            repo=iib_repo,
                            digest=digest,
                            arch="amd64",
                            signing_key=key,
                        )
                    )
    return to_sign_entries


def _remove_index_image_signatures(
    outdated_manifests: List[Tuple[str, str, str]],
    current_signatures: List[Tuple[str, str, str]],
    target_settings: Dict[str, Any],
) -> None:
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
    built_index_image: str,
    dest_tags: List[str],
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
    pre_push: bool = False,
) -> List[Tuple[str, str, str]]:
    """Sign index image with configured signers for the target.

    Args:
        built_index_image (str): Index image built results.
        dest_tags (List[str]): Destination tag.
        signing_keys (list): List of signing keys.
        task_id (str): Task ID.
        target_settings (dict): Target settings.
        pre_push (bool): Whether to sign before push.
    Returns:
        list: List of current signatures.
    """
    to_sign_entries = _index_image_to_sign_entries(
        built_index_image, dest_tags, signing_keys, target_settings, internal=not pre_push
    )
    current_signatures: List[Tuple[str, str, str]] = [
        (e.reference, e.digest, e.signing_key) for e in to_sign_entries
    ]
    set_aws_kms_environment_variables(target_settings, "cosign_signer")
    for signer in target_settings["signing"]:
        if signer["enabled"] and SIGNER_BY_LABEL[signer["label"]].pre_push == pre_push:
            signercls = SIGNER_BY_LABEL[signer["label"]]
            signer = signercls(config_file=signer["config_file"], settings=target_settings)
            signer.sign_containers(to_sign_entries, task_id=task_id)
    return current_signatures


def _sign_and_push(
    build_details: Any,
    tag: str,
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
    index_stamp = timestamp()
    quay_operator_namespace = target_settings.get(
        "quay_operator_namespace", target_settings["quay_namespace"]
    )
    # Copy target settings and override username and password for quay_operator_namespace
    index_image_ts = target_settings.copy()
    index_image_ts["dest_quay_user"] = index_image_ts.get(
        "index_image_quay_user", index_image_ts["dest_quay_user"]
    )
    index_image_ts["dest_quay_password"] = index_image_ts.get(
        "index_image_quay_password", index_image_ts["dest_quay_password"]
    )
    quay_client = QuayClient(
        index_image_ts["dest_quay_user"], index_image_ts["dest_quay_password"], "quay.io"
    )
    item_processor = item_processor_for_internal_data(
        quay_client,
        target_settings["quay_host"].rstrip("/"),
        target_settings["docker_settings"]["docker_reference_registry"],
        target_settings.get("retry_sleep_time", 5),
        quay_operator_namespace,
    )
    item_processor.extractor.full_extract = True

    # IIB task doesn't work with pushitem so we create VirtualPushItem to enable
    # existing code for fetching needed data.
    vitem = VirtualPushItem(
        metadata={"tags": {target_settings["quay_operator_repository"]: [tag]}},
        repos={target_settings["quay_operator_repository"]: [tag]},
    )
    existing_manifests = item_processor.generate_existing_manifests_metadata(vitem)
    outdated_manifests = []
    for ref, _tag, man_arch_dig in existing_manifests:
        if not man_arch_dig:
            continue
        outdated_manifests.append((man_arch_dig.digest, _tag, ref))

    # pre push sign
    current_signatures = _sign_index_image(
        build_details.internal_index_image_copy_resolved,
        [tag, f"{tag}-{index_stamp}"],
        signing_keys,
        task_id,
        target_settings,
        pre_push=True,
    )
    image_schema_tag = "{host}/{namespace}/{repo}:{tag}"
    dest_image = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=quay_operator_namespace,
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag=tag,
    )
    dest_image_stamp = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=quay_operator_namespace,
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag="%s-%s" % (tag, index_stamp),
    )

    # Push image to Quay
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

    # after push sign
    _sign_index_image(
        build_details.internal_index_image_copy_resolved,
        [tag, f"{tag}-{index_stamp}"],
        signing_keys,
        task_id,
        target_settings,
        pre_push=False,
    )
    _remove_index_image_signatures(outdated_manifests, current_signatures, target_settings)


def task_iib_add_bundles(
    bundles: List[str],
    archs: List[str],
    index_image: str,
    deprecation_list: List[str],
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
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
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
    verify_target_settings(target_settings)

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

    _sign_and_push(build_details, tag, signing_keys, task_id, target_settings)


def task_iib_remove_operators(
    operators: List[str],
    archs: List[str],
    index_image: str,
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
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
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
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

    _sign_and_push(build_details, tag, signing_keys, task_id, target_settings)


def task_iib_build_from_scratch(
    bundles: List[str],
    archs: List[str],
    index_image_tag: str,
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
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
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
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

    _sign_and_push(build_details, index_image_tag, signing_keys, task_id, target_settings)


def task_iib_add_deprecations(
    index_image: str,
    deprecation_schema: str,
    operator_package: str,
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
    """
    Perform all the necessary actions for the 'PushAddIIBDeprecations' entrypoint.

    Args:
        index_image (str):
            Index image to add the bundles to.
        deprecation_schema (str):
            JSON formatted deprecation schema.
        operator_package (str):
            Operator package to add deprecations to.
        signing_keys ([str]):
            Signing keys to be used.
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_add_deprecations(
        index_image=index_image,
        deprecation_schema=deprecation_schema,
        operator_package=operator_package,
        build_tags=["{0}-{1}".format(index_image.split(":")[1], task_id)],
        target_settings=target_settings,
    )
    if not build_details:
        sys.exit(1)
    _, tag = build_details.index_image.split(":", 1)

    _sign_and_push(build_details, tag, signing_keys, task_id, target_settings)


def iib_add_entrypoint(
    bundles: List[str],
    archs: List[str],
    index_image: str,
    deprecation_list: List[str],
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
    """Entry point for use in another python code."""
    task_iib_add_bundles(
        bundles,
        archs,
        index_image,
        deprecation_list,
        signing_keys,
        task_id,
        target_settings,
    )


def iib_remove_entrypoint(
    operators: List[str],
    archs: List[str],
    index_image: str,
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
    """Entry point for use in another python code."""
    task_iib_remove_operators(operators, archs, index_image, signing_keys, task_id, target_settings)


def iib_from_scratch_entrypoint(
    bundles: List[str],
    archs: List[str],
    index_image_tag: str,
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
    """Entry point for use in another python code."""
    task_iib_build_from_scratch(
        bundles, archs, index_image_tag, signing_keys, task_id, target_settings
    )


def iib_add_deprecations_entrypoint(
    index_image: str,
    deprecation_schema: str,
    operator_package: str,
    signing_keys: List[str],
    task_id: str,
    target_settings: Dict[str, Any],
) -> None:
    """Entry point for use in another python code."""
    task_iib_add_deprecations(
        index_image,
        deprecation_schema,
        operator_package,
        signing_keys,
        task_id,
        target_settings,
    )
