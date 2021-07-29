import logging

from .container_image_pusher import ContainerImagePusher
from .exceptions import InvalidTargetSettings
from .operator_pusher import OperatorPusher
from .signature_handler import OperatorSignatureHandler
from .signature_remover import SignatureRemover
from .utils.misc import get_internal_container_repo_name

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
    if (
        "iib_overwrite_from_index_token" in target_settings
        and "iib_overwrite_from_index" not in target_settings
    ) or (
        "iib_overwrite_from_index_token" not in target_settings
        and "iib_overwrite_from_index" in target_settings
    ):
        msg = (
            "Either both or neither of 'iib_overwrite_from_index' and "
            "'iib_overwrite_from_index_token' should be specified in target settings."
        )
        LOG.error(msg)
        raise InvalidTargetSettings(msg)


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
    image_schema_digest = "{host}/{namespace}/{repo}@{digest}"
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_add_bundles(
        bundles=bundles,
        archs=archs,
        index_image=index_image,
        deprecation_list=deprecation_list,
        target_settings=target_settings,
    )

    _, tag = build_details.index_image.split(":", 1)
    dest_image = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings["quay_namespace"],
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag=tag,
    )
    # Index image used to fetch manifest list. This image will never be overwritten
    iib_namespace = build_details.index_image_resolved.split("/")[1]
    image_digest = build_details.index_image_resolved.split("@")[1]
    intermediate_index_image = image_schema_digest.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=iib_namespace,
        repo="iib",
        digest=image_digest,
    )

    # Sign image
    sig_handler = OperatorSignatureHandler(hub, task_id, target_settings, target_name)
    claim_messages = sig_handler.sign_task_index_image(signing_keys, intermediate_index_image, tag)

    sig_remover = SignatureRemover(
        quay_api_token=target_settings["dest_quay_api_token"],
        quay_user=target_settings["dest_quay_user"],
        quay_password=target_settings["dest_quay_password"],
    )
    old_signatures = sig_remover.get_index_image_signatures(
        dest_image,
        claim_messages,
        target_settings["pyxis_server"],
        target_settings["iib_krb_principal"],
        target_settings.get("iib_krb_ktfile", None),
    )

    # Push image to Quay
    # NOTE: tagging doesn't use intermediate index image, because we want the most up-to-date
    #       image to be copied to the destination
    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, target_settings
    )

    signature_ids = [s["_id"] for s in old_signatures]
    sig_remover.remove_signatures_from_pyxis(
        signature_ids,
        target_settings["pyxis_server"],
        target_settings["iib_krb_principal"],
        target_settings.get("iib_krb_ktfile", None),
    )


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
    image_schema_digest = "{host}/{namespace}/{repo}@{digest}"
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_remove_operators(
        operators=operators,
        archs=archs,
        index_image=index_image,
        target_settings=target_settings,
    )

    _, tag = build_details.index_image.split(":", 1)
    dest_image = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings["quay_namespace"],
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag=tag,
    )

    # Index image used to fetch manifest list. This image will never be overwritten
    iib_namespace = build_details.index_image_resolved.split("/")[1]
    image_digest = build_details.index_image_resolved.split("@")[1]
    intermediate_index_image = image_schema_digest.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=iib_namespace,
        repo="iib",
        digest=image_digest,
    )

    # Sign image
    sig_handler = OperatorSignatureHandler(hub, task_id, target_settings, target_name)
    claim_messages = sig_handler.sign_task_index_image(signing_keys, intermediate_index_image, tag)

    sig_remover = SignatureRemover(
        quay_api_token=target_settings["dest_quay_api_token"],
        quay_user=target_settings["dest_quay_user"],
        quay_password=target_settings["dest_quay_password"],
    )
    old_signatures = sig_remover.get_index_image_signatures(
        dest_image,
        claim_messages,
        target_settings["pyxis_server"],
        target_settings["iib_krb_principal"],
        target_settings.get("iib_krb_ktfile", None),
    )

    # Push image to Quay
    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, target_settings
    )

    signature_ids = [s["_id"] for s in old_signatures]
    sig_remover.remove_signatures_from_pyxis(
        signature_ids,
        target_settings["pyxis_server"],
        target_settings["iib_krb_principal"],
        target_settings.get("iib_krb_ktfile", None),
    )


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
    image_schema_digest = "{host}/{namespace}/{repo}@{digest}"
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_add_bundles(
        bundles=bundles,
        archs=archs,
        target_settings=target_settings,
    )

    dest_image = image_schema_tag.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings["quay_namespace"],
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
        tag=index_image_tag,
    )

    _, tag = build_details.index_image.split(":", 1)
    # Index image used to fetch manifest list. This image will never be overwritten
    iib_namespace = build_details.index_image_resolved.split("/")[1]
    image_digest = build_details.index_image_resolved.split("@")[1]
    intermediate_index_image = image_schema_digest.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=iib_namespace,
        repo="iib",
        digest=image_digest,
    )

    # Sign image
    sig_handler = OperatorSignatureHandler(hub, task_id, target_settings, target_name)
    sig_handler.sign_task_index_image(signing_keys, intermediate_index_image, index_image_tag)

    # Push image to Quay
    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, target_settings
    )


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
