import logging

from .container_image_pusher import ContainerImagePusher
from .exceptions import InvalidTargetSettings
from .operator_pusher import OperatorPusher
from .signature_handler import OperatorSignatureHandler
from .utils.misc import get_internal_container_repo_name

LOG = logging.getLogger("PubLogger")
LOG.setLevel(logging.INFO)


def verify_target_settings(target_settings):
    """
    Verify the presence and validity of target settings.

    Args:
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
    LOG.info("Verifying the necessary target settings")

    required_settings = [
        "quay_user",
        "quay_password",
        "quay_api_token",
        "pyxis_server",
        "quay_namespace",
        "iib_krb_principal",
        "iib_index_image",
        "quay_operator_repository",
        "ssh_remote_host",
        "ssh_user",
        "ssh_password",
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
    bundles, archs, index_image, deprecation_list, signing_key, hub, task_id, target_settings
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
        signing_key (str):
            Signing key to be used.
        hub (HubProxy):
            Instance of XMLRPC pub-hub proxy.
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
    image_schema = "{host}/{namespace}/{repo}"
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_add_bundles(
        bundles=bundles,
        archs=archs,
        index_image=index_image,
        deprecation_list=deprecation_list,
        target_settings=target_settings,
    )

    # Push image to Quay
    index_image_repo = image_schema.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings["quay_namespace"],
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
    )
    # TODO: how is tag set? Do we derive it from source or destination index image?
    _, tag = build_details.index_image.split(":", 1)
    dest_image = "{0}:{1}".format(index_image_repo, tag)

    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, target_settings
    )

    # Sign image
    sig_handler = OperatorSignatureHandler(hub, task_id, target_settings)
    sig_handler.sign_task_index_image(build_details, signing_key, dest_image)


def task_iib_remove_operators(
    operators, archs, index_image, signing_key, hub, task_id, target_settings
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
        signing_key (str):
            Signing key to be used.
        hub (HubProxy):
            Instance of XMLRPC pub-hub proxy.
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
    image_schema = "{host}/{namespace}/{repo}"
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_remove_operators(
        operators=operators,
        archs=archs,
        index_image=index_image,
        target_settings=target_settings,
    )

    # Push image to Quay
    index_image_repo = image_schema.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings["quay_namespace"],
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
    )
    # TODO: how is tag set? Do we derive it from source or destination index image?
    _, tag = build_details.index_image.split(":", 1)
    dest_image = "{0}:{1}".format(index_image_repo, tag)

    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, target_settings
    )

    # Sign image
    sig_handler = OperatorSignatureHandler(hub, task_id, target_settings)
    sig_handler.sign_task_index_image(build_details, signing_key, dest_image)


def task_iib_build_from_scratch(
    bundles, archs, index_image_tag, signing_key, hub, task_id, target_settings
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
        signing_key (str):
            Signing key to be used.
        hub (HubProxy):
            Instance of XMLRPC pub-hub proxy.
        task_id (str):
            ID of the pub task.
        target_settings (dict):
            Dictionary containing settings necessary for performing the operation.
    """
    image_schema = "{host}/{namespace}/{repo}"
    verify_target_settings(target_settings)

    # Build new index image in IIB
    build_details = OperatorPusher.iib_add_bundles(
        bundles=bundles,
        archs=archs,
        target_settings=target_settings,
    )

    # Push image to Quay
    index_image_repo = image_schema.format(
        host=target_settings.get("quay_host", "quay.io").rstrip("/"),
        namespace=target_settings["quay_namespace"],
        repo=get_internal_container_repo_name(target_settings["quay_operator_repository"]),
    )
    dest_image = "{0}:{1}".format(index_image_repo, index_image_tag)

    ContainerImagePusher.run_tag_images(
        build_details.index_image, [dest_image], True, target_settings
    )

    # Sign image
    sig_handler = OperatorSignatureHandler(hub, task_id, target_settings)
    sig_handler.sign_task_index_image(build_details, signing_key, dest_image)


def iib_add_entrypoint(
    bundles, archs, index_image, deprecation_list, signing_key, hub, task_id, target_settings
):
    """Entry point for use in another python code."""
    task_iib_add_bundles(
        bundles, archs, index_image, deprecation_list, signing_key, hub, task_id, target_settings
    )


def iib_remove_entrypoint(
    operators, archs, index_image, signing_key, hub, task_id, target_settings
):
    """Entry point for use in another python code."""
    task_iib_remove_operators(
        operators, archs, index_image, signing_key, hub, task_id, target_settings
    )


def iib_from_scratch_entrypoint(
    bundles, archs, index_image_tag, signing_key, hub, task_id, target_settings
):
    """Entry point for use in another python code."""
    task_iib_build_from_scratch(
        bundles, archs, index_image_tag, signing_key, hub, task_id, target_settings
    )
