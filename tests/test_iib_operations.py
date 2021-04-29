import mock
import pytest

from pubtools._quay import exceptions
from pubtools._quay import iib_operations


def test_verify_target_settings_success(target_settings):
    iib_operations.verify_target_settings(target_settings)


def test_verify_target_settings_missing_setting(target_settings):
    target_settings.pop("quay_user")
    with pytest.raises(exceptions.InvalidTargetSettings, match="'quay_user' must be present.*"):
        iib_operations.verify_target_settings(target_settings)


def test_verify_target_settings_missing_docker_setting(target_settings):
    target_settings["docker_settings"].pop("umb_urls")
    with pytest.raises(
        exceptions.InvalidTargetSettings,
        match="'umb_urls' must be present in the docker settings.*",
    ):
        iib_operations.verify_target_settings(target_settings)


def test_verify_target_settings_overwrite_index_mismatch(target_settings):
    target_settings.pop("iib_overwrite_from_index_token")
    with pytest.raises(exceptions.InvalidTargetSettings, match="Either both or neither.*"):
        iib_operations.verify_target_settings(target_settings)


@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_add_bundles(
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_operator_signature_handler,
    target_settings,
):
    class IIBRes:
        def __init__(self, index_image):
            self.index_image = index_image

    build_details = IIBRes("some-registry.com/new-index-image:8")
    mock_iib_add_bundles.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_add_bundles(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["bundle3", "bundle4"],
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/index-image:5",
        deprecation_list=["bundle3", "bundle4"],
        target_settings=target_settings,
    )
    mock_run_tag_images.assert_called_once_with(
        "some-registry.com/new-index-image:8",
        ["quay.io/some-namespace/operators----index-image:8"],
        True,
        target_settings,
    )
    mock_operator_signature_handler.assert_called_once_with(mock_hub, "1", target_settings)
    mock_sign_task_index_image.assert_called_once_with(
        "some-key", "quay.io/some-namespace/iib:8", "8"
    )


@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_remove_operators")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_remove_operators(
    mock_verify_target_settings,
    mock_iib_remove_operators,
    mock_run_tag_images,
    mock_operator_signature_handler,
    target_settings,
):
    class IIBRes:
        def __init__(self, index_image):
            self.index_image = index_image

    build_details = IIBRes("some-registry.com/new-index-image:8")
    mock_iib_remove_operators.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_remove_operators(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_remove_operators.assert_called_once_with(
        operators=["operator1", "operator2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/index-image:5",
        target_settings=target_settings,
    )
    mock_run_tag_images.assert_called_once_with(
        "some-registry.com/new-index-image:8",
        ["quay.io/some-namespace/operators----index-image:8"],
        True,
        target_settings,
    )
    mock_operator_signature_handler.assert_called_once_with(mock_hub, "1", target_settings)
    mock_sign_task_index_image.assert_called_once_with(
        "some-key", "quay.io/some-namespace/iib:8", "8"
    )


@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_build_from_scratch(
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_operator_signature_handler,
    target_settings,
):
    class IIBRes:
        def __init__(self, index_image):
            self.index_image = index_image

    build_details = IIBRes("some-registry.com/new-index-image:8")
    mock_iib_add_bundles.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_build_from_scratch(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        target_settings=target_settings,
    )
    mock_run_tag_images.assert_called_once_with(
        "some-registry.com/new-index-image:8",
        ["quay.io/some-namespace/operators----index-image:12"],
        True,
        target_settings,
    )
    mock_operator_signature_handler.assert_called_once_with(mock_hub, "1", target_settings)
    mock_sign_task_index_image.assert_called_once_with(
        "some-key", "quay.io/some-namespace/iib:8", "12"
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_add_bundles")
def test_iib_add_entrypoint(mock_add_bundles, target_settings):
    mock_hub = mock.MagicMock()
    iib_operations.iib_add_entrypoint(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["bundle3", "bundle4"],
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )

    mock_add_bundles.assert_called_once_with(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["bundle3", "bundle4"],
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_remove_operators")
def test_iib_remove_entrypoint(mock_remove_operators, target_settings):
    mock_hub = mock.MagicMock()
    iib_operations.iib_remove_entrypoint(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )

    mock_remove_operators.assert_called_once_with(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_build_from_scratch")
def test_iib_from_scratch_entrypoint(mock_build_from_scratch, target_settings):
    mock_hub = mock.MagicMock()
    iib_operations.iib_from_scratch_entrypoint(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )

    mock_build_from_scratch.assert_called_once_with(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        "some-key",
        mock_hub,
        "1",
        target_settings,
    )
