import mock
import pytest

from pubtools._quay import exceptions
from pubtools._quay import iib_operations
from .utils.misc import IIBRes


def test_verify_target_settings_success(target_settings):
    iib_operations.verify_target_settings(target_settings)


def test_verify_target_settings_missing_setting(target_settings):
    target_settings.pop("dest_quay_user")
    with pytest.raises(
        exceptions.InvalidTargetSettings, match="'dest_quay_user' must be present.*"
    ):
        iib_operations.verify_target_settings(target_settings)


def test_verify_target_settings_missing_docker_setting(target_settings):
    target_settings["docker_settings"].pop("umb_urls")
    with pytest.raises(
        exceptions.InvalidTargetSettings,
        match="'umb_urls' must be present in the docker settings.*",
    ):
        iib_operations.verify_target_settings(target_settings)


@mock.patch("pubtools._quay.iib_operations.SignatureRemover")
@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
@mock.patch("pubtools._quay.iib_operations.timestamp")
def test_task_iib_add_bundles(
    mock_timestamp,
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_operator_signature_handler,
    mock_signature_remover,
    target_settings,
    fake_cert_key_paths,
):
    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    mock_iib_add_bundles.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_sign_task_index_image.return_value = [{"claim": "value1"}, {"claim": "value2"}]
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_get_index_image_signatures = mock.MagicMock()
    mock_get_index_image_signatures.return_value = [
        {
            "signature": "value1",
            "_id": "1",
            "reference": "some-registry.com/redhat-namespace/old-index-image:5",
            "repository": "image-repo",
            "manifest_digest": "sha256:a1a1a1",
            "sig_key_id": "sig-key",
        },
        {
            "signature": "value2",
            "_id": "2",
            "reference": "some-registry.com/redhat-namespace/old-index-image:5",
            "repository": "image-repo",
            "manifest_digest": "sha256:b2b2b2",
            "sig_key_id": "sig-key",
        },
    ]
    mock_signature_remover.return_value.get_index_image_signatures = mock_get_index_image_signatures

    mock_remove_signatures_from_pyxis = mock.MagicMock()
    mock_signature_remover.return_value.remove_signatures_from_pyxis = (
        mock_remove_signatures_from_pyxis
    )

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_add_bundles(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/redhat-namespace/new-index-image:5",
        ["bundle3", "bundle4"],
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/redhat-namespace/new-index-image:5",
        deprecation_list=["bundle3", "bundle4"],
        build_tags=["5-1"],
        target_settings=target_settings,
    )
    assert mock_run_tag_images.call_count == 2
    assert mock_run_tag_images.call_args_list[0] == mock.call(
        "some-registry.com/iib-namespace/new-index-image:8",
        [
            "quay.io/some-namespace/operators----index-image:8",
        ],
        True,
        target_settings,
    )
    assert mock_run_tag_images.call_args_list[1] == mock.call(
        "some-registry.com/iib-namespace/iib:8-1",
        [
            "quay.io/some-namespace/operators----index-image:8-timestamp",
        ],
        True,
        target_settings,
    )

    mock_operator_signature_handler.assert_called_once_with(
        mock_hub, "1", target_settings, "some-target"
    )
    mock_sign_task_index_image.assert_called_once_with(
        ["some-key"], "quay.io/iib-namespace/iib:8-1", ["8", "8-timestamp"]
    )

    mock_signature_remover.assert_called_once_with(
        quay_api_token="dest-quay-token", quay_user="dest-quay-user", quay_password="dest-quay-pass"
    )
    mock_get_index_image_signatures.assert_called_once_with(
        "quay.io/some-namespace/operators----index-image:8",
        [{"claim": "value1"}, {"claim": "value2"}],
        "pyxis-url.com",
        "/path/to/file.crt",
        "/path/to/file.key",
    )
    mock_remove_signatures_from_pyxis.assert_called_once_with(
        ["1", "2"], "pyxis-url.com", "/path/to/file.crt", "/path/to/file.key", 7
    )


@mock.patch("pubtools._quay.iib_operations.SignatureRemover")
@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
@mock.patch("pubtools._quay.iib_operations.timestamp")
def test_task_iib_add_bundles_operator_ns(
    mock_timestamp,
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_operator_signature_handler,
    mock_signature_remover,
    target_settings,
    fake_cert_key_paths,
):
    target_settings["quay_operator_namespace"] = "operator-ns"

    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    mock_iib_add_bundles.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_sign_task_index_image.return_value = [{"claim": "value1"}, {"claim": "value2"}]
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_get_index_image_signatures = mock.MagicMock()
    mock_get_index_image_signatures.return_value = [
        {
            "signature": "value1",
            "_id": "1",
            "reference": "some-registry.com/redhat-namespace/old-index-image:5",
            "repository": "image-repo",
            "manifest_digest": "sha256:a1a1a1",
            "sig_key_id": "sig-key",
        },
        {
            "signature": "value2",
            "_id": "2",
            "reference": "some-registry.com/redhat-namespace/old-index-image:5",
            "repository": "image-repo",
            "manifest_digest": "sha256:b2b2b2",
            "sig_key_id": "sig-key",
        },
    ]
    mock_signature_remover.return_value.get_index_image_signatures = mock_get_index_image_signatures

    mock_remove_signatures_from_pyxis = mock.MagicMock()
    mock_signature_remover.return_value.remove_signatures_from_pyxis = (
        mock_remove_signatures_from_pyxis
    )

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_add_bundles(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/redhat-namespace/new-index-image:5",
        ["bundle3", "bundle4"],
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/redhat-namespace/new-index-image:5",
        deprecation_list=["bundle3", "bundle4"],
        build_tags=["5-1"],
        target_settings=target_settings,
    )
    assert mock_run_tag_images.call_count == 2
    assert mock_run_tag_images.call_args_list[0] == mock.call(
        "some-registry.com/iib-namespace/new-index-image:8",
        [
            "quay.io/operator-ns/operators----index-image:8",
        ],
        True,
        target_settings,
    )
    assert mock_run_tag_images.call_args_list[1] == mock.call(
        "some-registry.com/iib-namespace/iib:8-1",
        [
            "quay.io/operator-ns/operators----index-image:8-timestamp",
        ],
        True,
        target_settings,
    )

    mock_operator_signature_handler.assert_called_once_with(
        mock_hub, "1", target_settings, "some-target"
    )
    mock_sign_task_index_image.assert_called_once_with(
        ["some-key"], "quay.io/iib-namespace/iib:8-1", ["8", "8-timestamp"]
    )

    mock_signature_remover.assert_called_once_with(
        quay_api_token="dest-quay-token", quay_user="dest-quay-user", quay_password="dest-quay-pass"
    )
    mock_get_index_image_signatures.assert_called_once_with(
        "quay.io/operator-ns/operators----index-image:8",
        [{"claim": "value1"}, {"claim": "value2"}],
        "pyxis-url.com",
        "/path/to/file.crt",
        "/path/to/file.key",
    )
    mock_remove_signatures_from_pyxis.assert_called_once_with(
        ["1", "2"], "pyxis-url.com", "/path/to/file.crt", "/path/to/file.key", 7
    )


@mock.patch("pubtools._quay.iib_operations.SignatureRemover")
@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_remove_operators")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
@mock.patch("pubtools._quay.iib_operations.timestamp")
def test_task_iib_remove_operators(
    mock_timestamp,
    mock_verify_target_settings,
    mock_iib_remove_operators,
    mock_run_tag_images,
    mock_operator_signature_handler,
    mock_signature_remover,
    target_settings,
    fake_cert_key_paths,
):
    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    mock_iib_remove_operators.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_sign_task_index_image.return_value = [{"claim": "value1"}, {"claim": "value2"}]
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_get_index_image_signatures = mock.MagicMock()
    mock_get_index_image_signatures.return_value = [
        {
            "signature": "value1",
            "_id": "1",
            "reference": "some-registry.com/redhat-namespace/old-index-image:5",
            "repository": "image-repo",
            "manifest_digest": "sha256:a1a1a1",
            "sig_key_id": "sig-key",
        },
        {
            "signature": "value2",
            "_id": "2",
            "reference": "some-registry.com/redhat-namespace/old-index-image:5",
            "repository": "image-repo",
            "manifest_digest": "sha256:b2b2b2",
            "sig_key_id": "sig-key",
        },
    ]
    mock_signature_remover.return_value.get_index_image_signatures = mock_get_index_image_signatures

    mock_remove_signatures_from_pyxis = mock.MagicMock()
    mock_signature_remover.return_value.remove_signatures_from_pyxis = (
        mock_remove_signatures_from_pyxis
    )

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_remove_operators(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/redhat-namespace/new-index-image:5",
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_remove_operators.assert_called_once_with(
        operators=["operator1", "operator2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/redhat-namespace/new-index-image:5",
        build_tags=["5-1"],
        target_settings=target_settings,
    )
    assert mock_run_tag_images.call_count == 2
    assert mock_run_tag_images.call_args_list[0] == mock.call(
        "some-registry.com/iib-namespace/new-index-image:8",
        [
            "quay.io/some-namespace/operators----index-image:8",
        ],
        True,
        target_settings,
    )
    assert mock_run_tag_images.call_args_list[1] == mock.call(
        "some-registry.com/iib-namespace/iib:8-1",
        [
            "quay.io/some-namespace/operators----index-image:8-timestamp",
        ],
        True,
        target_settings,
    )
    mock_operator_signature_handler.assert_called_once_with(
        mock_hub, "1", target_settings, "some-target"
    )
    mock_sign_task_index_image.assert_called_once_with(
        ["some-key"], "quay.io/iib-namespace/iib:8-1", ["8", "8-timestamp"]
    )

    mock_signature_remover.assert_called_once_with(
        quay_api_token="dest-quay-token", quay_user="dest-quay-user", quay_password="dest-quay-pass"
    )
    mock_get_index_image_signatures.assert_called_once_with(
        "quay.io/some-namespace/operators----index-image:8",
        [{"claim": "value1"}, {"claim": "value2"}],
        "pyxis-url.com",
        "/path/to/file.crt",
        "/path/to/file.key",
    )
    mock_remove_signatures_from_pyxis.assert_called_once_with(
        ["1", "2"], "pyxis-url.com", "/path/to/file.crt", "/path/to/file.key", 7
    )


@mock.patch("pubtools._quay.iib_operations.SignatureRemover")
@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_remove_operators")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
@mock.patch("pubtools._quay.iib_operations.timestamp")
def test_task_iib_remove_operators_operator_ns(
    mock_timestamp,
    mock_verify_target_settings,
    mock_iib_remove_operators,
    mock_run_tag_images,
    mock_operator_signature_handler,
    mock_signature_remover,
    target_settings,
    fake_cert_key_paths,
):
    target_settings["quay_operator_namespace"] = "operator-ns"

    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    mock_iib_remove_operators.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_sign_task_index_image.return_value = [{"claim": "value1"}, {"claim": "value2"}]
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_get_index_image_signatures = mock.MagicMock()
    mock_get_index_image_signatures.return_value = [
        {
            "signature": "value1",
            "_id": "1",
            "reference": "some-registry.com/redhat-namespace/old-index-image:5",
            "repository": "image-repo",
            "manifest_digest": "sha256:a1a1a1",
            "sig_key_id": "sig-key",
        },
        {
            "signature": "value2",
            "_id": "2",
            "reference": "some-registry.com/redhat-namespace/old-index-image:5",
            "repository": "image-repo",
            "manifest_digest": "sha256:b2b2b2",
            "sig_key_id": "sig-key",
        },
    ]
    mock_signature_remover.return_value.get_index_image_signatures = mock_get_index_image_signatures

    mock_remove_signatures_from_pyxis = mock.MagicMock()
    mock_signature_remover.return_value.remove_signatures_from_pyxis = (
        mock_remove_signatures_from_pyxis
    )

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_remove_operators(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/redhat-namespace/new-index-image:5",
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_remove_operators.assert_called_once_with(
        operators=["operator1", "operator2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/redhat-namespace/new-index-image:5",
        build_tags=["5-1"],
        target_settings=target_settings,
    )
    assert mock_run_tag_images.call_count == 2
    assert mock_run_tag_images.call_args_list[0] == mock.call(
        "some-registry.com/iib-namespace/new-index-image:8",
        [
            "quay.io/operator-ns/operators----index-image:8",
        ],
        True,
        target_settings,
    )
    assert mock_run_tag_images.call_args_list[1] == mock.call(
        "some-registry.com/iib-namespace/iib:8-1",
        [
            "quay.io/operator-ns/operators----index-image:8-timestamp",
        ],
        True,
        target_settings,
    )
    mock_operator_signature_handler.assert_called_once_with(
        mock_hub, "1", target_settings, "some-target"
    )
    mock_sign_task_index_image.assert_called_once_with(
        ["some-key"], "quay.io/iib-namespace/iib:8-1", ["8", "8-timestamp"]
    )

    mock_signature_remover.assert_called_once_with(
        quay_api_token="dest-quay-token", quay_user="dest-quay-user", quay_password="dest-quay-pass"
    )
    mock_get_index_image_signatures.assert_called_once_with(
        "quay.io/operator-ns/operators----index-image:8",
        [{"claim": "value1"}, {"claim": "value2"}],
        "pyxis-url.com",
        "/path/to/file.crt",
        "/path/to/file.key",
    )
    mock_remove_signatures_from_pyxis.assert_called_once_with(
        ["1", "2"], "pyxis-url.com", "/path/to/file.crt", "/path/to/file.key", 7
    )


@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
@mock.patch("pubtools._quay.iib_operations.timestamp")
def test_task_iib_build_from_scratch(
    mock_timestamp,
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_operator_signature_handler,
    target_settings,
):
    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    mock_iib_add_bundles.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_build_from_scratch(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        build_tags=["12-1"],
        target_settings=target_settings,
    )
    assert mock_run_tag_images.call_count == 2
    assert mock_run_tag_images.call_args_list[0] == mock.call(
        "some-registry.com/iib-namespace/new-index-image:8",
        [
            "quay.io/some-namespace/operators----index-image:12",
        ],
        True,
        target_settings,
    )
    assert mock_run_tag_images.call_args_list[1] == mock.call(
        "some-registry.com/iib-namespace/iib:8-1",
        [
            "quay.io/some-namespace/operators----index-image:12-timestamp",
        ],
        True,
        target_settings,
    )
    mock_operator_signature_handler.assert_called_once_with(
        mock_hub, "1", target_settings, "some-target"
    )
    mock_sign_task_index_image.assert_called_once_with(
        ["some-key"], "quay.io/iib-namespace/iib:8-1", ["12", "12-timestamp"]
    )


@mock.patch("pubtools._quay.iib_operations.OperatorSignatureHandler")
@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
@mock.patch("pubtools._quay.iib_operations.timestamp")
def test_task_iib_build_from_scratch_operator_ns(
    mock_timestamp,
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_operator_signature_handler,
    target_settings,
):
    target_settings["quay_operator_namespace"] = "operator-ns"
    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    mock_iib_add_bundles.return_value = build_details

    mock_sign_task_index_image = mock.MagicMock()
    mock_operator_signature_handler.return_value.sign_task_index_image = mock_sign_task_index_image

    mock_hub = mock.MagicMock()
    iib_operations.task_iib_build_from_scratch(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        build_tags=["12-1"],
        target_settings=target_settings,
    )
    assert mock_run_tag_images.call_count == 2
    assert mock_run_tag_images.call_args_list[0] == mock.call(
        "some-registry.com/iib-namespace/new-index-image:8",
        [
            "quay.io/operator-ns/operators----index-image:12",
        ],
        True,
        target_settings,
    )
    assert mock_run_tag_images.call_args_list[1] == mock.call(
        "some-registry.com/iib-namespace/iib:8-1",
        [
            "quay.io/operator-ns/operators----index-image:12-timestamp",
        ],
        True,
        target_settings,
    )
    mock_operator_signature_handler.assert_called_once_with(
        mock_hub, "1", target_settings, "some-target"
    )
    mock_sign_task_index_image.assert_called_once_with(
        ["some-key"], "quay.io/iib-namespace/iib:8-1", ["12", "12-timestamp"]
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_add_bundles")
def test_iib_add_entrypoint(mock_add_bundles, target_settings):
    mock_hub = mock.MagicMock()
    iib_operations.iib_add_entrypoint(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["bundle3", "bundle4"],
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_add_bundles.assert_called_once_with(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["bundle3", "bundle4"],
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_remove_operators")
def test_iib_remove_entrypoint(mock_remove_operators, target_settings):
    mock_hub = mock.MagicMock()
    iib_operations.iib_remove_entrypoint(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_remove_operators.assert_called_once_with(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_build_from_scratch")
def test_iib_from_scratch_entrypoint(mock_build_from_scratch, target_settings):
    mock_hub = mock.MagicMock()
    iib_operations.iib_from_scratch_entrypoint(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )

    mock_build_from_scratch.assert_called_once_with(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        ["some-key"],
        mock_hub,
        "1",
        target_settings,
        "some-target",
    )


@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
def test_task_iib_add_bundles_fail(mock_iib_add_bundles, target_settings):
    mock_iib_add_bundles.return_value = False
    mock_hub = mock.MagicMock()
    with pytest.raises(SystemExit):
        iib_operations.task_iib_add_bundles(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:5",
            ["bundle3", "bundle4"],
            ["some-key"],
            mock_hub,
            "1",
            target_settings,
            "some-target",
        )


@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_remove_operators")
def test_task_iib_remove_operators_fail(mock_iib_remove_operators, target_settings):
    mock_iib_remove_operators.return_value = False
    mock_hub = mock.MagicMock()
    with pytest.raises(SystemExit):
        iib_operations.task_iib_remove_operators(
            ["operator1", "operator2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:5",
            ["some-key"],
            mock_hub,
            "1",
            target_settings,
            "some-target",
        )


@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
def test_task_iib_build_from_scratch_fail(mock_iib_add_bundles, target_settings):
    mock_iib_add_bundles.return_value = False
    mock_hub = mock.MagicMock()
    with pytest.raises(SystemExit):
        iib_operations.task_iib_build_from_scratch(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "12",
            ["some-key"],
            mock_hub,
            "1",
            target_settings,
            "some-target",
        )
