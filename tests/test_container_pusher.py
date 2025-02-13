import copy
import logging
import mock
import pytest
import requests_mock
import requests

from pubtools._quay import exceptions
from pubtools._quay import quay_client
from pubtools._quay import container_image_pusher
from .utils.misc import sort_dictionary_sortable_values, compare_logs

# flake8: noqa: E501


@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_init(mock_quay_client, target_settings, container_multiarch_push_item):
    pusher = container_image_pusher.ContainerImagePusher(
        [container_multiarch_push_item], target_settings
    )

    assert pusher.push_items == [container_multiarch_push_item]
    assert pusher.target_settings == target_settings
    assert pusher.quay_host == "quay.io"
    mock_quay_client.assert_not_called()

    assert pusher.src_quay_client == mock_quay_client.return_value
    assert pusher.dest_quay_client == mock_quay_client.return_value
    assert mock_quay_client.call_args_list == [
        mock.call("src-quay-user", "src-quay-pass", "quay.io"),
        mock.call("dest-quay-user", "dest-quay-pass", "quay.io"),
    ]


@mock.patch("pubtools._quay.container_image_pusher.tag_images")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_tag_images(
    mock_quay_client,
    mock_tag_images,
    target_settings,
    container_multiarch_push_item,
):
    pusher = container_image_pusher.ContainerImagePusher(
        [container_multiarch_push_item], target_settings
    )

    pusher.run_tag_images(
        "source-ref:1", ["dest-ref:1", "dest-ref:2"], True, pusher.target_settings
    )
    mock_tag_images.assert_called_once_with(
        "source-ref:1",
        ["dest-ref:1", "dest-ref:2"],
        all_arch=True,
        quay_user="dest-quay-user",
        quay_password="dest-quay-pass",
        source_quay_host=None,
        source_quay_user="src-quay-user",
        source_quay_password="src-quay-pass",
        container_exec=True,
        container_image="registry.com/some/image:1",
        docker_url="unix://var/run/docker.sock",
        docker_timeout=None,
        docker_verify_tls=False,
        docker_cert_path=None,
        registry_username="quay-executor-user",
        registry_password="quay-executor-password",
    )


@mock.patch("time.sleep")
@mock.patch("pubtools._quay.container_image_pusher.tag_images")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_tag_images_retry(
    mock_quay_client,
    mock_tag_images,
    mock_sleep,
    target_settings,
    container_multiarch_push_item,
):
    mock_tag_images.side_effect = [RuntimeError, ValueError, 0]

    pusher = container_image_pusher.ContainerImagePusher(
        [container_multiarch_push_item], target_settings
    )

    pusher.run_tag_images(
        "source-ref:1", ["dest-ref:1", "dest-ref:2"], True, pusher.target_settings
    )

    tag_images_call = mock.call(
        "source-ref:1",
        ["dest-ref:1", "dest-ref:2"],
        all_arch=True,
        quay_user="dest-quay-user",
        quay_password="dest-quay-pass",
        source_quay_host=None,
        source_quay_user="src-quay-user",
        source_quay_password="src-quay-pass",
        container_exec=True,
        container_image="registry.com/some/image:1",
        docker_url="unix://var/run/docker.sock",
        docker_timeout=None,
        docker_verify_tls=False,
        docker_cert_path=None,
        registry_username="quay-executor-user",
        registry_password="quay-executor-password",
    )

    assert mock_tag_images.call_count == 3
    assert mock_tag_images.call_args_list[0] == tag_images_call
    assert mock_tag_images.call_args_list[1] == tag_images_call
    assert mock_tag_images.call_args_list[2] == tag_images_call


@mock.patch("pubtools._quay.container_image_pusher.tag_images")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_copy_src_item(
    mock_quay_client,
    mock_tag_images,
    target_settings,
    container_source_push_item,
):
    pusher = container_image_pusher.ContainerImagePusher(
        [container_source_push_item], target_settings
    )
    pusher.copy_source_push_item(container_source_push_item)
    mock_tag_images.assert_called_once_with(
        "some-registry/src/repo:2",
        [
            "quay.io/some-namespace/target----repo:latest-test-tag",
            "quay.io/some-namespace/target----repo:1.0",
        ],
        all_arch=True,
        quay_user="dest-quay-user",
        quay_password="dest-quay-pass",
        container_exec=True,
        container_image="registry.com/some/image:1",
        docker_url="unix://var/run/docker.sock",
        docker_timeout=None,
        docker_verify_tls=False,
        docker_cert_path=None,
        registry_username="quay-executor-user",
        registry_password="quay-executor-password",
        source_quay_host=None,
        source_quay_password="src-quay-pass",
        source_quay_user="src-quay-user",
    )


@mock.patch("pubtools._quay.container_image_pusher.tag_images")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_copy_v1_item(
    mock_quay_client,
    mock_tag_images,
    target_settings,
    container_v1_push_item,
):
    pusher = container_image_pusher.ContainerImagePusher([container_v1_push_item], target_settings)
    pusher.copy_v1_push_item(container_v1_push_item)
    mock_tag_images.assert_called_once_with(
        "some-registry/src/repo:2",
        [
            "quay.io/some-namespace/target----repo:latest-test-tag",
            "quay.io/some-namespace/target----repo:1.0",
        ],
        all_arch=True,
        quay_user="dest-quay-user",
        quay_password="dest-quay-pass",
        source_quay_host=None,
        source_quay_user="src-quay-user",
        source_quay_password="src-quay-pass",
        container_exec=True,
        container_image="registry.com/some/image:1",
        docker_url="unix://var/run/docker.sock",
        docker_timeout=None,
        docker_verify_tls=False,
        docker_cert_path=None,
        registry_username="quay-executor-user",
        registry_password="quay-executor-password",
    )


@mock.patch("pubtools._quay.container_image_pusher.tag_images")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_copy_multiarch_item_no_extra_archs(
    mock_quay_client,
    mock_tag_images,
    target_settings,
    container_multiarch_push_item,
):
    pusher = container_image_pusher.ContainerImagePusher(
        [container_multiarch_push_item], target_settings
    )
    pusher.copy_multiarch_push_item(container_multiarch_push_item, {"manifest_list": "first_ml"})

    assert mock_tag_images.call_count == 1
    assert mock_tag_images.call_args_list[0][0] == (
        "some-registry/src/repo:1",
        ["quay.io/some-namespace/target----repo:latest-test-tag"],
    )


@mock.patch("pubtools._quay.container_image_pusher.tag_images")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_copy_multiarch_item_no_dest_ml(
    mock_quay_client,
    mock_tag_images,
    target_settings,
    container_multiarch_push_item,
):

    pusher = container_image_pusher.ContainerImagePusher(
        [container_multiarch_push_item], target_settings
    )
    pusher.copy_multiarch_push_item(
        container_multiarch_push_item,
        {"manifest_list": "first_ml"},
    )

    assert mock_tag_images.call_count == 1
    assert mock_tag_images.call_args_list[0][0] == (
        "some-registry/src/repo:1",
        ["quay.io/some-namespace/target----repo:latest-test-tag"],
    )


@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_source_push_item")
@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_multiarch_push_item")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_push_container_items_src_item(
    mock_quay_client,
    mock_copy_multiarch,
    mock_copy_src,
    target_settings,
    container_source_push_item,
):
    mock_get_manifest = mock.MagicMock()

    mock_get_manifest.side_effect = exceptions.ManifestTypeError("no manifest list")
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    pusher = container_image_pusher.ContainerImagePusher(
        [container_source_push_item], target_settings
    )
    pusher.push_container_images()

    mock_copy_multiarch.assert_not_called()
    mock_copy_src.assert_called_once()


@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_source_push_item")
@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_multiarch_push_item")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_push_container_items_src_item_external_registry(
    mock_quay_client,
    mock_copy_multiarch,
    mock_copy_src,
    target_settings,
    container_source_push_item,
):
    mock_get_manifest = mock.MagicMock()

    response_404 = requests.Response()
    response_404.status_code = 404
    mock_get_manifest.side_effect = requests.exceptions.HTTPError(response=response_404)
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    pusher = container_image_pusher.ContainerImagePusher(
        [container_source_push_item], target_settings
    )
    pusher.push_container_images()

    mock_copy_multiarch.assert_not_called()
    mock_copy_src.assert_called_once()


@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_source_push_item")
@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_multiarch_push_item")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_push_container_items_src_item_500_error(
    mock_quay_client,
    mock_copy_multiarch,
    mock_copy_src,
    target_settings,
    container_source_push_item,
):
    mock_get_manifest = mock.MagicMock()

    response_500 = requests.Response()
    response_500.status_code = 500
    mock_get_manifest.side_effect = requests.exceptions.HTTPError(response=response_500)
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    pusher = container_image_pusher.ContainerImagePusher(
        [container_source_push_item], target_settings
    )
    with pytest.raises(requests.exceptions.HTTPError):
        pusher.push_container_images()


@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_v1_push_item")
@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_multiarch_push_item")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_push_container_items_v1_item(
    mock_quay_client,
    mock_copy_multiarch,
    mock_copy_src,
    target_settings,
    container_v1_push_item,
):
    mock_get_manifest = mock.MagicMock()

    mock_get_manifest.side_effect = exceptions.ManifestTypeError("no manifest list")
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    pusher = container_image_pusher.ContainerImagePusher([container_v1_push_item], target_settings)
    pusher.push_container_images()

    mock_copy_multiarch.assert_not_called()
    mock_copy_src.assert_called_once()


@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_v1_push_item")
@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_multiarch_push_item")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_push_container_items_v1_item(
    mock_quay_client,
    mock_copy_multiarch,
    mock_copy_src,
    target_settings,
    container_multiarch_push_item,
):
    mock_get_manifest = mock.MagicMock()

    mock_get_manifest.side_effect = exceptions.ManifestTypeError("no manifest list")
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    pusher = container_image_pusher.ContainerImagePusher(
        [container_multiarch_push_item], target_settings
    )
    pusher.push_container_images()


@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_v1_push_item")
@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_multiarch_push_item")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_push_container_items_single_arch(
    mock_quay_client,
    mock_copy_multiarch,
    mock_copy_src,
    target_settings_allow_v1_containers_false,
    container_multiarch_push_item,
):
    mock_get_manifest = mock.MagicMock()

    mock_get_manifest.side_effect = exceptions.ManifestTypeError("no manifest list")
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    pusher = container_image_pusher.ContainerImagePusher(
        [container_multiarch_push_item], target_settings_allow_v1_containers_false
    )
    pusher.push_container_images()


@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_source_push_item")
@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_multiarch_push_item")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_push_container_items_multiarch_item(
    mock_quay_client,
    mock_copy_multiarch,
    mock_copy_src,
    target_settings,
    container_multiarch_push_item,
):
    mock_get_manifest = mock.MagicMock()

    mock_get_manifest.return_value = {"some-manifest": "manifest-list"}
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    pusher = container_image_pusher.ContainerImagePusher(
        [container_multiarch_push_item], target_settings
    )
    pusher.push_container_images()

    mock_copy_src.assert_not_called()
    mock_copy_multiarch.assert_called_once()


@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_source_push_item")
@mock.patch("pubtools._quay.container_image_pusher.ContainerImagePusher.copy_multiarch_push_item")
@mock.patch("pubtools._quay.container_image_pusher.QuayClient")
def test_push_container_items_multiple_items(
    mock_quay_client,
    mock_copy_multiarch,
    mock_copy_src,
    target_settings,
    container_multiarch_push_item,
):
    mock_get_manifest = mock.MagicMock()

    mock_get_manifest.return_value = {"some-manifest": "manifest-list"}
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    push_items = [copy.deepcopy(container_multiarch_push_item) for i in range(10)]

    pusher = container_image_pusher.ContainerImagePusher(push_items, target_settings)
    pusher.push_container_images()

    assert mock_copy_multiarch.call_count == 10
