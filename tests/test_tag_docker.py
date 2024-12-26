from copy import deepcopy
import json
import logging
import mock
import pytest
import requests_mock
import requests

from pubtools._quay import exceptions
from pubtools._quay import quay_client
from pubtools._quay import tag_docker
from .utils.misc import sort_dictionary_sortable_values, compare_logs, mock_manifest_list_requests
from pubtools._quay.exceptions import BadPushItem

# flake8: noqa: E501

MSG_SIGNER_OPERATION_RESULT = [
    [
        {
            "i": 0,
            "msg": {
                "errors": [],
                "manifest_digest": "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                "pub_task_id": "12345",
                "repo": "iib-namespace/new-index-image",
                "request_id": "89cf86e0-8403-46e0-b5ed-5984a635e89e",
                "request_received_time": "2023-10-17T08:08:01.544757",
                "sig_key_id": "37036783",
                "sig_keyname": "testing",
                "signature_type": "container_signature",
                "signed_claim": "claim1",
            },
        },
        {},
    ]
]


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_init_verify_target_settings_ok(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    tag_docker_push_item_remove_no_src,
    tag_docker_push_item_mixed,
):
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    hub = mock.MagicMock()
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add, tag_docker_push_item_remove_no_src, tag_docker_push_item_mixed],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    assert tag_docker_instance.push_items == [
        tag_docker_push_item_add,
        tag_docker_push_item_remove_no_src,
        tag_docker_push_item_mixed,
    ]
    assert tag_docker_instance.hub == hub
    assert tag_docker_instance.task_id == "1"
    assert tag_docker_instance.target_name == "some-target"
    assert tag_docker_instance.target_settings == target_settings
    assert tag_docker_instance.quay_host == "quay.io"
    mock_local_executor.assert_not_called()

    assert tag_docker_instance.quay_client == mock_quay_client.return_value
    mock_quay_client.assert_called_once_with("dest-quay-user", "dest-quay-pass", "quay.io")
    mock_skopeo_login.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_init_missing_target_setting(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    target_settings.pop("pyxis_server")
    with pytest.raises(exceptions.InvalidTargetSettings, match="'pyxis_server' must be present.*"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_init_missing_docker_setting(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    target_settings["docker_settings"].pop("umb_urls")
    with pytest.raises(exceptions.InvalidTargetSettings, match="'umb_urls' must be present.*"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_init_wrong_input_data_non_docker_item_type(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.file_type = "non-docker"
    with pytest.raises(exceptions.BadPushItem, match="Push items must be of 'docker' type"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_init_wrong_input_data_number_of_repos(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.repos["new_repo"] = []
    with pytest.raises(exceptions.BadPushItem, match=".*must have precisely one repository.*"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_init_wrong_input_data_no_tag_source(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["tag_source"] = None
    with pytest.raises(exceptions.BadPushItem, match="Source must be provided.*"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_init_wrong_input_data_new_method(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["new_method"] = False
    with pytest.raises(exceptions.BadPushItem, match="Only new method is supported.*"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_init_wrong_input_data_hash_tag_source(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["tag_source"] = "sha256:a1a1a1a1"
    with pytest.raises(exceptions.BadPushItem, match="Specifying source via digest is not.*"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_check_input_validity_new_tag_not_in_stage(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    hub = mock.MagicMock()
    target_settings["propagated_from"] = "quay-stage-target"
    mock_worker = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-pass",
        }
    }
    mock_worker.get_target_info = mock_get_target_info
    hub.worker = mock_worker

    mock_get_manifest = mock.MagicMock()
    response = mock.MagicMock()
    response.status_code = 401
    mock_get_manifest.side_effect = [
        {"some": "manifest"},
        requests.exceptions.HTTPError("not found", response=response),
    ]
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    with pytest.raises(exceptions.BadPushItem, match="To-be-added tag v1.7 must.*"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        tag_docker_instance.check_input_validity()

    mock_get_target_info.assert_called_once_with("quay-stage-target")
    assert mock_get_manifest.call_count == 2
    assert mock_get_manifest.call_args_list[0] == mock.call(
        "quay.io/stage-namespace/namespace----test_repo:v1.6"
    )
    assert mock_get_manifest.call_args_list[1] == mock.call(
        "quay.io/stage-namespace/namespace----test_repo:v1.7"
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_check_input_validity_new_tag_server_error(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    hub = mock.MagicMock()
    target_settings["propagated_from"] = "quay-stage-target"
    mock_worker = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-pass",
        }
    }
    mock_worker.get_target_info = mock_get_target_info
    hub.worker = mock_worker

    mock_get_manifest = mock.MagicMock()
    response = mock.MagicMock()
    response.status_code = 500
    mock_get_manifest.side_effect = [
        {"some": "manifest"},
        requests.exceptions.HTTPError("server error", response=response),
    ]
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    with pytest.raises(requests.exceptions.HTTPError, match="server error"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_add],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        tag_docker_instance.check_input_validity()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_check_input_validity_remove_tag_still_in_stage(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_no_src,
):
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    hub = mock.MagicMock()
    target_settings["propagated_from"] = "quay-stage-target"
    mock_worker = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-pass",
        }
    }
    mock_worker.get_target_info = mock_get_target_info
    hub.worker = mock_worker

    mock_get_manifest = mock.MagicMock()
    response = mock.MagicMock()
    response.status_code = 401
    mock_get_manifest.side_effect = [
        requests.exceptions.HTTPError("not found", response=response),
        {"some": "manifest"},
    ]
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    with pytest.raises(exceptions.BadPushItem, match="To-be-removed tag v1.9 must already.*"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_remove_no_src],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        tag_docker_instance.check_input_validity_remove(tag_docker_push_item_remove_no_src, "v1.8")
        tag_docker_instance.check_input_validity_remove(tag_docker_push_item_remove_no_src, "v1.9")

    assert mock_get_target_info.call_count == 2
    assert mock_get_target_info.call_args_list[0] == mock.call("quay-stage-target")
    assert mock_get_manifest.call_count == 2
    assert mock_get_manifest.call_args_list[0] == mock.call(
        "quay.io/stage-namespace/namespace----test_repo2:v1.8"
    )
    assert mock_get_manifest.call_args_list[1] == mock.call(
        "quay.io/stage-namespace/namespace----test_repo2:v1.9"
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_check_input_validity_remove_tag_server_error(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_no_src,
):
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    hub = mock.MagicMock()
    target_settings["propagated_from"] = "quay-stage-target"
    mock_worker = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-pass",
        }
    }
    mock_worker.get_target_info = mock_get_target_info
    hub.worker = mock_worker

    mock_get_manifest = mock.MagicMock()
    response = mock.MagicMock()
    response.status_code = 500
    mock_get_manifest.side_effect = requests.exceptions.HTTPError("server error", response=response)
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    with pytest.raises(requests.exceptions.HTTPError, match="server error"):
        tag_docker_instance = tag_docker.TagDocker(
            [tag_docker_push_item_remove_no_src],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        tag_docker_instance.check_input_validity_remove(tag_docker_push_item_remove_no_src, "v1.8")


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_get_image_details_multiarch(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
):
    hub = mock.MagicMock()
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.return_value = (
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36"
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    result = tag_docker_instance.get_image_details(
        "some-registry.com/namespace/image:2", mock_local_executor.return_value
    )

    mock_get_manifest.assert_called_once_with("some-registry.com/namespace/image:2")
    mock_get_manifest_digest.assert_called_once_with("some-registry.com/namespace/image:2")

    assert result == tag_docker.TagDocker.ImageDetails(
        "some-registry.com/namespace/image:2",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_get_image_details_source(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    repo_api_data,
    v2s2_manifest_data,
):
    hub = mock.MagicMock()
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = v2s2_manifest_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.return_value = (
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36"
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest
    mock_skopeo_inspect = mock.MagicMock()
    mock_skopeo_inspect.return_value = {"Architecture": "amd64"}
    mock_local_executor.return_value.skopeo_inspect = mock_skopeo_inspect

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    result = tag_docker_instance.get_image_details(
        "some-registry.com/namespace/image:1", mock_local_executor.return_value
    )

    mock_get_manifest.assert_called_once_with("some-registry.com/namespace/image:1")
    mock_get_manifest_digest.assert_called_once_with("some-registry.com/namespace/image:1")
    mock_skopeo_inspect.assert_called_once_with("some-registry.com/namespace/image:1")

    assert result == tag_docker.TagDocker.ImageDetails(
        "some-registry.com/namespace/image:1",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_get_image_details_source_wrong_arch(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    v2s2_manifest_data,
):
    hub = mock.MagicMock()
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = v2s2_manifest_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest
    mock_skopeo_inspect = mock.MagicMock()
    mock_skopeo_inspect.return_value = {"Architecture": "some-arch"}
    mock_local_executor.return_value.skopeo_inspect = mock_skopeo_inspect

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(exceptions.BadPushItem, match=".*contains an architecture some-arch.*"):
        result = tag_docker_instance.get_image_details(
            "some-registry.com/namespace/image:1", mock_local_executor.return_value
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_get_image_details_doesnt_exist(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
    repo_api_data,
):
    hub = mock.MagicMock()
    response = mock.MagicMock()
    response.status_code = 401
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.side_effect = requests.exceptions.HTTPError("missing", response=response)
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    result = tag_docker_instance.get_image_details(
        "some-registry.com/namespace/image:2", mock_local_executor.return_value
    )

    mock_get_manifest.assert_called_once_with("some-registry.com/namespace/image:2")
    assert result == None


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_get_image_details_server_error(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
    repo_api_data,
):
    hub = mock.MagicMock()
    response = mock.MagicMock()
    response.status_code = 500
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.side_effect = requests.exceptions.HTTPError("server error", response=response)
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(requests.exceptions.HTTPError, match="server error"):
        tag_docker_instance.get_image_details(
            "some-registry.com/namespace/image:2", mock_local_executor.return_value
        )

    mock_get_manifest.assert_called_once_with("some-registry.com/namespace/image:2")


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_get_image_details_source_wrong_manifest_type(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    mock_get_manifest = mock.MagicMock()
    v2s1_manifest = {
        "mediaType": "application/vnd.docker.distribution.manifest.v1+json",
    }
    mock_get_manifest.return_value = v2s1_manifest
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(exceptions.BadPushItem, match=".*different than V2S2 or manifest list.*"):
        result = tag_docker_instance.get_image_details(
            "some-registry.com/namespace/image:1", mock_local_executor.return_value
        )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_is_arch_relevant_no_exclude(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    assert tag_docker_instance.is_arch_relevant(tag_docker_push_item_add, "arch1") is True
    assert tag_docker_instance.is_arch_relevant(tag_docker_push_item_add, "arch3") is False


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_is_arch_relevant_exclude(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    tag_docker_push_item_add.metadata["exclude_archs"] = True
    hub = mock.MagicMock()
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    assert tag_docker_instance.is_arch_relevant(tag_docker_push_item_add, "arch1") is False
    assert tag_docker_instance.is_arch_relevant(tag_docker_push_item_add, "arch3") is True


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_source_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_multiarch_image")
def test_tag_remove_calculate_archs_source_images(
    mock_remove_calculate_multiarch,
    mock_remove_calculate_source,
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    v2s2_manifest_data,
):
    hub = mock.MagicMock()
    mock_remove_calculate_source.return_value = "something"
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs(
        tag_docker_push_item_remove_src, "v1.8", mock_local_executor.return_value
    )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo2:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo2:v1.8", mock_local_executor.return_value
    )
    mock_remove_calculate_multiarch.assert_not_called()
    mock_remove_calculate_source.assert_called_once_with(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == "something"


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_source_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_multiarch_image")
def test_tag_remove_calculate_archs_multiarch_images(
    mock_remove_calculate_multiarch,
    mock_remove_calculate_source,
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    manifest_list_data,
):
    hub = mock.MagicMock()
    mock_remove_calculate_multiarch.return_value = "something-else"
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs(
        tag_docker_push_item_remove_src, "v1.8", mock_local_executor.return_value
    )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo2:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo2:v1.8", mock_local_executor.return_value
    )
    mock_remove_calculate_source.assert_not_called()
    mock_remove_calculate_multiarch.assert_called_once_with(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == "something-else"


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_source_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_multiarch_image")
def test_tag_remove_calculate_archs_no_src(
    mock_remove_calculate_multiarch,
    mock_remove_calculate_source,
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_no_src,
    manifest_list_data,
):
    hub = mock.MagicMock()
    mock_remove_calculate_multiarch.return_value = "something-other"
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.return_value = dest_details
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_no_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs(
        tag_docker_push_item_remove_no_src, "v1.8", mock_local_executor.return_value
    )

    mock_get_image_details.assert_called_once_with(
        "quay.io/some-namespace/namespace----test_repo2:v1.8", mock_local_executor.return_value
    )
    mock_remove_calculate_source.assert_not_called()
    mock_remove_calculate_multiarch.assert_called_once_with(
        tag_docker_push_item_remove_no_src, None, dest_details
    )
    assert ret == "something-other"


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_source_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_multiarch_image")
def test_tag_remove_calculate_archs_no_dest(
    mock_remove_calculate_multiarch,
    mock_remove_calculate_source,
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    manifest_list_data,
):
    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )

    mock_get_image_details.side_effect = [source_details, None]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs(
        tag_docker_push_item_remove_src, "v1.8", mock_local_executor.return_value
    )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo2:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo2:v1.8", mock_local_executor.return_value
    )
    mock_remove_calculate_source.assert_not_called()
    mock_remove_calculate_multiarch.assert_not_called()
    assert ret == ([], [])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_source_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs_multiarch_image")
def test_tag_remove_calculate_archs_different_manifest_types(
    mock_remove_calculate_multiarch,
    mock_remove_calculate_source,
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    manifest_list_data,
    v2s2_manifest_data,
):
    hub = mock.MagicMock()
    mock_remove_calculate_multiarch.return_value = "something-else"
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(exceptions.BadPushItem, match="Mismatch between manifest.*"):
        tag_docker_instance.tag_remove_calculate_archs(
            tag_docker_push_item_remove_src, "v1.8", mock_local_executor.return_value
        )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo2:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo2:v1.8", mock_local_executor.return_value
    )
    mock_remove_calculate_source.assert_not_called()
    mock_remove_calculate_multiarch.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_tag_remove_calculate_archs_source_image_src_specified_digests_correspond(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    v2s2_manifest_data,
):
    tag_docker_push_item_remove_src.metadata["archs"] = ["amd64"]
    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs_source_image(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == (["amd64"], [])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_tag_remove_calculate_archs_source_image_src_specified_digests_dont_correspond(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    v2s2_manifest_data,
):
    tag_docker_push_item_remove_src.metadata["archs"] = ["amd64"]
    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs_source_image(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == ([], ["amd64"])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_tag_remove_calculate_archs_source_image_no_src_relevant_arch(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_no_src,
    v2s2_manifest_data,
):
    tag_docker_push_item_remove_no_src.metadata["archs"] = ["amd64"]
    hub = mock.MagicMock()
    source_details = None
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_no_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs_source_image(
        tag_docker_push_item_remove_no_src, source_details, dest_details
    )
    assert ret == (["amd64"], [])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_tag_remove_calculate_archs_source_image_irrelevant_arch(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    v2s2_manifest_data,
):
    tag_docker_push_item_remove_src.metadata["archs"] = ["amd64"]
    tag_docker_push_item_remove_src.metadata["exclude_archs"] = True
    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs_source_image(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == ([], ["amd64"])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_tag_remove_calculate_archs_multiarch_image_all_archs_digests_correspond(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    manifest_list_data,
):
    tag_docker_push_item_remove_src.metadata["archs"] = [
        "amd64",
        "arm64",
        "arm",
        "ppc64le",
        "s390x",
    ]
    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs_multiarch_image(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == (["amd64", "arm64", "arm", "ppc64le", "s390x"], [])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_tag_remove_calculate_archs_multiarch_image_all_digests_correspond_some_archs_irrelevant(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    manifest_list_data,
):
    tag_docker_push_item_remove_src.metadata["archs"] = [
        "amd64",
        "s390x",
    ]
    tag_docker_push_item_remove_src.metadata["exclude_archs"] = True
    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs_multiarch_image(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == (["arm64", "arm", "ppc64le"], ["amd64", "s390x"])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_tag_remove_calculate_archs_multiarch_image_all_archs_relevant_some_digests_dont_correspond(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    manifest_list_data,
):
    tag_docker_push_item_remove_src.metadata["archs"] = [
        "amd64",
        "arm64",
        "arm",
        "ppc64le",
        "s390x",
    ]
    manifest_list_data2 = deepcopy(manifest_list_data)
    manifest_list_data2["manifests"][1][
        "digest"
    ] = "sha256:c06d2750af3cc462e5f8e34eccb0fdd350b28d8cd3b72b86bbf4d28e4a40e6ea"
    manifest_list_data2["manifests"][3][
        "digest"
    ] = "sha256:899560bde2837f603312932d5134a4bb3621e328797895233da54e9d5336911f"

    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        manifest_list_data2,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs_multiarch_image(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == (["amd64", "arm", "s390x"], ["arm64", "ppc64le"])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_tag_remove_calculate_archs_multiarch_image_no_src_some_archs_irrelevant(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    manifest_list_data,
):
    tag_docker_push_item_remove_src.metadata["archs"] = ["amd64", "s390x"]
    hub = mock.MagicMock()
    source_details = None
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_remove_calculate_archs_multiarch_image(
        tag_docker_push_item_remove_src, source_details, dest_details
    )
    assert ret == (["amd64", "s390x"], ["arm64", "arm", "ppc64le"])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
def test_tag_add_calculate_archs_source_images_overwrite(
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    v2s2_manifest_data,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["archs"] = ["amd64"]
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.6",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_add_calculate_archs(
        tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
    )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.6", mock_local_executor.return_value
    )
    assert ret == None


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
def test_tag_add_calculate_archs_source_images_irrelevant_arch(
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    v2s2_manifest_data,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["archs"] = ["amd64"]
    tag_docker_push_item_add.metadata["exclude_archs"] = True
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.6",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_add_calculate_archs(
        tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
    )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.6", mock_local_executor.return_value
    )
    assert ret == []


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
def test_tag_add_calculate_archs_multiarch_images_all_archs_relevant(
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["archs"] = []
    tag_docker_push_item_add.metadata["exclude_archs"] = True
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.6",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_add_calculate_archs(
        tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
    )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.6", mock_local_executor.return_value
    )
    assert ret == ["amd64", "arm64", "arm", "ppc64le", "s390x"]


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
def test_tag_add_calculate_archs_multiarch_images_some_archs_irrelevant(
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["archs"] = ["arm", "ppc64le"]
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.6",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_add_calculate_archs(
        tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
    )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.6", mock_local_executor.return_value
    )
    assert ret == ["arm", "ppc64le"]


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
def test_tag_add_calculate_archs_multiarch_images_missing_dest(
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["archs"] = ["arm", "ppc64le"]
    tag_docker_push_item_add.metadata["exclude_archs"] = True
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = None

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    ret = tag_docker_instance.tag_add_calculate_archs(
        tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
    )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.6", mock_local_executor.return_value
    )
    assert ret == ["amd64", "arm64", "s390x"]


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
def test_tag_add_calculate_archs_multiarch_images_missing_source(
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["archs"] = []
    tag_docker_push_item_add.metadata["exclude_archs"] = True
    source_details = None
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.6",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(exceptions.BadPushItem, match="Source image must be specified.*"):
        tag_docker_instance.tag_add_calculate_archs(
            tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
        )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.6", mock_local_executor.return_value
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
def test_tag_add_calculate_archs_different_manifest_types(
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
    v2s2_manifest_data,
):
    hub = mock.MagicMock()
    tag_docker_push_item_add.metadata["archs"] = []
    tag_docker_push_item_add.metadata["exclude_archs"] = True
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    dest_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo2:v1.6",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
    )

    mock_get_image_details.side_effect = [source_details, dest_details]
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(exceptions.BadPushItem, match="Mismatch between manifest types.*"):
        tag_docker_instance.tag_add_calculate_archs(
            tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
        )

    assert mock_get_image_details.call_count == 2
    assert mock_get_image_details.call_args_list[0] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )
    assert mock_get_image_details.call_args_list[1] == mock.call(
        "quay.io/some-namespace/namespace----test_repo:v1.6", mock_local_executor.return_value
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.ContainerImagePusher.run_tag_images")
def test_copy_all_archs_sign_images_source(
    mock_run_tag_images,
    mock_get_image_details,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    v2s2_manifest_data,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    src_manifest_list,
    v2s1_manifest,
):
    hub = mock.MagicMock()
    sig_handler = mock.MagicMock()
    mock_sign_claim_messages = mock.MagicMock()
    sig_handler.sign_claim_messages = mock_sign_claim_messages
    # shorten the ML to have less claim messages
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo:v1.5",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    mock_get_image_details.return_value = source_details

    signer_wrapper_entry_point.return_value = {
        "signer_result": {
            "status": "ok",
        },
        "operation": {
            "references": ["some-registry.com/iib-namespace/new-index-image:8"],
            "manifests": [
                "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6"
            ],
        },
        "operation_results": MSG_SIGNER_OPERATION_RESULT,
        "signing_key": "sig-key",
    }
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            src_manifest_list,
            v2s1_manifest,
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.7",
            status_code=404,
            text="Not found",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        # manifests for removal of old signatures
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/manifest_list_digest",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
            json=src_manifest_list,
        )

        tag_docker_instance.copy_tag_sign_images(
            tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
        )

    mock_get_image_details.assert_called_once_with(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )
    mock_run_tag_images.assert_called_once_with(
        "quay.io/some-namespace/namespace----test_repo:v1.5",
        ["quay.io/some-namespace/namespace----test_repo:v1.6"],
        True,
        target_settings,
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.ContainerImagePusher.run_tag_images")
def test_copy_all_archs_sign_images_404(
    mock_run_tag_images,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    v2s2_manifest_data,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    src_manifest_list,
    v2s1_manifest,
):
    hub = mock.MagicMock()
    sig_handler = mock.MagicMock()
    mock_sign_claim_messages = mock.MagicMock()
    sig_handler.sign_claim_messages = mock_sign_claim_messages

    signer_wrapper_entry_point.return_value = {
        "signer_result": {
            "status": "ok",
        },
        "operation": {
            "references": ["some-registry.com/iib-namespace/new-index-image:8"],
            "manifests": [
                "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6"
            ],
        },
        "operation_results": MSG_SIGNER_OPERATION_RESULT,
        "signing_key": "sig-key",
    }
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            status_code=404,
            text="Not found",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        # mock_manifest_list_requests(
        #     m,
        #     "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
        #     src_manifest_list,
        #     v2s1_manifest,
        # )
        # m.get(
        #     "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.7",
        #     status_code=404,
        #     text="Not found",
        #     headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        # )
        # m.put(
        #     "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
        #     headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        # )
        with pytest.raises(BadPushItem):
            tag_docker_instance.copy_tag_sign_images(
                tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
            )

    mock_run_tag_images.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.ContainerImagePusher.run_tag_images")
def test_tag_sign_images_multiarch_error(
    mock_run_tag_images,
    # mock_create_claim_message,
    mock_get_image_details,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
):
    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo:v1.5",
        manifest_list_data,
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    mock_get_image_details.return_value = source_details
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(ValueError, match="Tagging workflow is not supported.*"):
        tag_docker_instance.copy_tag_sign_images(
            tag_docker_push_item_add, "v1.6", mock_local_executor.return_value
        )

    mock_get_image_details.assert_called_once_with(
        "quay.io/some-namespace/namespace----test_repo:v1.5", mock_local_executor.return_value
    )

    mock_run_tag_images.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.tag_docker.ManifestListMerger")
def test_merge_manifest_lists_sign_images(
    mock_manifest_list_merger,
    mock_run_tag_images,
    mock_get_image_details,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    src_manifest_list,
    v2s1_manifest,
):
    hub = mock.MagicMock()
    sig_handler = mock.MagicMock()
    mock_sign_claim_messages = mock.MagicMock()
    sig_handler.sign_claim_messages = mock_sign_claim_messages

    # shorten the ML to have less claim messages
    new_manifest_list = deepcopy(manifest_list_data)
    new_manifest_list["manifests"] = new_manifest_list["manifests"][:2]
    mock_merge_manifest_lists = mock.MagicMock()
    mock_merge_manifest_lists.return_value = new_manifest_list
    mock_manifest_list_merger.return_value.merge_manifest_lists_selected_architectures = (
        mock_merge_manifest_lists
    )

    signer_wrapper_entry_point.return_value = {
        "signer_result": {
            "status": "ok",
        },
        "operation": {
            "references": ["some-registry.com/iib-namespace/new-index-image:8"],
            "manifests": [
                "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6"
            ],
        },
        "operation_results": MSG_SIGNER_OPERATION_RESULT,
        "signing_key": "sig-key",
    }

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.7",
            src_manifest_list,
            v2s1_manifest,
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        # manifests for removal od old signatures
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/manifest_list_digest",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
            json=src_manifest_list,
        )

        tag_docker_instance.merge_manifest_lists_sign_images(
            tag_docker_push_item_add, "v1.6", ["arm64", "amd64"]
        )

    mock_manifest_list_merger.assert_called_once_with(
        "quay.io/some-namespace/namespace----test_repo:v1.5",
        "quay.io/some-namespace/namespace----test_repo:v1.6",
    )
    mock_merge_manifest_lists.assert_called_once_with(["arm64", "amd64"])


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.tag_docker.ManifestListMerger")
def test_merge_manifest_lists_sign_images_upload_original_manifest(
    mock_manifest_list_merger,
    mock_run_tag_images,
    mock_get_image_details,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    src_manifest_list,
    v2s1_manifest,
    fixture_run_in_parallel_signer,
):
    hub = mock.MagicMock()

    # shorten the ML to have less claim messages
    new_manifest_list = deepcopy(manifest_list_data)
    new_manifest_list["manifests"] = new_manifest_list["manifests"][:2]
    mock_merge_manifest_lists = mock.MagicMock()
    mock_merge_manifest_lists.return_value = new_manifest_list
    mock_manifest_list_merger.return_value.merge_manifest_lists_selected_architectures = (
        mock_merge_manifest_lists
    )
    # rearrange the "original" ML
    manifest_list_data["manifests"] = manifest_list_data["manifests"][:2]
    manifest_list_data["manifests"] = manifest_list_data["manifests"][1:] + [
        manifest_list_data["manifests"][0]
    ]
    signer_wrapper_entry_point.return_value = {
        "signer_result": {
            "status": "ok",
        },
        "operation": {
            "references": ["some-registry.com/iib-namespace/new-index-image:8"],
            "manifests": [
                "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6"
            ],
        },
        "operation_results": MSG_SIGNER_OPERATION_RESULT,
        "signing_key": "sig-key",
    }
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/tags/list",
            [
                {
                    "json": {
                        "name": "namespace----repo1",
                        "tags": [
                            "latest-test-tag",
                        ],
                    },
                },
            ],
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            json=manifest_list_data,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest-list-digest",
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest-list-digest",
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.7",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest-list-digest",
            },
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest-list-digest",
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/manifest-list-digest",
            text=json.dumps(src_manifest_list, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
            # request_headers={"Accept": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/sha256:1111111111",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            # request_headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/sha256:2222222222",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            # request_headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/sha256:3333333333",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            # request_headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/sha256:5555555555",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            # request_headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        # manifest for removal of old signatures
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/manifest-list-digest",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        tag_docker_instance.merge_manifest_lists_sign_images(
            tag_docker_push_item_add, "v1.6", ["arm64", "amd64"]
        )

    mock_manifest_list_merger.assert_called_once_with(
        "quay.io/some-namespace/namespace----test_repo:v1.5",
        "quay.io/some-namespace/namespace----test_repo:v1.6",
    )
    mock_merge_manifest_lists.assert_called_once_with(["arm64", "amd64"])


@mock.patch("pubtools._quay.tag_docker.untag_images")
def test_run_untag_images_remove_last(mock_untag_images, target_settings):
    tag_docker.TagDocker.run_untag_images(
        ["quay.io/some-namespace/namespace----test_repo:v1.5"], True, target_settings
    )

    mock_untag_images.assert_called_once_with(
        references=["quay.io/some-namespace/namespace----test_repo:v1.5"],
        quay_api_token="dest-quay-token",
        remove_last=True,
        quay_user="dest-quay-user",
        quay_password="dest-quay-pass",
    )


@mock.patch("pubtools._quay.tag_docker.untag_images")
def test_run_untag_images_dont_remove_last(mock_untag_images, target_settings):
    tag_docker.TagDocker.run_untag_images(
        ["quay.io/some-namespace/namespace----test_repo:v1.5"], False, target_settings
    )

    mock_untag_images.assert_called_once_with(
        references=["quay.io/some-namespace/namespace----test_repo:v1.5"],
        quay_api_token="dest-quay-token",
        remove_last=False,
        quay_user="dest-quay-user",
        quay_password="dest-quay-pass",
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.TagDocker.run_untag_images")
def test_untag_image(
    mock_run_untag_images,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    fake_cert_key_paths,
    src_manifest_list,
    v2s1_manifest,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    hub = mock.MagicMock()
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.8",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.9",
            src_manifest_list,
            v2s1_manifest,
        )
        # manifest for removal of old digests
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )

        tag_docker_instance.untag_image(tag_docker_push_item_remove_src, "v1.8")

    mock_run_untag_images.assert_called_once_with(
        ["quay.io/some-namespace/namespace----test_repo2:v1.8"], True, target_settings
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
def test_manifest_list_remove_archs(
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
    manifest_list_data,
    fake_cert_key_paths,
    src_manifest_list,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    hub = mock.MagicMock()
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest
    mock_upload_manifest = mock.MagicMock()
    mock_quay_client.return_value.upload_manifest = mock_upload_manifest
    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    expected_manifest_list = deepcopy(manifest_list_data)
    expected_manifest_list["manifests"] = expected_manifest_list["manifests"][3:]

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.7",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        # Call for old signatures removal
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            json=expected_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            json=expected_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            json=expected_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        tag_docker_instance.manifest_list_remove_archs(
            tag_docker_push_item_remove_src, "v1.8", ["amd64", "arm64", "arm"]
        )

    mock_get_manifest.assert_called_once_with(
        "quay.io/some-namespace/namespace----test_repo2:v1.8",
    )
    mock_upload_manifest.assert_called_once_with(
        expected_manifest_list, "quay.io/some-namespace/namespace----test_repo2:v1.8"
    )


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.tag_docker.TagDocker.copy_tag_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.merge_manifest_lists_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.untag_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.manifest_list_remove_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_add_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.check_input_validity")
def test_run_add_noop(
    mock_check_input_validity,
    mock_tag_remove_calculate_archs,
    mock_tag_add_calculate_archs,
    mock_manifest_list_remove_archs,
    mock_untag_image,
    mock_merge_manifest_lists_sign_images,
    mock_copy_tag_sign_images,
    mock_check_repos_validity,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    mock_tag_add_calculate_archs.return_value = []

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    tag_docker_instance.run()

    mock_check_repos_validity.assert_called_once_with(
        [tag_docker_push_item_add], hub, target_settings
    )
    mock_check_input_validity.assert_called_once_with()
    assert mock_tag_add_calculate_archs.call_count == 2
    assert mock_tag_add_calculate_archs.call_args_list[0] == mock.call(
        tag_docker_push_item_add, "v1.6", mock_local_executor.return_value.__enter__()
    )
    assert mock_tag_add_calculate_archs.call_args_list[1] == mock.call(
        tag_docker_push_item_add, "v1.7", mock_local_executor.return_value.__enter__()
    )
    mock_copy_tag_sign_images.assert_not_called()
    mock_merge_manifest_lists_sign_images.assert_not_called()
    mock_tag_remove_calculate_archs.assert_not_called()
    mock_untag_image.assert_not_called()
    mock_manifest_list_remove_archs.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.tag_docker.TagDocker.copy_tag_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.merge_manifest_lists_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.untag_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.manifest_list_remove_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_add_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.check_input_validity")
def test_run_add_tag_images(
    mock_check_input_validity,
    mock_tag_remove_calculate_archs,
    mock_tag_add_calculate_archs,
    mock_manifest_list_remove_archs,
    mock_untag_image,
    mock_merge_manifest_lists_sign_images,
    mock_copy_tag_sign_images,
    mock_check_repos_validity,
    # mock_basic_signature_handler,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    mock_tag_add_calculate_archs.return_value = None

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    tag_docker_instance.run()

    mock_check_repos_validity.assert_called_once_with(
        [tag_docker_push_item_add], hub, target_settings
    )
    mock_check_input_validity.assert_called_once_with()
    # mock_basic_signature_handler.assert_called_once_with(hub, "1", target_settings, "some-target")
    assert mock_tag_add_calculate_archs.call_count == 2
    assert mock_tag_add_calculate_archs.call_args_list[0] == mock.call(
        tag_docker_push_item_add, "v1.6", mock_local_executor.return_value.__enter__()
    )
    assert mock_tag_add_calculate_archs.call_args_list[1] == mock.call(
        tag_docker_push_item_add, "v1.7", mock_local_executor.return_value.__enter__()
    )
    assert mock_copy_tag_sign_images.call_count == 2
    assert mock_copy_tag_sign_images.call_args_list[0] == mock.call(
        tag_docker_push_item_add,
        "v1.6",
        mock_local_executor.return_value.__enter__(),
    )
    assert mock_copy_tag_sign_images.call_args_list[1] == mock.call(
        tag_docker_push_item_add,
        "v1.7",
        mock_local_executor.return_value.__enter__(),
    )
    mock_merge_manifest_lists_sign_images.assert_not_called()
    mock_tag_remove_calculate_archs.assert_not_called()
    mock_untag_image.assert_not_called()
    mock_manifest_list_remove_archs.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.tag_docker.TagDocker.copy_tag_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.merge_manifest_lists_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.untag_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.manifest_list_remove_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_add_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.check_input_validity")
def test_run_add_merge_manifest_lists(
    mock_check_input_validity,
    mock_tag_remove_calculate_archs,
    mock_tag_add_calculate_archs,
    mock_manifest_list_remove_archs,
    mock_untag_image,
    mock_merge_manifest_lists_sign_images,
    mock_copy_tag_sign_images,
    mock_check_repos_validity,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_add,
):
    hub = mock.MagicMock()
    mock_tag_add_calculate_archs.side_effect = [["amd64", "arm"], ["amd64", "arm64", "arm"]]

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    tag_docker_instance.run()

    mock_check_repos_validity.assert_called_once_with(
        [tag_docker_push_item_add], hub, target_settings
    )
    mock_check_input_validity.assert_called_once_with()
    assert mock_tag_add_calculate_archs.call_count == 2
    assert mock_tag_add_calculate_archs.call_args_list[0] == mock.call(
        tag_docker_push_item_add, "v1.6", mock_local_executor.return_value.__enter__()
    )
    assert mock_tag_add_calculate_archs.call_args_list[1] == mock.call(
        tag_docker_push_item_add, "v1.7", mock_local_executor.return_value.__enter__()
    )
    mock_copy_tag_sign_images.assert_not_called()
    assert mock_merge_manifest_lists_sign_images.call_count == 2
    assert mock_merge_manifest_lists_sign_images.call_args_list[0] == mock.call(
        tag_docker_push_item_add,
        "v1.6",
        ["amd64", "arm"],
    )
    assert mock_merge_manifest_lists_sign_images.call_args_list[1] == mock.call(
        tag_docker_push_item_add,
        "v1.7",
        ["amd64", "arm64", "arm"],
    )
    mock_tag_remove_calculate_archs.assert_not_called()
    mock_untag_image.assert_not_called()
    mock_manifest_list_remove_archs.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.tag_docker.TagDocker.copy_tag_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.merge_manifest_lists_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.untag_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.manifest_list_remove_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_add_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.check_input_validity")
def test_run_remove_noop(
    mock_check_input_validity,
    mock_tag_remove_calculate_archs,
    mock_tag_add_calculate_archs,
    mock_manifest_list_remove_archs,
    mock_untag_image,
    mock_merge_manifest_lists_sign_images,
    mock_copy_tag_sign_images,
    mock_check_repos_validity,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
):
    hub = mock.MagicMock()
    mock_tag_remove_calculate_archs.return_value = ([], ["arm"])

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    tag_docker_instance.run()

    mock_check_repos_validity.assert_called_once_with(
        [tag_docker_push_item_remove_src], hub, target_settings
    )
    mock_check_input_validity.assert_called_once_with()
    mock_tag_add_calculate_archs.assert_not_called()
    mock_copy_tag_sign_images.assert_not_called()
    mock_merge_manifest_lists_sign_images.assert_not_called()
    assert mock_tag_remove_calculate_archs.call_count == 2
    assert mock_tag_remove_calculate_archs.call_args_list[0] == mock.call(
        tag_docker_push_item_remove_src, "v1.8", mock_local_executor.return_value.__enter__()
    )
    assert mock_tag_remove_calculate_archs.call_args_list[1] == mock.call(
        tag_docker_push_item_remove_src, "v1.9", mock_local_executor.return_value.__enter__()
    )
    mock_untag_image.assert_not_called()
    mock_manifest_list_remove_archs.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.tag_docker.TagDocker.copy_tag_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.merge_manifest_lists_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.untag_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.manifest_list_remove_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_add_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.check_input_validity")
def test_run_remove_untag_image(
    mock_check_input_validity,
    mock_tag_remove_calculate_archs,
    mock_tag_add_calculate_archs,
    mock_manifest_list_remove_archs,
    mock_untag_image,
    mock_merge_manifest_lists_sign_images,
    mock_copy_tag_sign_images,
    mock_check_repos_validity,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
):
    hub = mock.MagicMock()
    mock_tag_remove_calculate_archs.side_effect = [(["amd64", "ppc64le"], []), (["s390x"], [])]

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    tag_docker_instance.run()

    mock_check_repos_validity.assert_called_once_with(
        [tag_docker_push_item_remove_src], hub, target_settings
    )
    mock_check_input_validity.assert_called_once_with()
    mock_tag_add_calculate_archs.assert_not_called()
    mock_copy_tag_sign_images.assert_not_called()
    mock_merge_manifest_lists_sign_images.assert_not_called()
    assert mock_tag_remove_calculate_archs.call_count == 2
    assert mock_tag_remove_calculate_archs.call_args_list[0] == mock.call(
        tag_docker_push_item_remove_src, "v1.8", mock_local_executor.return_value.__enter__()
    )
    assert mock_tag_remove_calculate_archs.call_args_list[1] == mock.call(
        tag_docker_push_item_remove_src, "v1.9", mock_local_executor.return_value.__enter__()
    )
    assert mock_untag_image.call_count == 2
    assert mock_untag_image.call_args_list[0] == mock.call(tag_docker_push_item_remove_src, "v1.8")
    assert mock_untag_image.call_args_list[1] == mock.call(tag_docker_push_item_remove_src, "v1.9")
    mock_manifest_list_remove_archs.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.LocalExecutor")
@mock.patch("pubtools._quay.tag_docker.QuayClient")
@mock.patch("pubtools._quay.tag_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.tag_docker.TagDocker.copy_tag_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.merge_manifest_lists_sign_images")
@mock.patch("pubtools._quay.tag_docker.TagDocker.untag_image")
@mock.patch("pubtools._quay.tag_docker.TagDocker.manifest_list_remove_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_add_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.tag_remove_calculate_archs")
@mock.patch("pubtools._quay.tag_docker.TagDocker.check_input_validity")
def test_run_remove_manifest_list_remove_archs(
    mock_check_input_validity,
    mock_tag_remove_calculate_archs,
    mock_tag_add_calculate_archs,
    mock_manifest_list_remove_archs,
    mock_untag_image,
    mock_merge_manifest_lists_sign_images,
    mock_copy_tag_sign_images,
    mock_check_repos_validity,
    mock_quay_client,
    mock_local_executor,
    target_settings,
    tag_docker_push_item_remove_src,
):
    hub = mock.MagicMock()
    mock_tag_remove_calculate_archs.side_effect = [
        (["amd64", "arm64"], ["arm", "ppc64le"]),
        (["amd64"], ["s390x"]),
    ]

    tag_docker_instance = tag_docker.TagDocker(
        [tag_docker_push_item_remove_src],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    tag_docker_instance.run()

    mock_check_repos_validity.assert_called_once_with(
        [tag_docker_push_item_remove_src], hub, target_settings
    )
    mock_check_input_validity.assert_called_once_with()
    # mock_basic_signature_handler.assert_called_once_with(hub, "1", target_settings, "some-target")
    mock_tag_add_calculate_archs.assert_not_called()
    mock_copy_tag_sign_images.assert_not_called()
    mock_merge_manifest_lists_sign_images.assert_not_called()
    assert mock_tag_remove_calculate_archs.call_count == 2
    assert mock_tag_remove_calculate_archs.call_args_list[0] == mock.call(
        tag_docker_push_item_remove_src, "v1.8", mock_local_executor.return_value.__enter__()
    )
    assert mock_tag_remove_calculate_archs.call_args_list[1] == mock.call(
        tag_docker_push_item_remove_src, "v1.9", mock_local_executor.return_value.__enter__()
    )
    mock_untag_image.assert_not_called()
    assert mock_manifest_list_remove_archs.call_count == 2
    assert mock_manifest_list_remove_archs.call_args_list[0] == mock.call(
        tag_docker_push_item_remove_src, "v1.8", ["amd64", "arm64"]
    )
    assert mock_manifest_list_remove_archs.call_args_list[1] == mock.call(
        tag_docker_push_item_remove_src, "v1.9", ["amd64"]
    )


@mock.patch("pubtools._quay.tag_docker.TagDocker")
def test_mod_entrypoint(
    mock_tag_docker, target_settings, tag_docker_push_item_remove_src, tag_docker_push_item_add
):
    hub = mock.MagicMock()
    mock_run = mock.MagicMock()
    mock_tag_docker.return_value.run = mock_run

    tag_docker.mod_entry_point(
        [tag_docker_push_item_remove_src, tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    mock_tag_docker.assert_called_once_with(
        [tag_docker_push_item_remove_src, tag_docker_push_item_add],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    mock_run.assert_called_once_with()


@mock.patch("pubtools._quay.tag_docker.TagDocker.get_image_details")
@mock.patch("pubtools._quay.tag_docker.ContainerImagePusher.run_tag_images")
def test_copy_all_archs_sign_images_source_none_signing_key(
    mock_run_tag_images,
    mock_get_image_details,
    target_settings,
    tag_docker_push_item_add,
    v2s2_manifest_data,
    fake_cert_key_paths,
    signer_wrapper_remove_signatures,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    src_manifest_list,
    v2s1_manifest,
):
    executor = mock.MagicMock()
    hub = mock.MagicMock()
    source_details = tag_docker.TagDocker.ImageDetails(
        "quay.io/some-namespace/namespace----test_repo:v1.5",
        v2s2_manifest_data,
        "application/vnd.docker.distribution.manifest.v2+json",
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
    )
    mock_get_image_details.return_value = source_details
    push_item_none_key = tag_docker_push_item_add
    push_item_none_key.claims_signing_key = None
    tag_docker_instance = tag_docker.TagDocker(
        [push_item_none_key],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            src_manifest_list,
            v2s1_manifest,
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.7",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
            text="error",
            status_code=404,
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        tag_docker_instance.copy_tag_sign_images(push_item_none_key, "v1.6", executor)

    mock_run_tag_images.assert_called_once_with(
        "quay.io/some-namespace/namespace----test_repo:v1.5",
        ["quay.io/some-namespace/namespace----test_repo:v1.6"],
        True,
        target_settings,
    )
    signer_wrapper_remove_signatures.assert_not_called()


@mock.patch("pubtools._quay.tag_docker.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.tag_docker.ManifestListMerger")
def test_merge_manifest_lists_sign_images_none_signing_key(
    mock_manifest_list_merger,
    mock_run_tag_images,
    target_settings,
    tag_docker_push_item_add,
    manifest_list_data,
    fake_cert_key_paths,
    src_manifest_list,
    v2s1_manifest,
    signer_wrapper_remove_signatures,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    hub = mock.MagicMock()
    sig_handler = mock.MagicMock()
    mock_sign_claim_messages = mock.MagicMock()
    sig_handler.sign_claim_messages = mock_sign_claim_messages

    new_manifest_list = deepcopy(manifest_list_data)
    new_manifest_list["manifests"] = new_manifest_list["manifests"][:2]
    mock_merge_manifest_lists = mock.MagicMock()
    mock_merge_manifest_lists.return_value = new_manifest_list
    mock_manifest_list_merger.return_value.merge_manifest_lists_selected_architectures = (
        mock_merge_manifest_lists
    )
    push_item_none_key = tag_docker_push_item_add
    push_item_none_key.claims_signing_key = None

    tag_docker_instance = tag_docker.TagDocker(
        [push_item_none_key],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/latest-test-tag",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            src_manifest_list,
            v2s1_manifest,
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        tag_docker_instance.merge_manifest_lists_sign_images(
            push_item_none_key, "v1.6", ["arm64", "amd64"]
        )
    signer_wrapper_remove_signatures.assert_not_called()
