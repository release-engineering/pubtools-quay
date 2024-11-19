import json
import logging
import mock
import pytest
import requests_mock
import requests

from pubtools._quay import exceptions
from pubtools._quay import push_docker
from .utils.misc import (
    sort_dictionary_sortable_values,
    compare_logs,
    IIBRes,
    mock_manifest_list_requests,
)

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

# flake8: noqa: E501


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_init_verify_target_settings_ok(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_ok,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item, operator_push_item_ok],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    assert push_docker_instance.push_items == [
        container_multiarch_push_item,
        operator_push_item_ok,
    ]
    assert push_docker_instance.hub == hub
    assert push_docker_instance.task_id == "1"
    assert push_docker_instance.target_name == "some-target"
    assert push_docker_instance.target_settings == target_settings
    assert push_docker_instance.quay_host == "quay.io"
    mock_quay_client.assert_not_called()
    mock_quay_api_client.assert_not_called()

    assert push_docker_instance.dest_quay_client == mock_quay_client.return_value
    assert push_docker_instance.dest_quay_api_client == mock_quay_api_client.return_value
    mock_quay_client.assert_called_once_with("dest-quay-user", "dest-quay-pass", "quay.io")
    mock_quay_api_client.assert_called_once_with("dest-quay-token", "quay.io")


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_init_verify_target_settings_missing_item(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_ok,
):
    hub = mock.MagicMock()
    target_settings.pop("source_quay_user", None)
    with pytest.raises(
        exceptions.InvalidTargetSettings, match="'source_quay_user' must be present.*"
    ):
        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_push_item, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_init_verify_target_settings_missing_docker_item(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_ok,
):
    hub = mock.MagicMock()
    target_settings["docker_settings"].pop("umb_urls", None)
    with pytest.raises(exceptions.InvalidTargetSettings, match="'umb_urls' must be present.*"):
        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_push_item, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_container_push_items_ok(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_ok,
    container_source_push_item,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [
            container_multiarch_push_item,
            container_multiarch_push_item,
            operator_push_item_ok,
            container_source_push_item,
        ],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    items = push_docker_instance.get_docker_push_items()
    assert items == [container_multiarch_push_item, container_source_push_item]


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_container_push_items_errors(
    mock_quay_api_client, mock_quay_client, target_settings, container_push_item_errors
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [container_push_item_errors], hub, "1", "some-target", target_settings
    )
    with pytest.raises(exceptions.BadPushItem, match=".*contains errors.*"):
        items = push_docker_instance.get_docker_push_items()


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_container_push_items_no_pull_data(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_push_item_no_metadata,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [container_push_item_no_metadata], hub, "1", "some-target", target_settings
    )
    with pytest.raises(exceptions.BadPushItem, match=".*doesn't contain pull data.*"):
        items = push_docker_instance.get_docker_push_items()


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_operator_push_items_ok(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    operator_push_item_ok,
    operator_push_item_ok2,
    container_push_item_ok,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [operator_push_item_ok, operator_push_item_ok2, container_push_item_ok],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    items = push_docker_instance.get_operator_push_items()
    assert items == [operator_push_item_ok, operator_push_item_ok2]


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_operator_push_item_errors(
    mock_quay_api_client, mock_quay_client, target_settings, operator_push_item_errors
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [operator_push_item_errors], hub, "1", "some-target", target_settings
    )
    with pytest.raises(exceptions.BadPushItem, match=".*contains errors.*"):
        items = push_docker_instance.get_operator_push_items()


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_operator_push_item_no_op_type(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    operator_push_item_no_op_type,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [operator_push_item_no_op_type], hub, "1", "some-target", target_settings
    )
    with pytest.raises(exceptions.BadPushItem, match=".*doesn't contain 'op_type'.*"):
        items = push_docker_instance.get_operator_push_items()


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_operator_push_item_op_appregistry(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    operator_push_item_ok2,
    operator_push_item_appregistry,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [operator_push_item_ok2, operator_push_item_appregistry],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    items = push_docker_instance.get_operator_push_items()
    assert items == [operator_push_item_ok2]


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_operator_push_item_unknown_op_type(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    operator_push_item_unknown_op_type,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [operator_push_item_unknown_op_type], hub, "1", "some-target", target_settings
    )
    with pytest.raises(exceptions.BadPushItem, match=".*has unknown op_type.*"):
        items = push_docker_instance.get_operator_push_items()


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_get_operator_push_item_no_ocp_versions(
    mock_quay_api_client, mock_quay_client, target_settings, operator_push_item_no_ocp
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [operator_push_item_no_ocp], hub, "1", "some-target", target_settings
    )
    with pytest.raises(exceptions.BadPushItem, match=".*specify 'com.redhat.openshift.versions'.*"):
        items = push_docker_instance.get_operator_push_items()


@mock.patch("pubtools._quay.push_docker.pyxis_get_repo_metadata")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_check_repos_validity_success(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_repo_metadata,
    target_settings,
    container_push_item_correct_repos,
    container_signing_push_item,
    container_push_item_external_repos,
    fake_cert_key_paths,
):
    target_settings["do_repo_deprecation_check"] = True
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage_namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    mock_worker = mock.MagicMock()
    mock_worker.get_target_info = mock_get_target_info
    hub = mock.MagicMock()
    hub.worker = mock_worker

    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.side_effect = ["repo_data1", "repo_data2", "repo_data3"]
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags

    mock_get_repo_metadata.side_effect = [
        {"release_categories": "value2"},
        {"release_categories": "value1"},
        {"release_categories": "value2"},
    ]
    target_settings["propagated_from"] = "target_stage_quay"
    push_docker_instance = push_docker.PushDocker(
        [container_push_item_correct_repos, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    push_docker_instance.check_repos_validity(
        [
            container_push_item_external_repos,
            container_push_item_correct_repos,
            container_signing_push_item,
        ],
        hub,
        target_settings,
    )

    mock_get_target_info.assert_called_once_with("target_stage_quay")
    assert mock_get_repo_metadata.call_count == 3
    mock_get_repo_metadata.call_args_list[0] == mock.call("namespace/repo1")
    mock_get_repo_metadata.call_args_list[1] == mock.call("namespace/repo2")
    mock_get_repo_metadata.call_args_list[2] == mock.call("namespace/repo3")
    assert mock_get_repository_tags.call_count == 3
    mock_get_repository_tags.call_args_list[0] == mock.call("some-namespace/namespace----repo1")
    mock_get_repository_tags.call_args_list[1] == mock.call("some-namespace/namespace----repo2")


@mock.patch("pubtools._quay.push_docker.pyxis_get_repo_metadata")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_check_repos_validity_missing_repo(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_repo_metadata,
    target_settings,
    container_signing_push_item,
):
    target_settings["do_repo_deprecation_check"] = True
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage_namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    mock_worker = mock.MagicMock()
    mock_worker.get_target_info = mock_get_target_info
    hub = mock.MagicMock()
    hub.worker = mock_worker

    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.side_effect = ["repo_data1", "repo_data2"]
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags

    response = mock.MagicMock()
    response.status_code = 404
    mock_get_repo_metadata.side_effect = [
        {"release_categories": "value1"},
        requests.exceptions.HTTPError("missing", response=response),
    ]
    target_settings["propagated_from"] = "target_stage_quay"
    push_docker_instance = push_docker.PushDocker(
        [container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    push_docker_instance.check_repos_validity(
        [container_signing_push_item],
        hub,
        target_settings,
    )

    mock_get_target_info.assert_called_once_with("target_stage_quay")
    assert mock_get_repo_metadata.call_count == 2
    mock_get_repo_metadata.call_args_list[0] == mock.call("namespace/repo1")
    mock_get_repo_metadata.call_args_list[1] == mock.call("namespace/repo2")
    assert mock_get_repository_tags.call_count == 2
    mock_get_repository_tags.call_args_list[0] == mock.call("some-namespace/namespace----repo1")
    mock_get_repository_tags.call_args_list[1] == mock.call("some-namespace/namespace----repo2")


@mock.patch("pubtools._quay.push_docker.pyxis_get_repo_metadata")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_check_repos_validity_get_repo_server_error(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_repo_metadata,
    target_settings,
    container_push_item_ok,
    container_signing_push_item,
):
    target_settings["do_repo_deprecation_check"] = True
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage_namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    mock_worker = mock.MagicMock()
    mock_worker.get_target_info = mock_get_target_info
    hub = mock.MagicMock()
    hub.worker = mock_worker

    response = mock.MagicMock()
    response.status_code = 500
    mock_get_repo_metadata.side_effect = [
        {"release_categories": "value1"},
        requests.exceptions.HTTPError("server error", response=response),
    ]
    target_settings["propagated_from"] = "target_stage_quay"
    push_docker_instance = push_docker.PushDocker(
        [container_push_item_ok, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(requests.exceptions.HTTPError, match=".*server error.*"):
        push_docker_instance.check_repos_validity(
            [container_push_item_ok, container_signing_push_item],
            hub,
            target_settings,
        )

    mock_get_target_info.assert_called_once_with("target_stage_quay")
    assert mock_get_repo_metadata.call_count == 2
    mock_get_repo_metadata.call_args_list[0] == mock.call("namespace/repo1")
    mock_get_repo_metadata.call_args_list[1] == mock.call("namespace/repo2")


@mock.patch("pubtools._quay.push_docker.pyxis_get_repo_metadata")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_check_repos_validity_deprecated_repo(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_repo_metadata,
    target_settings,
    container_push_item_ok,
    container_signing_push_item,
    fake_cert_key_paths,
):
    target_settings["do_repo_deprecation_check"] = True
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage_namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    mock_worker = mock.MagicMock()
    mock_worker.get_target_info = mock_get_target_info
    hub = mock.MagicMock()
    hub.worker = mock_worker

    mock_get_repo_metadata.side_effect = [
        {"release_categories": "value1"},
        {"release_categories": "Deprecated"},
    ]
    target_settings["propagated_from"] = "target_stage_quay"
    push_docker_instance = push_docker.PushDocker(
        [container_push_item_ok, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(exceptions.InvalidRepository, match=".*is deprecated.*"):
        push_docker_instance.check_repos_validity(
            [container_push_item_ok, container_signing_push_item],
            hub,
            target_settings,
        )

    mock_get_target_info.assert_called_once_with("target_stage_quay")
    assert mock_get_repo_metadata.call_count == 2
    mock_get_repo_metadata.call_args_list[0] == mock.call("namespace/repo1")
    mock_get_repo_metadata.call_args_list[1] == mock.call("namespace/repo2")


@mock.patch("pubtools._quay.utils.misc.pyxis_get_repo_metadata")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_check_repos_validity_deprecated_repo_check_disabled(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_repo_metadata,
    target_settings,
    container_push_item_ok,
    container_signing_push_item,
):
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage_namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    mock_worker = mock.MagicMock()
    mock_worker.get_target_info = mock_get_target_info
    hub = mock.MagicMock()
    hub.worker = mock_worker

    mock_get_repo_metadata.return_value = {"release_categories": "Deprecated"}
    target_settings["propagated_from"] = "target_stage_quay"
    push_docker_instance = push_docker.PushDocker(
        [container_push_item_ok, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    push_docker_instance.check_repos_validity(
        [container_push_item_ok, container_signing_push_item],
        hub,
        target_settings,
    )

    mock_get_target_info.assert_called_once_with("target_stage_quay")
    assert mock_get_repo_metadata.call_count == 0


@mock.patch("pubtools._quay.push_docker.pyxis_get_repo_metadata")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_check_repos_validity_missing_stage_repo(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_repo_metadata,
    target_settings,
    container_push_item_ok,
    container_signing_push_item,
    fake_cert_key_paths,
):
    target_settings["do_repo_deprecation_check"] = True
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage_namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    mock_worker = mock.MagicMock()
    mock_worker.get_target_info = mock_get_target_info
    hub = mock.MagicMock()
    hub.worker = mock_worker

    response = mock.MagicMock()
    response.status_code = 404
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.side_effect = [
        "repo_data1",
        requests.exceptions.HTTPError("missing", response=response),
    ]
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags

    mock_get_repo_metadata.side_effect = [
        {"release_categories": "value1"},
        {"release_categories": "value2"},
    ]
    target_settings["propagated_from"] = "target_stage_quay"
    push_docker_instance = push_docker.PushDocker(
        [container_push_item_ok, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(exceptions.InvalidRepository, match=".*doesn't exist on stage.*"):
        push_docker_instance.check_repos_validity(
            [container_push_item_ok, container_signing_push_item],
            hub,
            target_settings,
        )

    mock_get_target_info.assert_called_once_with("target_stage_quay")
    assert mock_get_repo_metadata.call_count == 2
    mock_get_repo_metadata.call_args_list[0] == mock.call("namespace/repo1")
    mock_get_repo_metadata.call_args_list[1] == mock.call("namespace/repo2")
    assert mock_get_repository_tags.call_count == 2
    mock_get_repository_tags.call_args_list[0] == mock.call("some-namespace/namespace----repo1")
    mock_get_repository_tags.call_args_list[1] == mock.call("some-namespace/namespace----repo2")


@mock.patch("pubtools._quay.push_docker.pyxis_get_repo_metadata")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_check_repos_validity_get_stage_repo_server_error(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_repo_metadata,
    target_settings,
    container_push_item_ok,
    container_signing_push_item,
    fake_cert_key_paths,
):
    target_settings["do_repo_deprecation_check"] = True
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage_namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    mock_worker = mock.MagicMock()
    mock_worker.get_target_info = mock_get_target_info
    hub = mock.MagicMock()
    hub.worker = mock_worker

    response = mock.MagicMock()
    response.status_code = 500
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.side_effect = [
        "repo_data1",
        requests.exceptions.HTTPError("server error", response=response),
    ]
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags

    mock_get_repo_metadata.side_effect = [
        {"release_categories": "value1"},
        {"release_categories": "value2"},
    ]
    target_settings["propagated_from"] = "target_stage_quay"
    push_docker_instance = push_docker.PushDocker(
        [container_push_item_ok, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(requests.exceptions.HTTPError, match=".*server error*"):
        push_docker_instance.check_repos_validity(
            [container_push_item_ok, container_signing_push_item],
            hub,
            target_settings,
        )

    mock_get_target_info.assert_called_once_with("target_stage_quay")
    assert mock_get_repo_metadata.call_count == 2
    assert mock_get_repo_metadata.call_args_list[0] == mock.call("namespace/repo1", target_settings)
    assert mock_get_repo_metadata.call_args_list[1] == mock.call("namespace/repo2", target_settings)
    assert mock_get_repository_tags.call_count == 2
    assert mock_get_repository_tags.call_args_list[0] == mock.call(
        "stage_namespace/namespace----repo1"
    )
    assert mock_get_repository_tags.call_args_list[1] == mock.call(
        "stage_namespace/namespace----repo2"
    )


@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_generate_backup_mapping(
    mock_quay_api_client,
    target_settings,
    container_multiarch_push_item,
    container_signing_push_item,
    container_push_item_ok,
    src_manifest_list,
    v2s1_manifest,
    fixture_run_in_parallel,
):
    hub = mock.MagicMock()

    push_docker_instance = push_docker.PushDocker(
        [
            container_multiarch_push_item,
            container_signing_push_item,
            container_push_item_ok,
        ],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/test-repo/manifests/latest-test-tag",
            src_manifest_list,
            v2s1_manifest,
        )
        m.get(
            "https://quay.io/v2/some-namespace/test-repo/manifests/1.0",
            text="Not Found",
            status_code=404,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text="Not Found",
            status_code=404,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo1/manifests/tag1",
            src_manifest_list,
            v2s1_manifest,
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo1/manifests/tag2",
            text="Not Found",
            status_code=404,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo1/manifests/tag2",
            text="Not Found",
            status_code=404,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo2/manifests/tag3",
            src_manifest_list,
            v2s1_manifest,
        )
        backup_tags, rollback_tags = push_docker_instance.generate_backup_mapping(
            [
                container_multiarch_push_item,
                container_signing_push_item,
                container_push_item_ok,
            ]
        )

    assert backup_tags == {
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo1",
            tag="tag1",
            v2s2_digest="",
            v2s1_digest="",
            v2list_digest="manifest_list_digest",
        ): (src_manifest_list, ""),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo2",
            tag="tag3",
            v2s2_digest="",
            v2s1_digest="",
            v2list_digest="manifest_list_digest",
        ): (src_manifest_list, ""),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/test-repo",
            tag="latest-test-tag",
            v2s2_digest="",
            v2s1_digest="",
            v2list_digest="manifest_list_digest",
        ): (src_manifest_list, ""),
    }
    assert rollback_tags == [
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo",
            tag="latest-test-tag",
            v2s2_digest=None,
            v2s1_digest=None,
            v2list_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo1",
            tag="tag2",
            v2s2_digest=None,
            v2s1_digest=None,
            v2list_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/test-repo",
            tag="1.0",
            v2s2_digest=None,
            v2s1_digest=None,
            v2list_digest=None,
        ),
    ]


@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_generate_backup_mapping_server_error(
    mock_quay_api_client,
    target_settings,
    container_multiarch_push_item,
    container_signing_push_item,
    src_manifest_list,
    v2s1_manifest,
):
    hub = mock.MagicMock()

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            [{"status_code": 500, "reason": "server error"}],
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo1/manifests/tag1",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo1/manifests/tag2",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo2/manifests/tag3",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo1/manifests/some-other-tag",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo/manifests/some-other-tag",
            src_manifest_list,
            v2s1_manifest,
        )
        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_push_item],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        with pytest.raises(requests.exceptions.HTTPError, match=".*server error*"):
            backup_tags, rollback_tags = push_docker_instance.generate_backup_mapping(
                [container_multiarch_push_item, container_signing_push_item]
            )


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_rollback(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    container_signing_push_item,
):
    hub = mock.MagicMock()
    mock_upload_manifest = mock.MagicMock()
    mock_quay_client.return_value.upload_manifest = mock_upload_manifest
    mock_delete_tag = mock.MagicMock()
    mock_quay_api_client.return_value.delete_tag = mock_delete_tag

    backup_tags = {
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo1",
            tag="1",
            v2list_digest=None,
            v2s2_digest=None,
            v2s1_digest=None,
        ): "some-manifest-list",
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo2",
            tag="2",
            v2list_digest=None,
            v2s2_digest=None,
            v2s1_digest=None,
        ): "other-manifest-list",
    }
    rollback_tags = [
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo3",
            tag="3",
            v2list_digest=None,
            v2s2_digest=None,
            v2s1_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo4",
            tag="4",
            v2list_digest=None,
            v2s2_digest=None,
            v2s1_digest=None,
        ),
    ]
    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    push_docker_instance.rollback(backup_tags, rollback_tags)

    assert mock_upload_manifest.call_count == 2
    assert mock_upload_manifest.call_args_list[0] == mock.call(
        "some-manifest-list", "quay.io/some-namespace/target----repo1:1"
    )
    assert mock_upload_manifest.call_args_list[1] == mock.call(
        "other-manifest-list", "quay.io/some-namespace/target----repo2:2"
    )
    assert mock_delete_tag.call_count == 2
    assert mock_delete_tag.call_args_list[0] == mock.call("some-namespace/target----repo3", "3")
    assert mock_delete_tag.call_args_list[1] == mock.call("some-namespace/target----repo4", "4")


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_rollback_deleted_tag_not_found(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    container_signing_push_item,
):
    hub = mock.MagicMock()
    mock_delete_tag = mock.MagicMock()
    response = mock.MagicMock()
    response.status_code = 404
    mock_delete_tag.side_effect = [
        requests.exceptions.HTTPError("not found", response=response),
        None,
    ]
    mock_quay_api_client.return_value.delete_tag = mock_delete_tag

    backup_tags = {}
    rollback_tags = [
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo3",
            tag="3",
            v2list_digest=None,
            v2s2_digest=None,
            v2s1_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo4",
            tag="4",
            v2list_digest=None,
            v2s2_digest=None,
            v2s1_digest=None,
        ),
    ]
    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    push_docker_instance.rollback(backup_tags, rollback_tags)

    assert mock_delete_tag.call_count == 2
    assert mock_delete_tag.call_args_list[0] == mock.call("some-namespace/target----repo3", "3")
    assert mock_delete_tag.call_args_list[1] == mock.call("some-namespace/target----repo4", "4")


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_rollback_delete_tag_server_error(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    container_signing_push_item,
):
    hub = mock.MagicMock()
    mock_delete_tag = mock.MagicMock()
    response = mock.MagicMock()
    response.status_code = 500
    mock_delete_tag.side_effect = [
        requests.exceptions.HTTPError("server error", response=response),
        None,
    ]
    mock_quay_api_client.return_value.delete_tag = mock_delete_tag

    backup_tags = {}
    rollback_tags = [
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo3",
            tag="3",
            v2list_digest=None,
            v2s2_digest=None,
            v2s1_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo4",
            tag="4",
            v2list_digest=None,
            v2s2_digest=None,
            v2s1_digest=None,
        ),
    ]
    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(requests.exceptions.HTTPError, match=".*server error.*"):
        push_docker_instance.rollback(backup_tags, rollback_tags)

    mock_delete_tag.assert_called_once_with("some-namespace/target----repo3", "3")


@mock.patch("pubtools._quay.push_docker.set_aws_kms_environment_variables")
@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.timestamp")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_full_success(
    mock_quay_api_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_operator_pusher,
    mock_rollback,
    mock_timestamp,
    mock_security_manifest_pusher,
    mock_set_aws_kms_environment_variables,
    target_settings,
    container_multiarch_push_item,
    container_push_item_external_repos,
    container_push_item_ok,
    operator_push_item_ok,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    v2s1_manifest,
    dest_manifest_list,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_get_signatures_from_pyxis = mock.MagicMock(
        return_value=(
            [
                {
                    "manifest_digest": "some-digest",
                    "repository": "orig-ns/some-repo",
                    "reference": "registry/orig-ns/some-repo:sometag",
                    "_id": "signature-id-1",
                }
            ]
        )
    )
    iib_res = IIBRes(
        "registry.com/namespace/index-image@sha256:v4.5",
        "registry.com/namespace/iib@sha256:a1a1a1",
        ["v4.5-1"],
    )
    mock_build_index_images = mock.Mock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": iib_res, "signing_keys": ["sigkey"], "destination_tags": ["v4.5"]}
    }

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    # mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images
    mock_timestamp.return_value = "timestamp"

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.side_effect = [
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo", "sometag", "some-digest", None, "some-digest"
                ): ({"digest": "some-digest"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo", "sometag", None, "some-digest", "some-digest"
                ): ({"digest": "some-digest"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo",
                    "sometag2",
                    "some-digest-2",
                    None,
                    "some-digest-2",
                ): ({"manifests": [{"digest": "some-digest"}]}, ""),
            },
            ["item1", "item2"],
        ),
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo",
                    "sometag",
                    "some-new-digest",
                    None,
                    "some-digest",
                ): ({"digest": "some-digest-new"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo",
                    "sometag",
                    None,
                    "some-digest-new",
                    "some-digest",
                ): ({"digest": "some-digest-new"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo",
                    "sometag2",
                    "some-digest-2",
                    None,
                    "some-digest-2",
                ): ({"manifests": [{"digest": "some-digest-new"}]}, ""),
            },
            ["item1", "item2"],
        ),
    ]
    # iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")

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
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=v2s1_manifest,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.v2+json",
                "docker-content-digest": "sha256:5555555555",
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.v1+json",
                "docker-content-digest": "sha256:5555555555",
            },
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/v4.5-1",
            json=dest_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "sha256:5555555555",
            },
        )
        # call to untag old signatures
        m.get(
            "https://quay.io/v2/some-namespace/orig-ns----some-repo/manifests/some-digest",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_push_item, container_push_item_ok, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_has_calls(
        [
            mock.call([container_multiarch_push_item], all_arches=True),
            mock.call([container_multiarch_push_item], all_arches=True),
        ]
    )
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_set_aws_kms_environment_variables.assert_has_calls(
        [
            mock.call(target_settings, "cosign_signer"),
            mock.call(target_settings, "security_manifest_signer"),
        ]
    )
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once_with([operator_push_item_ok], "1", target_settings)
    mock_build_index_images.assert_called_once_with()
    mock_push_index_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_res, "signing_keys": ["sigkey"], "destination_tags": ["v4.5"]}},
        "timestamp",
    )
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.timestamp")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_full_prerelease(
    mock_quay_api_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_operator_pusher,
    mock_rollback,
    mock_timestamp,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_pre_release_push_item,
    container_push_item_external_repos,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    operator_push_item_ok,
    fake_cert_key_paths,
    v2s1_manifest,
    dest_manifest_list,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_get_signatures_from_pyxis = mock.MagicMock(
        return_value=(
            [
                {
                    "manifest_digest": "some-digest",
                    "repository": "orig-ns/some-repo",
                    "reference": "registry/orig-ns/some-repo:sometag",
                    "_id": "signature-id-1",
                }
            ]
        )
    )
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    iib_res = IIBRes(
        "registry.com/namespace/index-image@sha256:v4.5",
        "registry.com/namespace/iib@sha256:a1a1a1",
        ["v4.5-1"],
    )
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": iib_res, "signing_keys": ["sigkey"], "destination_tags": ["v4.5"]}
    }

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_timestamp.return_value = "timestamp"

    mock_get_docker_push_items.return_value = [container_multiarch_pre_release_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.side_effect = [
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo",
                    "sometag",
                    "some-digest-list",
                    "some-digest-sch2",
                    "some-digest-sch1",
                ): ({"digest": "some-digest"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo", "sometag2", None, "some-digest", None
                ): ({"manifests": [{"digest": "some-digest"}]}, ""),
            },
            ["item1", "item2"],
        ),
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo",
                    "sometag",
                    "some-digest-list",
                    "some-digest-sch2",
                    "some-digest-sch1-new",
                ): ({"digest": "some-digest"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo", "sometag2", None, "some-digest", None
                ): ({"manifests": [{"digest": "some-digest"}]}, ""),
            },
            ["item1", "item2"],
        ),
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
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=v2s1_manifest,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.v2+json",
                "docker-content-digest": "sha256:5555555555",
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.v1+json",
                "docker-content-digest": "sha256:5555555555",
            },
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/v4.5-1",
            json=dest_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "sha256:5555555555",
            },
        )
        # call for untagging old signatures
        m.get(
            "https://quay.io/v2/some-namespace/orig-ns----some-repo/manifests/some-digest-sch1",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/orig-ns----some-repo/manifests/some-digest-sch2",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_pre_release_push_item, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_pre_release_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_has_calls(
        [
            mock.call([container_multiarch_pre_release_push_item], all_arches=True),
            mock.call([container_multiarch_pre_release_push_item], all_arches=True),
        ]
    )
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_pre_release_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_pre_release_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once_with([operator_push_item_ok], "1", target_settings)
    mock_build_index_images.assert_called_once_with()
    mock_push_index_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_res, "signing_keys": ["sigkey"], "destination_tags": ["v4.5"]}},
        "timestamp",
    )
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.timestamp")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_full_no_v2sch2(
    mock_quay_api_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_operator_pusher,
    mock_rollback,
    mock_timestamp,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    container_push_item_external_repos,
    operator_push_item_ok,
    dest_manifest_list,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    v2s1_manifest,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_get_signatures_from_pyxis = mock.MagicMock(
        return_value=(
            [
                {
                    "manifest_digest": "some-digest",
                    "repository": "orig-ns/some-repo",
                    "reference": "registry/orig-ns/some-repo:sometag",
                    "_id": "signature-id-1",
                }
            ]
        )
    )
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_timestamp.return_value = "timestamp"

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.side_effect = [
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo", "sometag", None, None, None
                ): ({"digest": "some-digest"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo", "sometag2", None, None, None
                ): ({"manifests": [{"digest": "some-digest"}]}, ""),
            },
            ["item1", "item2"],
        ),
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo", "sometag", None, None, None
                ): ({"digest": "some-digest-new"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----some-repo", "sometag2", None, None, None
                ): ({"manifests": [{"digest": "some-digest-new"}]}, ""),
            },
            ["item1", "item2"],
        ),
    ]
    iib_res = IIBRes(
        "registry.com/namespace/index-image@sha256:v4.5",
        "registry.com/namespace/iib@sha256:a1a1a1",
        ["v4.5-1"],
    )
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": iib_res, "signing_keys": [], "destination_tags": ["v4.5"]}
    }

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
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/v4.5-1",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_push_item, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_has_calls(
        [
            mock.call([container_multiarch_push_item], all_arches=True),
            mock.call([container_multiarch_push_item], all_arches=True),
        ]
    )
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once_with([operator_push_item_ok], "1", target_settings)
    mock_build_index_images.assert_called_once_with()
    mock_push_index_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_res, "signing_keys": [], "destination_tags": ["v4.5"]}},
        "timestamp",
    )
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.timestamp")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_full_success_repush(
    mock_quay_api_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_operator_pusher,
    mock_rollback,
    mock_timestamp,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    container_push_item_external_repos,
    operator_push_item_ok,
    fake_cert_key_paths,
    v2s1_manifest,
    dest_manifest_list,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images
    mock_sign_container_images = mock.MagicMock(return_value=[])
    mock_sign_container_images_new_digests = mock.MagicMock(return_value=[])
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images
    mock_get_existing_index_images = mock.MagicMock(
        return_value=[("somedigest", "sometag", "somerepo")]
    )
    mock_timestamp.return_value = "timestamp"
    mock_operator_pusher.return_value.get_existing_index_images = mock_get_existing_index_images

    mock_get_docker_push_items.return_value = [
        container_multiarch_push_item,
        container_push_item_external_repos,
    ]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.side_effect = [
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----somerepo", "sometag", None, None, None
                ): ({"digest": "some-digest"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----somerepo", "sometag2", None, None, None
                ): ({"manifests": [{"digest": "some-digest"}]}, ""),
            },
            ["item1", "item2"],
        ),
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----somerepo", "sometag", None, None, None
                ): ({"digest": "some-digest-new"}, "amd64"),
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----somerepo", "sometag2", None, None, None
                ): ({"manifests": [{"digest": "some-digest-new"}]}, ""),
            },
            ["item1", "item2"],
        ),
    ]
    iib_res = IIBRes(
        "registry.com/namespace/index-image@sha256:v4.5",
        "registry.com/namespace/iib@sha256:a1a1a1",
        ["v4.5-1"],
    )
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": iib_res, "signing_keys": [], "destination_tags": ["v4.5"]}
    }
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
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/external----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/test_repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/test_repo/manifests/1.0",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/test_repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/external----repo/manifests/1.0",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/external----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/v4.5-1",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/external----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        # Call for untag old signatures
        m.get(
            "https://quay.io/v2/some-namespace/somerepo/manifests/somedigest",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )

        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_push_item, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item, container_push_item_external_repos],
        hub,
        target_settings,
    )
    mock_generate_backup_mapping.assert_has_calls(
        [
            mock.call(
                [container_multiarch_push_item, container_push_item_external_repos], all_arches=True
            ),
            mock.call(
                [container_multiarch_push_item, container_push_item_external_repos], all_arches=True
            ),
        ]
    )
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item, container_push_item_external_repos],
        target_settings,
    )
    mock_push_container_images.assert_called_once_with()
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item, container_push_item_external_repos], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once_with([operator_push_item_ok], "1", target_settings)
    mock_build_index_images.assert_called_once_with()
    mock_push_index_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_res, "signing_keys": [], "destination_tags": ["v4.5"]}},
        "timestamp",
    )
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_no_operator_push_items(
    mock_quay_api_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_operator_pusher,
    mock_rollback,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    fake_cert_key_paths,
    v2s1_manifest,
    dest_manifest_list,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images

    mock_sign_operator_images = mock.MagicMock(return_value=[])

    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = []
    mock_generate_backup_mapping.side_effect = [
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----somerepo", "sometag", None, None, None
                ): ({"digest": "some-digest"}, "amd64")
            },
            ["item1", "item2"],
        ),
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----somerepo", "sometag", None, None, None
                ): ({"digest": "some-digest-new"}, "amd64")
            },
            ["item1", "item2"],
        ),
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

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/v4.5-1",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_push_item], hub, "1", "some-target", target_settings
        )
        push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_has_calls(
        [
            mock.call([container_multiarch_push_item], all_arches=True),
            mock.call([container_multiarch_push_item], all_arches=True),
        ]
    )

    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()

    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_not_called()
    mock_build_index_images.assert_not_called()
    mock_push_index_images.assert_not_called()
    mock_sign_operator_images.assert_not_called()
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_failure_no_rollback(
    mock_quay_api_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_operator_pusher,
    # mock_operator_signature_handler,
    mock_rollback,
    mock_security_manifest_pusher,
    target_settings,
    fake_cert_key_paths,
    container_multiarch_push_item,
    operator_push_item_ok,
    v2s1_manifest,
    dest_manifest_list,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    """Rollback shouldn't be triggered as one of the index image build is succesfull."""
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images
    mock_sign_container_images = mock.MagicMock(return_value=([], []))

    iib_res = IIBRes(
        "registry.com/namespace/index-image@sha256:v4.5",
        "registry.com/namespace/iib@sha256:a1a1a1",
        ["v4.5-1"],
    )
    mock_build_index_images = mock.MagicMock()
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": iib_res, "signing_keys": [], "destination_tags": ["v4.5"]},
        "v4.6": {"iib_result": False, "signing_keys": [], "destination_tags": ["v4.6"]},
    }
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images
    mock_sign_operator_images = mock.MagicMock(return_value=([], []))

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.side_effect = [
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----somerepo", "sometag", None, None, None
                ): ({"digest": "some-digest"}, "amd64")
            },
            ["item1", "item2"],
        ),
        (
            {
                push_docker.PushDocker.ImageData(
                    "some-ns/orig-ns----somerepo", "sometag", None, None, None
                ): ({"digest": "some-digest-new"}, "amd64")
            },
            ["item1", "item2"],
        ),
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
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/v4.5-1",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        push_docker_instance = push_docker.PushDocker(
            [container_multiarch_push_item, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        with pytest.raises(SystemExit):
            push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_has_calls(
        [
            mock.call([container_multiarch_push_item], all_arches=True),
            mock.call([container_multiarch_push_item], all_arches=True),
        ]
    )

    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()

    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once()
    mock_build_index_images.assert_called_once()
    mock_push_index_images.assert_called_once()
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_failure_rollback(
    mock_quay_api_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_operator_pusher,
    mock_rollback,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_ok,
    v2s1_manifest,
    dest_manifest_list,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images
    mock_build_index_images = mock.MagicMock()
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": False, "signing_keys": []},
        "v4.6": {"iib_result": False, "signing_keys": []},
    }
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", "sha256:aaaa", None, None
            ): ({"digest": "some-digest"}, "amd64")
        },
        ["item1", "item2"],
    )

    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item, operator_push_item_ok],
        hub,
        "1",
        "some-target",
        target_settings,
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
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/v4.5-1",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        with pytest.raises(SystemExit):
            push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_called_once_with(
        [container_multiarch_push_item], all_arches=True
    )
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once()
    mock_build_index_images.assert_called_once()
    mock_push_index_images.assert_called_once()
    mock_rollback.assert_called_once_with(
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", "sha256:aaaa", None, None
            ): {"digest": "some-digest"}
        },
        ["item1", "item2"],
    )


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_failure_fbc_rollback(
    mock_quay_api_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_operator_pusher,
    mock_rollback,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_fbc_inconsistent,
    v2s1_manifest,
    dest_manifest_list,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    operator_push_item_fbc_inconsistent.errors = {"repo": "error"}
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images
    mock_sign_container_images = mock.MagicMock(return_value=([], []))
    mock_build_index_images = mock.MagicMock()
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": False, "signing_keys": []},
        "v4.6": {"iib_result": False, "signing_keys": []},
    }
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_fbc_inconsistent]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", "sha256:aaaa", None, None
            ): ({"digest": "some-digest"}, "amd64")
        },
        ["item1", "item2"],
    )

    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item, operator_push_item_fbc_inconsistent],
        hub,
        "1",
        "some-target",
        target_settings,
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
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/v4.5-1",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        with pytest.raises(SystemExit):
            push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_called_once_with(
        [container_multiarch_push_item], all_arches=True
    )
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once()
    mock_build_index_images.assert_called_once()
    mock_push_index_images.assert_not_called()
    mock_rollback.assert_called_once_with(
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", "sha256:aaaa", None, None
            ): {"digest": "some-digest"}
        },
        ["item1", "item2"],
    )


@mock.patch("pubtools._quay.push_docker.PushDocker")
def test_mod_entrypoint(
    mock_push_docker,
    container_multiarch_push_item,
    operator_push_item_ok,
    target_settings,
):
    hub = mock.MagicMock()
    mock_run = mock.MagicMock()
    mock_run.return_value = ["repo1", "repo2"]
    mock_push_docker.return_value.run = mock_run

    push_docker.mod_entry_point(
        [container_multiarch_push_item, operator_push_item_ok],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    mock_push_docker.assert_called_once_with(
        [container_multiarch_push_item, operator_push_item_ok],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    mock_run.assert_called_once_with()
