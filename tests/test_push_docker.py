import json
import logging
import mock
import pytest
import requests_mock
import requests

from pubtools._quay import exceptions
from pubtools._quay import quay_client
from pubtools._quay import push_docker
from .utils.misc import sort_dictionary_sortable_values, compare_logs

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


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_generate_backup_mapping(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    container_signing_push_item,
    container_push_item_ok,
):
    hub = mock.MagicMock()

    response = mock.MagicMock()
    response.status_code = 401
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.side_effect = [
        {"name": "target----repo", "tags": ["latest-test-tag"]},
        requests.exceptions.HTTPError("missing", response=response),
        {"name": "target----repo", "tags": ["some-other-tag"]},
        {"name": "test-repo", "tags": ["latest-test-tag", "1.0"]},
    ]
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.side_effect = [
        "sha256:a1a1a1a1a1a1",
        "sha256:a3a3a3a3a3a3",
        "sha256:b2b2b2b2b2b2",
        "sha256:b4b4b4b4b4b4",
    ]
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = "some-manifest-list"
    mock_quay_client.return_value.get_manifest = mock_get_manifest

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
    backup_tags, rollback_tags = push_docker_instance.generate_backup_mapping(
        [
            container_multiarch_push_item,
            container_signing_push_item,
            container_push_item_ok,
        ]
    )
    assert backup_tags == {
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo",
            tag="latest-test-tag",
            digest="sha256:a1a1a1a1a1a1",
            v2s1_digest="sha256:a3a3a3a3a3a3",
        ): "some-manifest-list",
        push_docker.PushDocker.ImageData(
            repo="some-namespace/test-repo",
            tag="latest-test-tag",
            digest="sha256:b2b2b2b2b2b2",
            v2s1_digest=None,
        ): "some-manifest-list",
        push_docker.PushDocker.ImageData(
            repo="some-namespace/test-repo",
            tag="1.0",
            digest="sha256:b4b4b4b4b4b4",
            v2s1_digest=None,
        ): "some-manifest-list",
    }
    assert rollback_tags == [
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo1",
            tag="tag1",
            digest=None,
            v2s1_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo1",
            tag="tag2",
            digest=None,
            v2s1_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo2",
            tag="tag3",
            digest=None,
            v2s1_digest=None,
        ),
    ]
    assert mock_get_repository_tags.call_count == 4
    assert mock_get_repository_tags.call_args_list[0] == mock.call("some-namespace/target----repo")
    assert mock_get_repository_tags.call_args_list[1] == mock.call("some-namespace/target----repo1")
    assert mock_get_repository_tags.call_args_list[2] == mock.call("some-namespace/target----repo2")
    assert mock_get_repository_tags.call_args_list[3] == mock.call("some-namespace/test-repo")

    assert mock_get_manifest.call_count == 3
    assert mock_get_manifest.call_args_list[0] == mock.call(
        "quay.io/some-namespace/target----repo@sha256:a1a1a1a1a1a1"
    )
    assert mock_get_manifest.call_args_list[1] == mock.call(
        "quay.io/some-namespace/test-repo@sha256:b2b2b2b2b2b2"
    )
    assert mock_get_manifest.call_args_list[2] == mock.call(
        "quay.io/some-namespace/test-repo@sha256:b4b4b4b4b4b4"
    )


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_generate_backup_mapping_server_error(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_multiarch_push_item,
    container_signing_push_item,
):
    hub = mock.MagicMock()

    response = mock.MagicMock()
    response.status_code = 500
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.side_effect = [
        {"name": "target----repo", "tags": ["latest-test-tag"]},
        requests.exceptions.HTTPError("server error", response=response),
        {"name": "target----repo", "tags": ["some-other-tag"]},
    ]
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.side_effect = [
        "sha256:a1a1a1a1a1a1",
        "sha256:a3a3a3a3a3a3",
        "sha256:b2b2b2b2b2b2",
        "sha256:b4b4b4b4b4b4",
    ]
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item, container_signing_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(requests.exceptions.HTTPError, match=".*server error*"):
        backup_tags, rollback_tags = push_docker_instance.generate_backup_mapping(
            [container_multiarch_push_item, container_signing_push_item]
        )

    assert mock_get_repository_tags.call_count == 2


@mock.patch("pubtools._quay.push_docker.PushDocker._poll_tag_inconsistency")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_generate_backup_mapping_tag_inconsistency(
    mock_quay_api_client,
    mock_quay_client,
    mock_poll_tag_inconsistency,
    target_settings,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()

    response = mock.MagicMock()
    response.status_code = 404
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "target----repo",
        "tags": ["latest-test-tag"],
    }

    mock_poll_tag_inconsistency.return_value = None

    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.side_effect = (
        requests.exceptions.HTTPError("not found", response=response),
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    mock_get_manifest = mock.MagicMock()
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    backup_tags, rollback_tags = push_docker_instance.generate_backup_mapping(
        [container_multiarch_push_item]
    )
    assert backup_tags == {}
    assert rollback_tags == [
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo",
            tag="latest-test-tag",
            digest=None,
            v2s1_digest=None,
        ),
    ]
    assert mock_get_repository_tags.call_count == 1
    assert mock_get_repository_tags.call_args_list[0] == mock.call("some-namespace/target----repo")

    assert mock_get_manifest.call_count == 0

    mock_poll_tag_inconsistency.assert_called_once_with(
        "some-namespace/target----repo", "latest-test-tag"
    )


@mock.patch("pubtools._quay.push_docker.PushDocker._poll_tag_inconsistency")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_generate_backup_mapping_tag_inconsistency_uncaught_error(
    mock_quay_api_client,
    mock_quay_client,
    mock_poll_tag_inconsistency,
    target_settings,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()

    response = mock.MagicMock()
    response.status_code = 500
    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "target----repo",
        "tags": ["latest-test-tag"],
    }

    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.side_effect = (
        requests.exceptions.HTTPError("server error", response=response),
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )
    with pytest.raises(requests.exceptions.HTTPError, match=".*server error.*"):
        push_docker_instance.generate_backup_mapping([container_multiarch_push_item])

    assert mock_get_repository_tags.call_count == 1
    assert mock_get_repository_tags.call_args_list[0] == mock.call("some-namespace/target----repo")

    mock_poll_tag_inconsistency.assert_not_called()


@mock.patch("pubtools._quay.push_docker.sleep")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_poll_tag_inconsistency_found_match(
    mock_quay_api_client,
    mock_quay_client,
    mock_sleep,
    target_settings,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "target----repo",
        "tags": ["latest-test-tag"],
    }
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags

    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.return_value = "sha256:a1a1a1a1a1a1"
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    digest = push_docker_instance._poll_tag_inconsistency(
        "some-namespace/target----repo", "latest-test-tag"
    )
    assert digest == "sha256:a1a1a1a1a1a1"
    mock_sleep.assert_called_once_with(30)
    mock_get_repository_tags.assert_called_once_with("some-namespace/target----repo")
    mock_get_manifest_digest.assert_called_once_with(
        "quay.io/some-namespace/target----repo:latest-test-tag"
    )


@mock.patch("pubtools._quay.push_docker.sleep")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_poll_tag_inconsistency_tag_doesnt_exist(
    mock_quay_api_client,
    mock_quay_client,
    mock_sleep,
    target_settings,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {"name": "target----repo", "tags": []}
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags

    response = mock.MagicMock()
    response.status_code = 404
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.side_effect = requests.exceptions.HTTPError(
        "not found", response=response
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    digest = push_docker_instance._poll_tag_inconsistency(
        "some-namespace/target----repo", "latest-test-tag"
    )
    assert digest == None
    mock_sleep.assert_called_once_with(30)
    mock_get_repository_tags.assert_called_once_with("some-namespace/target----repo")
    mock_get_manifest_digest.assert_called_once_with(
        "quay.io/some-namespace/target----repo:latest-test-tag"
    )


@mock.patch("pubtools._quay.push_docker.sleep")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_poll_tag_inconsistency_timeout_reached(
    mock_quay_api_client,
    mock_quay_client,
    mock_sleep,
    target_settings,
    container_multiarch_push_item,
    caplog,
):
    caplog.set_level(logging.WARNING)
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {
        "name": "target----repo",
        "tags": ["latest-test-tag"],
    }
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags

    response = mock.MagicMock()
    response.status_code = 404
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.side_effect = requests.exceptions.HTTPError(
        "not found", response=response
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    digest = push_docker_instance._poll_tag_inconsistency(
        "some-namespace/target----repo", "latest-test-tag"
    )
    assert digest == None
    assert mock_sleep.call_count == 4
    assert mock_get_repository_tags.call_count == 4
    assert mock_get_manifest_digest.call_count == 4

    expected_logs = [
        ".*determine if image 'quay.io/some-namespace/target----repo:latest-test-tag' exists.*",
    ]
    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.push_docker.sleep")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_poll_tag_inconsistency_server_error(
    mock_quay_api_client,
    mock_quay_client,
    mock_sleep,
    target_settings,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()
    push_docker_instance = push_docker.PushDocker(
        [container_multiarch_push_item],
        hub,
        "1",
        "some-target",
        target_settings,
    )

    mock_get_repository_tags = mock.MagicMock()
    mock_get_repository_tags.return_value = {"name": "target----repo", "tags": []}
    mock_quay_client.return_value.get_repository_tags = mock_get_repository_tags

    response = mock.MagicMock()
    response.status_code = 500
    mock_get_manifest_digest = mock.MagicMock()
    mock_get_manifest_digest.side_effect = requests.exceptions.HTTPError(
        "server error", response=response
    )
    mock_quay_client.return_value.get_manifest_digest = mock_get_manifest_digest

    with pytest.raises(requests.exceptions.HTTPError, match=".*server error.*"):
        push_docker_instance._poll_tag_inconsistency(
            "some-namespace/target----repo", "latest-test-tag"
        )

    mock_sleep.assert_called_once_with(30)
    mock_get_repository_tags.assert_called_once_with("some-namespace/target----repo")
    mock_get_manifest_digest.assert_called_once_with(
        "quay.io/some-namespace/target----repo:latest-test-tag"
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
            digest=None,
            v2s1_digest=None,
        ): "some-manifest-list",
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo2",
            tag="2",
            digest=None,
            v2s1_digest=None,
        ): "other-manifest-list",
    }
    rollback_tags = [
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo3",
            tag="3",
            digest=None,
            v2s1_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo4",
            tag="4",
            digest=None,
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
            digest=None,
            v2s1_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo4",
            tag="4",
            digest=None,
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
            digest=None,
            v2s1_digest=None,
        ),
        push_docker.PushDocker.ImageData(
            repo="some-namespace/target----repo4",
            tag="4",
            digest=None,
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
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_full_success(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_container_signature_handler,
    mock_operator_pusher,
    mock_operator_signature_handler,
    mock_rollback,
    mock_timestamp,
    mock_security_manifest_pusher,
    mock_set_aws_kms_environment_variables,
    target_settings,
    container_multiarch_push_item,
    container_push_item_external_repos,
    operator_push_item_ok,
    fake_cert_key_paths,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images

    mock_sign_container_images = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images = mock_sign_container_images

    mock_sign_container_images_new_digests = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images_new_digests = (
        mock_sign_container_images_new_digests
    )

    mock_sign_operator_images = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_operator_images = mock_sign_operator_images

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
    mock_container_signature_handler.return_value.get_signatures_from_pyxis = (
        mock_get_signatures_from_pyxis
    )
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images
    mock_timestamp.return_value = "timestamp"

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----some-repo", "sometag", None, None
            ): {"digest": "some-digest"},
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----some-repo", "sometag2", None, None
            ): {"manifests": [{"digest": "some-digest"}]},
        },
        ["item1", "item2"],
    )
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {"v4.5": {"iib_result": iib_result, "signing_keys": []}}

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
    mock_generate_backup_mapping.assert_called_once_with([container_multiarch_push_item])
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_container_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    assert mock_sign_container_images.call_count == 1
    assert mock_sign_container_images.call_args_list[0] == mock.call(
        [container_multiarch_push_item]
    )
    assert mock_sign_container_images_new_digests.call_count == 1
    assert mock_sign_container_images_new_digests.call_args_list[0] == mock.call(
        [container_multiarch_push_item]
    )
    mock_set_aws_kms_environment_variables.assert_called_once_with(
        target_settings, "security_manifest_signer"
    )
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once_with([operator_push_item_ok], "1", target_settings)
    mock_build_index_images.assert_called_once_with()
    mock_push_index_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_result, "signing_keys": []}}, "timestamp"
    )
    mock_operator_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    mock_sign_operator_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_result, "signing_keys": []}}, "timestamp"
    )
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.timestamp")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_full_prerelease(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_container_signature_handler,
    mock_operator_pusher,
    mock_operator_signature_handler,
    mock_rollback,
    mock_timestamp,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_pre_release_push_item,
    container_push_item_external_repos,
    operator_push_item_ok,
    fake_cert_key_paths,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images

    mock_sign_container_images = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images = mock_sign_container_images

    mock_sign_container_images_new_digests = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images_new_digests = (
        mock_sign_container_images_new_digests
    )

    mock_sign_operator_images = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_operator_images = mock_sign_operator_images

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
    mock_container_signature_handler.return_value.get_signatures_from_pyxis = (
        mock_get_signatures_from_pyxis
    )
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images
    mock_timestamp.return_value = "timestamp"

    mock_get_docker_push_items.return_value = [container_multiarch_pre_release_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----some-repo", "sometag", None, None
            ): {"digest": "some-digest"},
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----some-repo", "sometag2", None, None
            ): {"manifests": [{"digest": "some-digest"}]},
        },
        ["item1", "item2"],
    )
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {"v4.5": {"iib_result": iib_result, "signing_keys": []}}

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
    mock_generate_backup_mapping.assert_called_once_with(
        [container_multiarch_pre_release_push_item]
    )
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_pre_release_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_container_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    assert mock_sign_container_images.call_count == 1
    assert mock_sign_container_images.call_args_list[0] == mock.call(
        [container_multiarch_pre_release_push_item]
    )
    assert mock_sign_container_images_new_digests.call_count == 1
    assert mock_sign_container_images_new_digests.call_args_list[0] == mock.call(
        [container_multiarch_pre_release_push_item]
    )
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_pre_release_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once_with([operator_push_item_ok], "1", target_settings)
    mock_build_index_images.assert_called_once_with()
    mock_push_index_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_result, "signing_keys": []}}, "timestamp"
    )
    mock_operator_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    mock_sign_operator_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_result, "signing_keys": []}}, "timestamp"
    )
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.timestamp")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_full_no_v2sch2(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_container_signature_handler,
    mock_operator_pusher,
    mock_operator_signature_handler,
    mock_rollback,
    mock_timestamp,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    container_push_item_external_repos,
    operator_push_item_ok,
    fake_cert_key_paths,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images

    mock_sign_container_images = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images = mock_sign_container_images

    mock_sign_container_images_new_digests = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images_new_digests = (
        mock_sign_container_images_new_digests
    )

    # raise not-found error for v2sch2 manifest which simulates ppc64le only repos (for example)
    def get_manifest_sf(image, media_type):
        if media_type != mock_quay_client.MANIFEST_V2S2_TYPE:
            return {}
        else:
            raise exceptions.ManifestNotFoundError()

    mock_quay_client.return_value.get_manifest_digest.side_effect = get_manifest_sf

    mock_sign_operator_images = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_operator_images = mock_sign_operator_images

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
    mock_container_signature_handler.return_value.get_signatures_from_pyxis = (
        mock_get_signatures_from_pyxis
    )
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images

    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images

    mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images
    mock_timestamp.return_value = "timestamp"

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----some-repo", "sometag", None, None
            ): {"digest": "some-digest"},
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----some-repo", "sometag2", None, None
            ): {"manifests": [{"digest": "some-digest"}]},
        },
        ["item1", "item2"],
    )
    iib_result = mock.MagicMock(index_image_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {"v4.5": {"iib_result": iib_result, "signing_keys": []}}

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
    mock_generate_backup_mapping.assert_called_once_with([container_multiarch_push_item])
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_container_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    assert mock_sign_container_images.call_count == 1
    assert mock_sign_container_images.call_args_list[0] == mock.call(
        [container_multiarch_push_item]
    )
    assert mock_sign_container_images_new_digests.call_count == 1
    assert mock_sign_container_images_new_digests.call_args_list[0] == mock.call(
        [container_multiarch_push_item]
    )
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once_with([operator_push_item_ok], "1", target_settings)
    mock_build_index_images.assert_called_once_with()
    mock_push_index_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_result, "signing_keys": []}}, "timestamp"
    )
    mock_operator_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    mock_sign_operator_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_result, "signing_keys": []}}, "timestamp"
    )
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.timestamp")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_full_success_repush(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_container_signature_handler,
    mock_operator_pusher,
    mock_operator_signature_handler,
    mock_rollback,
    mock_timestamp,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    container_push_item_external_repos,
    operator_push_item_ok,
    fake_cert_key_paths,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images
    mock_sign_container_images = mock.MagicMock(return_value=[])
    mock_sign_container_images_new_digests = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images_new_digests = (
        mock_sign_container_images_new_digests
    )

    mock_container_signature_handler.return_value.sign_container_images = mock_sign_container_images
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images
    mock_get_existing_index_images = mock.MagicMock(
        return_value=[("somerepo", "somedigest", "sometag")]
    )
    mock_timestamp.return_value = "timestamp"
    mock_operator_pusher.return_value.get_existing_index_images = mock_get_existing_index_images
    mock_sign_operator_images = mock.MagicMock(
        return_value=[
            {
                "repo": "somerepo",
                "manifest_digest": "somedigest",
                "docker_reference": "reference/repo:sometag",
            }
        ]
    )
    mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images

    mock_get_docker_push_items.return_value = [
        container_multiarch_push_item,
        container_push_item_external_repos,
    ]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", None, None
            ): {"digest": "some-digest"},
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag2", None, None
            ): {"manifests": [{"digest": "some-digest"}]},
        },
        ["item1", "item2"],
    )
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {"v4.5": {"iib_result": iib_result, "signing_keys": []}}

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
    mock_generate_backup_mapping.assert_called_once_with(
        [container_multiarch_push_item, container_push_item_external_repos]
    )
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item, container_push_item_external_repos],
        target_settings,
    )
    mock_push_container_images.assert_called_once_with()
    mock_container_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    assert mock_sign_container_images.call_count == 1
    assert mock_sign_container_images.call_args_list[0] == mock.call(
        [container_multiarch_push_item, container_push_item_external_repos]
    )
    assert mock_sign_container_images_new_digests.call_count == 1
    assert mock_sign_container_images_new_digests.call_args_list[0] == mock.call(
        [container_multiarch_push_item, container_push_item_external_repos],
    )
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item, container_push_item_external_repos], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once_with([operator_push_item_ok], "1", target_settings)
    mock_build_index_images.assert_called_once_with()
    mock_push_index_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_result, "signing_keys": []}}, "timestamp"
    )
    mock_operator_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    mock_sign_operator_images.assert_called_once_with(
        {"v4.5": {"iib_result": iib_result, "signing_keys": []}}, "timestamp"
    )
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_no_operator_push_items(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_container_signature_handler,
    mock_operator_pusher,
    mock_operator_signature_handler,
    mock_rollback,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    fake_cert_key_paths,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images

    mock_sign_container_images_new_digests = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images_new_digests = (
        mock_sign_container_images_new_digests
    )

    mock_sign_container_images = mock.MagicMock(return_value=[])
    mock_container_signature_handler.return_value.sign_container_images = mock_sign_container_images

    mock_sign_operator_images = mock.MagicMock(return_value=[])
    mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images

    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images
    mock_build_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = []
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", None, None
            ): {"digest": "some-digest"}
        },
        ["item1", "item2"],
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
    mock_generate_backup_mapping.assert_called_once_with([container_multiarch_push_item])
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_container_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    assert mock_sign_container_images.call_count == 1
    assert mock_sign_container_images.call_args_list[0] == mock.call(
        [container_multiarch_push_item]
    )

    assert mock_sign_container_images_new_digests.call_count == 1
    assert mock_sign_container_images_new_digests.call_args_list[0] == mock.call(
        [container_multiarch_push_item],
    )
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
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.remove_old_signatures")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_failure_no_rollback(
    mock_quay_api_client,
    mock_quay_client,
    mock_remove_old_signatures,
    mock_get_docker_push_items,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_container_signature_handler,
    mock_operator_pusher,
    mock_operator_signature_handler,
    mock_rollback,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_ok,
):
    """Rollback shouldn't be triggered as one of the index image build is succesfull."""
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images
    mock_sign_container_images = mock.MagicMock(return_value=([], []))
    mock_container_signature_handler.return_value.sign_container_images = mock_sign_container_images
    mock_sign_container_images_new_digests = mock.MagicMock(return_value=([], []))
    mock_container_signature_handler.return_value.sign_container_images_new_digests = (
        mock_sign_container_images_new_digests
    )

    mock_build_index_images = mock.MagicMock()
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": iib_result, "signing_keys": []},
        "v4.6": {"iib_result": False, "signing_keys": []},
    }
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images
    mock_sign_operator_images = mock.MagicMock(return_value=([], []))
    mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", None, None
            ): {"digest": "some-digest"}
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
    with pytest.raises(SystemExit):
        push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_called_once_with([container_multiarch_push_item])
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()

    assert mock_container_signature_handler.call_count == 1
    assert mock_container_signature_handler.call_args_list[0] == mock.call(
        hub, "1", target_settings, "some-target"
    )
    assert mock_sign_container_images.call_count == 1
    assert mock_sign_container_images.call_args_list[0] == mock.call(
        [container_multiarch_push_item]
    )
    assert mock_sign_container_images_new_digests.call_count == 1
    assert mock_sign_container_images_new_digests.call_args_list[0] == mock.call(
        [container_multiarch_push_item],
    )
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once()
    mock_build_index_images.assert_called_once()
    mock_push_index_images.assert_called_once()
    mock_sign_operator_images.assert_called_once()
    mock_rollback.assert_not_called()


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.remove_old_signatures")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_failure_rollback(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_docker_push_items,
    mock_remove_old_signatures,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_container_signature_handler,
    mock_operator_pusher,
    mock_operator_signature_handler,
    mock_rollback,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_ok,
):
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images
    mock_sign_container_images = mock.MagicMock(return_value=([], []))
    mock_container_signature_handler.return_value.sign_container_images = mock_sign_container_images
    mock_sign_container_images_new_digests = mock.MagicMock(return_value=([], []))
    mock_container_signature_handler.return_value.sign_container_images_new_digests = (
        mock_sign_container_images_new_digests
    )
    mock_build_index_images = mock.MagicMock()
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": False, "signing_keys": []},
        "v4.6": {"iib_result": False, "signing_keys": []},
    }
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images
    mock_sign_operator_images = mock.MagicMock(return_value=([], []))
    mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_ok]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", None, None
            ): {"digest": "some-digest"}
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
    with pytest.raises(SystemExit):
        push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_called_once_with([container_multiarch_push_item])
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_container_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    assert mock_sign_container_images.call_count == 1
    assert mock_sign_container_images.call_args_list[0] == mock.call(
        [container_multiarch_push_item]
    )
    assert mock_sign_container_images_new_digests.call_count == 1
    assert mock_sign_container_images_new_digests.call_args_list[0] == mock.call(
        [container_multiarch_push_item],
    )
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once()
    mock_build_index_images.assert_called_once()
    mock_push_index_images.assert_called_once()
    mock_sign_operator_images.assert_called_once()
    mock_rollback.assert_called_once_with(
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", None, None
            ): {"digest": "some-digest"}
        },
        ["item1", "item2"],
    )


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.rollback")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorPusher")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.ContainerImagePusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.generate_backup_mapping")
@mock.patch("pubtools._quay.push_docker.PushDocker.check_repos_validity")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_operator_push_items")
@mock.patch("pubtools._quay.push_docker.PushDocker.remove_old_signatures")
@mock.patch("pubtools._quay.push_docker.PushDocker.get_docker_push_items")
@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
def test_push_docker_failure_fbc_rollback(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_docker_push_items,
    mock_remove_old_signatures,
    mock_get_operator_push_items,
    mock_check_repos_validity,
    mock_generate_backup_mapping,
    mock_container_image_pusher,
    mock_container_signature_handler,
    mock_operator_pusher,
    mock_operator_signature_handler,
    mock_rollback,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item,
    operator_push_item_fbc_inconsistent,
):
    operator_push_item_fbc_inconsistent.errors = {"repo": "error"}
    hub = mock.MagicMock()
    mock_push_container_images = mock.MagicMock()
    mock_container_image_pusher.return_value.push_container_images = mock_push_container_images
    mock_sign_container_images = mock.MagicMock(return_value=([], []))
    mock_container_signature_handler.return_value.sign_container_images = mock_sign_container_images
    mock_sign_container_images_new_digests = mock.MagicMock(return_value=([], []))
    mock_container_signature_handler.return_value.sign_container_images_new_digests = (
        mock_sign_container_images_new_digests
    )
    mock_build_index_images = mock.MagicMock()
    iib_result = mock.MagicMock(internal_index_image_copy_resolved="registry/ns/iib@digest")
    mock_build_index_images.return_value = {
        "v4.5": {"iib_result": False, "signing_keys": []},
        "v4.6": {"iib_result": False, "signing_keys": []},
    }
    mock_operator_pusher.return_value.build_index_images = mock_build_index_images
    mock_push_index_images = mock.MagicMock()
    mock_operator_pusher.return_value.push_index_images = mock_push_index_images
    mock_sign_operator_images = mock.MagicMock(return_value=([], []))
    mock_operator_signature_handler.return_value.sign_operator_images = mock_sign_operator_images

    mock_get_docker_push_items.return_value = [container_multiarch_push_item]
    mock_get_operator_push_items.return_value = [operator_push_item_fbc_inconsistent]
    mock_generate_backup_mapping.return_value = (
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", None, None
            ): {"digest": "some-digest"}
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
    with pytest.raises(SystemExit):
        push_docker_instance.run()

    mock_get_docker_push_items.assert_called_once_with()
    mock_get_docker_push_items.assert_called_once_with()
    mock_check_repos_validity.assert_called_once_with(
        [container_multiarch_push_item], hub, target_settings
    )
    mock_generate_backup_mapping.assert_called_once_with([container_multiarch_push_item])
    mock_container_image_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_push_container_images.assert_called_once_with()
    mock_container_signature_handler.assert_called_once_with(
        hub, "1", target_settings, "some-target"
    )
    assert mock_sign_container_images.call_count == 1
    assert mock_sign_container_images.call_args_list[0] == mock.call(
        [container_multiarch_push_item]
    )
    assert mock_sign_container_images_new_digests.call_count == 1
    assert mock_sign_container_images_new_digests.call_args_list[0] == mock.call(
        [container_multiarch_push_item],
    )
    mock_security_manifest_pusher.assert_called_once_with(
        [container_multiarch_push_item], target_settings
    )
    mock_security_manifest_pusher.return_value.push_security_manifests.assert_called_once_with()
    mock_operator_pusher.assert_called_once()
    mock_build_index_images.assert_called_once()
    mock_push_index_images.assert_not_called()
    mock_sign_operator_images.assert_called_once()
    mock_rollback.assert_called_once_with(
        {
            push_docker.PushDocker.ImageData(
                "some-ns/orig-ns----somerepo", "sometag", None, None
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


@mock.patch("pubtools._quay.push_docker.PushDocker.verify_target_settings")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.SignatureRemover")
def test_remove_old_signatures_no_old_signatures(
    mock_signature_remover,
    mock_operator_signature_handler,
    mock_container_signature_handler,
    patched_verify_target_settings,
    container_push_item_external_repos,
    fake_cert_key_paths,
    claim_messages,
):
    backup_tags = {}
    image_data = push_docker.PushDocker.ImageData(
        "another-reference/some-product----repo:sometag", "sometag", None, None
    )
    backup_tags[image_data] = {"digest": "somedigest"}

    mock_get_signatures_from_pyxis = mock.MagicMock(
        return_value=[
            {
                "manifest_digest": "some-digest",
                "repository": "some-product/some-repo",
                "reference": "registry/some-product/some-repo:sometag",
                "_id": "signature-id-1",
            }
        ]
    )
    mock_container_signature_handler.get_signatures_from_pyxis = mock_get_signatures_from_pyxis

    push_docker.PushDocker(
        [container_push_item_external_repos],
        mock.MagicMock(),
        mock.MagicMock(),
        mock.MagicMock(),
        mock.MagicMock(),
    ).remove_old_signatures(
        [container_push_item_external_repos],
        [],
        [],
        backup_tags,
        [],
        mock_container_signature_handler,
        mock_operator_signature_handler,
        mock_signature_remover,
        claim_messages,
        claim_messages,
    )
    mock_signature_remover.remove_signatures_from_pyxis.assert_not_called()


@mock.patch("pubtools._quay.push_docker.PushDocker.verify_target_settings")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.SignatureRemover")
def test_remove_old_signatures_container_signatures(
    mock_signature_remover,
    mock_operator_signature_handler,
    mock_container_signature_handler,
    patched_verify_target_settings,
    container_push_item_external_repos,
    fake_cert_key_paths,
):
    mock_get_signatures_from_pyxis = mock.MagicMock(
        return_value=(
            [
                {
                    "manifest_digest": "some-digest",
                    "repository": "some-product/some-repo",
                    "reference": "registry/some-product/some-repo:sometag",
                    "_id": "signature-id-1",
                    "sig_key_id": "sig-key",
                }
            ]
        )
    )
    claim_messages = [
        {
            "manifest_digest": "other-digest",
            "docker_reference": "registry/some-product/some-repo:sometag",
        }
    ]
    mock_container_signature_handler.get_signatures_from_pyxis = mock_get_signatures_from_pyxis
    backup_tags = {}
    image_data = push_docker.PushDocker.ImageData(
        "reference/some-product----some-repo", "sometag", "some-digest", "other-digest"
    )
    rollback_tags = [image_data]
    backup_tags[image_data] = "v2sch2-manifest"
    mock_target_settings = {
        "pyxis_server": "mock_pyxis_server",
        "iib_krb_principal": "mock_pyxis_principal",
        "iib_krb_ktfile": "mock_pyxis_krb_ktfile",
    }

    push_docker.PushDocker(
        [container_push_item_external_repos],
        mock.MagicMock(),
        mock.MagicMock(),
        mock.MagicMock(),
        mock_target_settings,
    ).remove_old_signatures(
        [container_push_item_external_repos],
        [],
        {},
        backup_tags,
        rollback_tags,
        mock_container_signature_handler,
        mock_operator_signature_handler,
        mock_signature_remover,
        claim_messages,
        claim_messages,
    )
    mock_signature_remover.remove_signatures_from_pyxis.assert_called_with(
        ["signature-id-1"],
        "mock_pyxis_server",
        "/path/to/file.crt",
        "/path/to/file.key",
        7,
    )


@mock.patch("pubtools._quay.push_docker.PushDocker.verify_target_settings")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.SignatureRemover")
def test_remove_old_signatures_operator_signatures(
    mock_signature_remover,
    mock_operator_signature_handler,
    mock_container_signature_handler,
    patched_verify_target_settings,
    container_push_item_external_repos,
    operator_push_item_ok,
    fake_cert_key_paths,
    claim_messages,
):
    mock_get_signatures_from_pyxis = mock.MagicMock(
        side_effect=[
            [
                {
                    "manifest_digest": "some-digest",
                    "repository": "some-product/some-repo",
                    "reference": "registry/some-product/some-repo:sometag",
                    "_id": "signature-id-1",
                    "sig_key_id": "sig-key",
                }
            ],
            [
                {
                    "manifest_digest": "some-digest",
                    "repository": "some-product/some-repo",
                    "reference": "registry/some-product/some-repo:someversion",
                    "_id": "signature-id-2",
                    "sig_key_id": "sig-key",
                }
            ],
        ]
    )
    existing_index_images = [("some-digest", "someversion", "some-product/some-repo")]

    mock_container_signature_handler.get_signatures_from_pyxis = mock_get_signatures_from_pyxis
    backup_tags = {}
    image_data = push_docker.PushDocker.ImageData(
        "reference/some-product----some-repo", "someversion", None, None
    )
    backup_tags[image_data] = {"digest": "some-digest"}
    rollback_tags = [image_data]
    mock_target_settings = {
        "pyxis_server": "mock_pyxis_server",
        "iib_krb_principal": "mock_pyxis_principal",
        "iib_krb_ktfile": "mock_pyxis_krb_ktfile",
    }

    push_docker.PushDocker(
        [container_push_item_external_repos],
        mock.MagicMock(),
        mock.MagicMock(),
        mock.MagicMock(),
        mock_target_settings,
    ).remove_old_signatures(
        [container_push_item_external_repos],
        existing_index_images,
        {
            "v4.5": {
                "iib_result": mock.MagicMock(
                    internal_index_image_copy_resolved="registy/ns/iib@digest"
                ),
                "signing_keys": ["sig_key1"],
            }
        },
        backup_tags,
        rollback_tags,
        mock_container_signature_handler,
        mock_operator_signature_handler,
        mock_signature_remover,
        claim_messages,
        claim_messages,
    )

    mock_signature_remover.remove_signatures_from_pyxis.assert_called_once_with(
        ["signature-id-2"],
        "mock_pyxis_server",
        "/path/to/file.crt",
        "/path/to/file.key",
        7,
    )


@mock.patch("pubtools._quay.push_docker.PushDocker.verify_target_settings")
@mock.patch("pubtools._quay.push_docker.ContainerSignatureHandler")
@mock.patch("pubtools._quay.push_docker.OperatorSignatureHandler")
@mock.patch("pubtools._quay.push_docker.SignatureRemover")
def test_remove_old_signatures_operator_signatures_repush(
    mock_signature_remover,
    mock_operator_signature_handler,
    mock_container_signature_handler,
    patched_verify_target_settings,
    container_push_item_external_repos,
    operator_push_item_ok,
    fake_cert_key_paths,
    claim_messages,
):
    mock_get_signatures_from_pyxis = mock.MagicMock(
        side_effect=[
            [
                {
                    "manifest_digest": "some-digest",
                    "repository": "some-product/some-repo",
                    "reference": "registry/some-product/some-repo:sometag",
                    "_id": "signature-id-1",
                    "sig_key_id": "sig-key",
                }
            ],
            [
                {
                    "manifest_digest": "some-digest",
                    "repository": "some-product/some-repo",
                    "reference": "registry/some-product/some-repo:someversion",
                    "_id": "signature-id-2",
                    "sig_key_id": "sig-key",
                }
            ],
        ]
    )
    existing_index_images = [("some-digest", "someversion", "some-product/some-repo")]

    mock_container_signature_handler.get_signatures_from_pyxis = mock_get_signatures_from_pyxis
    backup_tags = {}
    image_data = push_docker.PushDocker.ImageData(
        "reference/some-product----some-repo", "someversion", None, None
    )
    backup_tags[image_data] = {"digest": "some-digest"}
    rollback_tags = [image_data]
    mock_target_settings = {
        "pyxis_server": "mock_pyxis_server",
        "iib_krb_principal": "mock_pyxis_principal",
        "iib_krb_ktfile": "mock_pyxis_krb_ktfile",
    }

    push_docker.PushDocker(
        [container_push_item_external_repos],
        mock.MagicMock(),
        mock.MagicMock(),
        mock.MagicMock(),
        mock_target_settings,
    ).remove_old_signatures(
        [container_push_item_external_repos],
        existing_index_images,
        {
            "v4.5": {
                "iib_result": mock.MagicMock(
                    internal_index_image_copy_resolved="registy/ns/iib@digest"
                ),
                "signing_keys": ["sig_key1"],
            }
        },
        backup_tags,
        rollback_tags,
        mock_container_signature_handler,
        mock_operator_signature_handler,
        mock_signature_remover,
        claim_messages,
        claim_messages,
    )
    mock_container_signature_handler.get_signatures_from_pyxis.assert_has_calls(
        [mock.call([None]), mock.call(["some-digest"])]
    )
