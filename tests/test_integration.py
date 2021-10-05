import json
import logging
import mock
import pytest
import requests_mock
from copy import deepcopy

from pubtools._quay.push_docker import PushDocker
from pubtools._quay.tag_docker import TagDocker
from pubtools._quay import iib_operations
from pubtools._quay import clear_repo
from pubtools._quay import remove_repo
from .utils.misc import sort_dictionary_sortable_values, compare_logs, IIBRes

# flake8: noqa: E501


@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
@mock.patch("pubtools._quay.command_executor.APIClient")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.proton")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.push_docker.run_entrypoint")
def test_push_docker_multiarch_merge_ml_operator(
    mock_run_entrypoint_push_docker,
    mock_run_entrypoint_sig_handler,
    mock_claims_handler,
    mock_proton,
    mock_run_cmd,
    mock_send_umb_message,
    mock_run_entrypoint_operator_pusher,
    mock_api_client,
    mock_run_entrypoint_signature_remover,
    target_settings,
    container_multiarch_push_item_integration,
    operator_push_item_ok,
    src_manifest_list,
    dest_manifest_list,
    fake_cert_key_paths,
):
    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    hub.worker.get_target_info = mock_get_target_info
    target_settings["propagated_from"] = "test-target"

    mock_run_entrypoint_push_docker.side_effect = [
        # pubtools-pyxis-get-repo-metadata
        {"release_categories": ["definitely-not-deprecated"]},
    ]
    mock_run_entrypoint_sig_handler.side_effect = [
        # pubtools-pyxis-get-signatures (containers)
        [
            {
                "reference": "registry.com/namespace/repo:1",
                "manifest_digest": "e5e5e5",
                "sig_key_id": "some-key",
            }
        ],
        # pubtools-pyxis-upload-signatures
        [],
        # pubtools-pyxis-get-signatures (operators)
        [
            {
                "reference": "registry.com/namespace/repo:1",
                "manifest_digest": "e5e5e5",
                "sig_key_id": "some-key",
            }
        ],
        # pubtools-pyxis-get-signatures (containers) (removing signatures)
        [
            {
                "reference": "registry.com/namespace/target----repo:latest-test-tag",
                "manifest_digest": "sha256:6666666666",
                "sig_key_id": "some-key",
                "repository": "target/repo",
                "_id": "some-id1",
            },
            {
                "reference": "registry.com/namespace/target----repo:latest-test-tag",
                "manifest_digest": "sha256:7777777777",
                "sig_key_id": "some-key",
                "repository": "target/repo",
                "_id": "some-id2",
            },
        ],
        # pubtools-pyxis-get-signatures (operators) (removing signatures)
        [
            {
                "reference": "registry.com/namespace/operators----index-image:v4.6",
                "manifest_digest": "sha256:8888888888",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
                "_id": "some-id1",
            },
            {
                "reference": "registry.com/namespace/operators----index-image:v4.5",
                "manifest_digest": "sha256:6666666666",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
                "_id": "some-id2",
            },
        ],
    ]
    mock_run_entrypoint_operator_pusher.side_effect = [
        # pubtools-pyxis-get-operator-indices
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}],
        # pubtools-iib-add-bundles (4.5)
        IIBRes(
            "registry.com/namespace/index-image@sha256:v4.5",
            "registry.com/namespace/index-image@sha256:a1a1a1",
        ),
        # pubtools-iib-add-bundles (4.6)
        IIBRes(
            "registry.com/namespace/index-image@sha256:v4.6",
            "registry.com/namespace/index-image@sha256:b2b2b2",
        ),
    ]

    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/stage-namespace/test_namespace----test_repo/tags/list",
            json={"some-data": "value"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/a1a1a1",
            json={"mediaType": "manifest"},
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/src/repo?includeTags=True",
            json={"tags": {"1": {"image_id": None}}},
        )
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            [
                {
                    "text": json.dumps(dest_manifest_list, sort_keys=True),
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
                    },
                },
                {
                    "json": dest_manifest_list,
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
                    },
                },
            ],
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/sha256:9daac465523ce42a89e605151734e7b92c5ade2123055a6a2aeabbf60e5edfa4",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/v4.5",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/v4.6",
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put("https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag")
        m.get("https://git-server.com/v4_5.yml/raw?ref=master")
        m.get("https://git-server.com/v4_6.yml/raw?ref=master")
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/sha256:a1a1a1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/namespace/iib/manifests/sha256:b2b2b2",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.delete("https://pyxis-url.com/v1/signatures/id/some-id1")
        m.delete("https://pyxis-url.com/v1/signatures/id/some-id2")

        push_docker = PushDocker(
            [container_multiarch_push_item_integration, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        push_docker.run()


@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
@mock.patch("pubtools._quay.command_executor.APIClient")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.proton")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.push_docker.run_entrypoint")
def test_push_docker_multiarch_simple_workflow(
    mock_run_entrypoint_push_docker,
    mock_run_entrypoint_sig_handler,
    mock_claims_handler,
    mock_proton,
    mock_run_cmd,
    mock_send_umb_message,
    mock_api_client,
    mock_run_entrypoint_signature_remover,
    target_settings,
    container_multiarch_push_item_integration,
    src_manifest_list,
    fake_cert_key_paths,
):
    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    hub.worker.get_target_info = mock_get_target_info
    target_settings["propagated_from"] = "test-target"

    mock_run_entrypoint_push_docker.side_effect = [
        # pubtools-pyxis-get-repo-metadata
        {"release_categories": ["definitely-not-deprecated"]},
    ]
    mock_run_entrypoint_sig_handler.side_effect = [
        # pubtools-pyxis-get-signatures (containers)
        [
            {
                "reference": "registry.com/namespace/repo:1",
                "manifest_digest": "e5e5e5",
                "sig_key_id": "some-key",
            }
        ],
        # pubtools-pyxis-upload-signatures
        [],
        # pubtools-pyxis-get-signatures (containers) (removing signatures)
        [
            {
                "reference": "registry.com/namespace/target----repo:latest-test-tag",
                "manifest_digest": "sha256:6666666666",
                "sig_key_id": "some-key",
                "repository": "target/repo",
                "_id": "some-id1",
            },
            {
                "reference": "registry.com/namespace/target----repo:latest-test-tag",
                "manifest_digest": "sha256:7777777777",
                "sig_key_id": "some-key",
                "repository": "target/repo",
                "_id": "some-id2",
            },
        ],
    ]

    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/stage-namespace/test_namespace----test_repo/tags/list",
            json={"some-data": "value"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/a1a1a1",
            json={"mediaType": "manifest"},
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/src/repo?includeTags=True",
            json={"tags": {"1": {"image_id": None}}},
        )
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            [
                {
                    "text": json.dumps(src_manifest_list, sort_keys=True),
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
                    },
                },
                {
                    "json": src_manifest_list,
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
                    },
                },
            ],
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/sha256:8ce181d89b7bb7f1639d8df3d65d630b1322d0bb6daff5c492eec24ec53628d5",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
        )

        push_docker = PushDocker(
            [container_multiarch_push_item_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        push_docker.run()


@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
@mock.patch("pubtools._quay.command_executor.APIClient")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.proton")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.push_docker.run_entrypoint")
def test_push_docker_source(
    mock_run_entrypoint_push_docker,
    mock_run_entrypoint_sig_handler,
    mock_claims_handler,
    mock_proton,
    mock_run_cmd,
    mock_send_umb_message,
    mock_api_client,
    mock_run_entrypoint_signature_remover,
    target_settings,
    container_source_push_item_integration,
    src_manifest_list,
    fake_cert_key_paths,
):
    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    hub.worker.get_target_info = mock_get_target_info
    target_settings["propagated_from"] = "test-target"

    mock_run_entrypoint_push_docker.side_effect = [
        # pubtools-pyxis-get-repo-metadata
        {"release_categories": ["definitely-not-deprecated"]},
    ]
    mock_run_entrypoint_sig_handler.side_effect = [
        # pubtools-pyxis-get-signatures (containers)
        [
            {
                "reference": "registry.com/namespace/repo:1",
                "manifest_digest": "e5e5e5",
                "sig_key_id": "some-key",
            }
        ],
        # pubtools-pyxis-upload-signatures
        [],
        # pubtools-pyxis-get-signatures (containers) (removing signatures)
        [
            {
                "reference": "registry.com/namespace/target----repo:latest-test-tag",
                "manifest_digest": "sha256:6666666666",
                "sig_key_id": "some-key",
                "repository": "target/repo",
                "_id": "some-id1",
            },
            {
                "reference": "registry.com/namespace/target----repo:latest-test-tag",
                "manifest_digest": "sha256:7777777777",
                "sig_key_id": "some-key",
                "repository": "target/repo",
                "_id": "some-id2",
            },
        ],
    ]

    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/stage-namespace/test_namespace----test_repo/tags/list",
            json={"some-data": "value"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/a1a1a1",
            json={"mediaType": "manifest"},
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/src/repo?includeTags=True",
            json={"tags": {"1": {"image_id": None}}},
        )
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            [
                {
                    "text": json.dumps(src_manifest_list, sort_keys=True),
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
                    },
                },
                {
                    "json": src_manifest_list,
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
                    },
                },
            ],
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/sha256:8ce181d89b7bb7f1639d8df3d65d630b1322d0bb6daff5c492eec24ec53628d5",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
        )

        push_docker = PushDocker(
            [container_source_push_item_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        push_docker.run()


@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.proton")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.push_docker.run_entrypoint")
def test_push_docker_multiarch_rollback(
    mock_run_entrypoint_push_docker,
    mock_run_entrypoint_sig_handler,
    mock_claims_handler,
    mock_proton,
    mock_run_cmd,
    mock_send_umb_message,
    mock_run_entrypoint_signature_remover,
    target_settings,
    container_multiarch_push_item_integration,
    src_manifest_list,
    fake_cert_key_paths,
):
    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    hub.worker.get_target_info = mock_get_target_info
    target_settings["propagated_from"] = "test-target"

    mock_run_entrypoint_push_docker.side_effect = [
        # pubtools-pyxis-get-repo-metadata
        {"release_categories": ["definitely-not-deprecated"]},
    ]
    mock_run_entrypoint_sig_handler.side_effect = [
        # pubtools-pyxis-get-signatures (containers)
        [
            {
                "reference": "registry.com/namespace/repo:1",
                "manifest_digest": "e5e5e5",
                "sig_key_id": "some-key",
            }
        ],
        # pubtools-pyxis-upload-signatures
        ValueError("something went wrong"),
    ]

    mock_run_cmd.return_value = ("out", "err")

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/stage-namespace/test_namespace----test_repo/tags/list",
            json={"some-data": "value"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/a1a1a1",
            json={"mediaType": "manifest"},
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/src/repo?includeTags=True",
            json={"tags": {"1": {"image_id": None}}},
        )
        m.get(
            "https://quay.io/v2/src/repo/manifests/1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            [
                {
                    "text": json.dumps(src_manifest_list, sort_keys=True),
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
                    },
                },
                {
                    "json": src_manifest_list,
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
                    },
                },
            ],
        )
        m.put(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/sha256:8ce181d89b7bb7f1639d8df3d65d630b1322d0bb6daff5c492eec24ec53628d5",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        push_docker = PushDocker(
            [container_multiarch_push_item_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        with pytest.raises(ValueError, match="something went wrong"):
            push_docker.run()


@mock.patch("pubtools._quay.command_executor.APIClient")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.push_docker.run_entrypoint")
def test_tag_docker_multiarch_merge_ml(
    mock_run_entrypoint_push_docker,
    mock_run_entrypoint_sig_handler,
    mock_run_entrypoint_sig_remover,
    mock_claims_handler,
    mock_api_client,
    target_settings,
    tag_docker_push_item_add_integration,
    tag_docker_push_item_remove_no_src_integration,
    src_manifest_list,
    fake_cert_key_paths,
):
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    hub.worker.get_target_info = mock_get_target_info
    target_settings["propagated_from"] = "test-target"

    mock_run_entrypoint_push_docker.side_effect = [
        # pubtools-pyxis-get-repo-metadata
        {"release_categories": ["definitely-not-deprecated"]},
        # pubtools-pyxis-get-repo-metadata
        {"release_categories": ["definitely-not-deprecated"]},
    ]

    mock_run_entrypoint_sig_handler.side_effect = [
        # pubtools-pyxis-get-signatures (containers)
        [
            {
                "reference": "registry.com/namespace/repo:1",
                "manifest_digest": "e5e5e5",
                "sig_key_id": "some-key",
            }
        ],
        # pubtools-pyxis-upload-signatures
        [],
    ]
    mock_run_entrypoint_sig_remover.side_effect = [
        # pubtools-pyxis-get-signatures (removing signatures)
        [
            {
                "reference": "registry.com/namespace/namespace----test_repo:v1.6",
                "manifest_digest": "sha256:1111111111",
                "sig_key_id": "some-key",
                "repository": "namespace/test_repo",
                "_id": "some-id1",
            },
            {
                "reference": "registry.com/namespace/namespace----test_repo:v1.6",
                "manifest_digest": "sha256:2222222222",
                "sig_key_id": "some-key",
                "repository": "namespace/test_repo",
                "_id": "some-id2",
            },
        ],
        # pubtools-pyxis-delete-signatures
        [],
    ]

    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    src_manifest_list_missing = deepcopy(src_manifest_list)
    src_manifest_list_missing["manifests"] = src_manifest_list_missing["manifests"][:2]

    with requests_mock.Mocker() as m:

        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo/tags/list",
            json={
                "name": "namespace----test_repo",
                "tags": [
                    "v1.5",
                    "v1.6",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/tags/list",
            json={
                "name": "namespace----test_repo",
                "tags": [
                    "v1.5",
                    "v1.6",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo2/tags/list",
            json={
                "name": "namespace----test_repo2",
                "tags": [
                    "v1.5",
                    "v1.6",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/tags/list",
            json={
                "name": "namespace----test_repo2",
                "tags": [
                    "v1.5",
                    "v1.6",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo/manifests/v1.6",
            json=src_manifest_list_missing,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo2/manifests/v1.8",
            status_code=404,
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/namespace----test_repo?includeTags=True",
            json={
                "tags": {
                    "v1.5": {"manifest_digest": "a1a1a1"},
                    "v1.6": {"manifest_digest": "b2b2b2"},
                }
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            json=src_manifest_list_missing,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.8",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/namespace----test_repo2?includeTags=True",
            json={"tags": {"v1.8": {"manifest_digest": "c3c3c3"}}},
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.8",
        )

        tag_docker_instance = TagDocker(
            [tag_docker_push_item_add_integration, tag_docker_push_item_remove_no_src_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        tag_docker_instance.run()


@mock.patch("pubtools._quay.command_executor.APIClient")
@mock.patch("pubtools._quay.untag_images.send_umb_message")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.push_docker.run_entrypoint")
def test_tag_docker_source_copy_untag(
    mock_run_entrypoint_push_docker,
    mock_run_entrypoint_sig_handler,
    mock_run_entrypoint_sig_remover,
    mock_claims_handler,
    mock_run_cmd,
    mock_send_umb_message_tag,
    mock_send_umb_message_untag,
    mock_api_client,
    target_settings,
    tag_docker_push_item_add_integration,
    tag_docker_push_item_remove_no_src_integration,
    v2s2_manifest_data,
    fake_cert_key_paths,
):
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
        }
    }
    hub.worker.get_target_info = mock_get_target_info
    target_settings["propagated_from"] = "test-target"

    mock_run_entrypoint_push_docker.side_effect = [
        # pubtools-pyxis-get-repo-metadata
        {"release_categories": ["definitely-not-deprecated"]},
        # pubtools-pyxis-get-repo-metadata
        {"release_categories": ["definitely-not-deprecated"]},
    ]

    mock_run_entrypoint_sig_handler.side_effect = [
        # pubtools-pyxis-get-signatures (containers)
        [
            {
                "reference": "registry.com/namespace/repo:1",
                "manifest_digest": "e5e5e5",
                "sig_key_id": "some-key",
            }
        ],
        # pubtools-pyxis-upload-signatures
        [],
    ]

    mock_api_client.return_value.exec_start.side_effect = [
        b"something",
        b"Login Succeeded",
        b'{"Architecture": "amd64"}',
        b'{"Architecture": "amd64"}',
        b'{"Architecture": "amd64"}',
        b"dest-quay-user",
        b"finished tagging",
        b'{"Architecture": "amd64"}',
    ]
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    with requests_mock.Mocker() as m:

        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.5",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.6",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo/tags/list",
            json={
                "name": "namespace----test_repo",
                "tags": [
                    "v1.5",
                    "v1.6",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/tags/list",
            json={
                "name": "namespace----test_repo",
                "tags": [
                    "v1.5",
                    "v1.6",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo2/tags/list",
            json={
                "name": "namespace----test_repo2",
                "tags": [
                    "v1.5",
                    "v1.6",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/tags/list",
            json={
                "name": "namespace----test_repo2",
                "tags": [
                    "v1.5",
                    "v1.6",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo/manifests/v1.6",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo2/manifests/v1.8",
            status_code=404,
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/namespace----test_repo?includeTags=True",
            json={
                "tags": {
                    "v1.5": {"manifest_digest": "a1a1a1"},
                    "v1.6": {"manifest_digest": "b2b2b2"},
                }
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.8",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/namespace----test_repo2?includeTags=True",
            json={"tags": {"v1.8": {"manifest_digest": "c3c3c3", "image_id": "some-id"}}},
        )
        m.put(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.8",
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-namespace/namespace----test_repo2/tag/v1.8",
        )

        tag_docker_instance = TagDocker(
            [tag_docker_push_item_add_integration, tag_docker_push_item_remove_no_src_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        tag_docker_instance.run()


@mock.patch("pubtools._quay.command_executor.APIClient")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
@mock.patch("pubtools._quay.utils.misc.timestamp")
def test_task_iib_add_bundles(
    mock_timestamp,
    mock_run_entrypoint_operator_pusher,
    mock_manifest_claims_handler,
    mock_run_entrypoint_signature_handler,
    mock_run_entrypoint_signature_remover,
    mock_run_cmd,
    mock_send_umb_message,
    mock_api_client,
    target_settings,
    src_manifest_list,
    fake_cert_key_paths,
):
    class IIBRes:
        def __init__(self, index_image, index_image_resolved):
            self.index_image = index_image
            self.index_image_resolved = index_image_resolved

    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/new-index-image@sha256:a1a1a1",
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    mock_run_entrypoint_signature_remover.return_value = [
        {
            "reference": "registry.com/namespace/operators----index-image:8",
            "manifest_digest": "sha256:1111111111",
            "sig_key_id": "some-key",
            "repository": "operators/index-image",
            "_id": "some-id1",
        },
        {
            "reference": "registry.com/namespace/operators----index-image:8",
            "manifest_digest": "sha256:2222222222",
            "sig_key_id": "some-key",
            "repository": "operators/index-image",
            "_id": "some-id2",
        },
    ]

    mock_hub = mock.MagicMock()

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/iib-namespace/iib/manifests/sha256:a1a1a1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

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


@mock.patch("pubtools._quay.command_executor.APIClient")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_task_iib_remove_operators(
    mock_run_entrypoint_operator_pusher,
    mock_manifest_claims_handler,
    mock_run_entrypoint_signature_handler,
    mock_run_entrypoint_signature_remover,
    mock_run_cmd,
    mock_send_umb_message,
    mock_api_client,
    target_settings,
    src_manifest_list,
    fake_cert_key_paths,
):
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/new-index-image@sha256:a1a1a1",
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    mock_run_entrypoint_signature_remover.return_value = [
        {
            "reference": "registry.com/namespace/operators----index-image:8",
            "manifest_digest": "sha256:1111111111",
            "sig_key_id": "some-key",
            "repository": "operators/index-image",
            "_id": "some-id1",
        },
        {
            "reference": "registry.com/namespace/operators----index-image:8",
            "manifest_digest": "sha256:2222222222",
            "sig_key_id": "some-key",
            "repository": "operators/index-image",
            "_id": "some-id2",
        },
    ]

    mock_hub = mock.MagicMock()

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/iib-namespace/iib/manifests/sha256:a1a1a1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

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


@mock.patch("pubtools._quay.command_executor.APIClient")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_task_iib_build_from_scratch(
    mock_run_entrypoint_operator_pusher,
    mock_manifest_claims_handler,
    mock_run_entrypoint_signature_handler,
    mock_run_cmd,
    mock_send_umb_message,
    mock_api_client,
    target_settings,
    src_manifest_list,
    fake_cert_key_paths,
):
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/new-index-image@sha256:a1a1a1",
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    mock_hub = mock.MagicMock()

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/iib-namespace/iib/manifests/sha256:a1a1a1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

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


@mock.patch("pubtools._quay.untag_images.send_umb_message")
@mock.patch("pubtools._quay.clear_repo.send_umb_message")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
def test_clear_repo(
    mock_run_entrypoint_signature_remover,
    mock_send_umb_message_clear_repo,
    mock_send_umb_message_untag_images,
    src_manifest_list,
):

    mock_run_entrypoint_signature_remover.return_value = [
        {
            "reference": "registry.com/namespace/namespace----repo1:1",
            "manifest_digest": "sha256:1111111111",
            "sig_key_id": "some-key",
            "repository": "namespace/repo1",
            "_id": "some-id1",
        },
        {
            "reference": "registry.com/namespace/namespace----repo1-image:2",
            "manifest_digest": "sha256:1111111111",
            "sig_key_id": "some-key",
            "repository": "namespace/repo1",
            "_id": "some-id2",
        },
    ]

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-org/namespace----repo1/tags/list",
            json={
                "name": "namespace----repo1",
                "tags": [
                    "1",
                    "2",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/some-org/namespace----repo2/tags/list",
            json={
                "name": "namespace----repo1",
                "tags": [
                    "3",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/some-org/namespace----repo1/manifests/1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-org/namespace----repo1/manifests/2",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-org/namespace----repo2/manifests/3",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-org/namespace----repo1/tag/1",
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-org/namespace----repo1/tag/2",
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-org/namespace----repo2/tag/3",
        )

        clear_repo.clear_repositories(
            repositories="namespace/repo1,namespace/repo2",
            quay_org="some-org",
            quay_api_token="some-api-token",
            quay_user="some-user",
            quay_password="some-password",
            pyxis_server="pyxis-server.com",
            pyxis_ssl_crtfile="/path/to/file.crt",
            pyxis_ssl_keyfile="/path/to/file.key",
            send_umb_msg=False,
        )


@mock.patch("pubtools._quay.remove_repo.send_umb_message")
@mock.patch("pubtools._quay.signature_remover.run_entrypoint")
def test_remove_repo(
    mock_run_entrypoint_signature_remover,
    mock_send_umb_message_clear_repo,
    src_manifest_list,
):

    mock_run_entrypoint_signature_remover.return_value = [
        {
            "reference": "registry.com/namespace/namespace----repo1:1",
            "manifest_digest": "sha256:1111111111",
            "sig_key_id": "some-key",
            "repository": "namespace/repo1",
            "_id": "some-id1",
        },
        {
            "reference": "registry.com/namespace/namespace----repo1-image:2",
            "manifest_digest": "sha256:1111111111",
            "sig_key_id": "some-key",
            "repository": "namespace/repo1",
            "_id": "some-id2",
        },
    ]

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-org/namespace----repo1/tags/list",
            json={
                "name": "namespace----repo1",
                "tags": [
                    "1",
                    "2",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/some-org/namespace----repo2/tags/list",
            json={
                "name": "namespace----repo1",
                "tags": [
                    "3",
                ],
            },
        )
        m.get(
            "https://quay.io/v2/some-org/namespace----repo1/manifests/1",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-org/namespace----repo1/manifests/2",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-org/namespace----repo2/manifests/3",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-org/namespace----repo1",
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-org/namespace----repo2",
        )

        remove_repo.remove_repositories(
            repositories="namespace/repo1,namespace/repo2",
            quay_org="some-org",
            quay_api_token="some-api-token",
            quay_user="some-user",
            quay_password="some-password",
            pyxis_server="pyxis-server.com",
            pyxis_ssl_crtfile="/path/to/file.crt",
            pyxis_ssl_keyfile="/path/to/file.key",
            send_umb_msg=False,
        )
