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
from pubtools._quay.exceptions import BadPushItem
from .utils.misc import (
    sort_dictionary_sortable_values,
    compare_logs,
    IIBRes,
    mock_manifest_list_requests,
)

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


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
@mock.patch("pubtools._quay.utils.misc.run_entrypoint")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.push_docker.timestamp")
def test_push_docker_multiarch_merge_ml_operator(
    mock_timestamp,
    mock_run_cmd,
    mock_run_entrypoint_operator_pusher,
    mock_run_entrypoint_misc,
    mock_api_client,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item_integration,
    operator_push_item_ok,
    src_manifest_list,
    dest_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    signer_wrapper_remove_signatures,
    fixture_run_in_parallel_signer,
    fixture_run_in_parallel_push_docker,
):
    mock_timestamp.return_value = "timestamp"
    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
            "pyxis_server": "",
        }
    }
    hub.worker.get_target_info = mock_get_target_info
    target_settings["propagated_from"] = "test-target"

    mock_run_entrypoint_misc.side_effect = [
        # pubtools-pyxis-get-repo-metadata
        {"fbc_opt_in": False},
        {"fbc_opt_in": False},
        # pubtools-pyxis-get-repo-metadata in get_index_images
        {"fbc_opt_in": False},
        {"fbc_opt_in": False},
    ]
    signer_wrapper_run_entry_point.side_effect = [
        # fetch existing signatures
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:5555555555x",
                "reference": "some-registry1.com/target/repo:latest-test-tag",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
            }
        ],
        # store signed
        [],
        [],
        # fetch existing manfiests
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:6666666666a",
                "reference": "some-registry1.com/namespace/operators/index-image:v4.5",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
            }
        ],
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:6666666666a",
                "reference": "some-registry1.com/namespace/operators/index-image:v4.5",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
            }
        ],
        # store signed
        [],
        # filter existing manifests
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:6666666666",
                "reference": "some-registry1.com/namespace/operators/index-image:v4.5",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
            }
        ],
        # list existing signatures
        (True, ["quay.io/testing/repo:v4.5"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig1"]),
        (True, ["quay.io/testing/repo:v4.6"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig1"]),
        [],
        [],
        [],
        # filter to remove
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:6666666666",
                "reference": "some-registry1.com/operators/index-image:v4.5",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
            }
        ],
        # filter to remove
        [],
        [],
        [],
        [],
        [],
        [],
        (True, ["quay.io/testing/repo:v4.5"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig1"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig1"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig2"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig3"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig4"]),
        # remove existing signatures
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:6666666666",
                "reference": "some-registry2.com/operators/index-image:v4.5",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
            }
        ],
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:6666666666",
                "reference": "some-registry1.com/operators/index-image:v4.6",
                "sig_key_id": "some-key",
                "repository": "operators/index-image",
            }
        ],
        # remove signatures (list signatures)
        (True, ["quay.io/testing/repo:sha256-6666666666.sig5"]),
        (True, ["quay.io/testing/repo:sha256-6666666666.sig6"]),
    ]
    mock_run_entrypoint_operator_pusher.side_effect = [
        # pubtools-pyxis-get-operator-indices
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}],
        # pubtools-iib-add-bundles (4.5)
        IIBRes(
            "registry.com/namespace/index-image@sha256:v4.5",
            "registry.com/namespace/iib@sha256:a1a1a1",
            ["v4.5-1"],
        ),
        # pubtools-iib-add-bundles (4.6)
        IIBRes(
            "registry.com/namespace/index-image@sha256:v4.6",
            "registry.com/namespace/iib@sha256:b2b2b2",
            ["v4.6-1"],
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
        mock_manifest_list_requests(
            m, "https://quay.io/v2/src/repo/manifests/1", src_manifest_list, v2s1_manifest
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            dest_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo/manifests/sha256:9daac465523ce42a89e605151734e7b92c5ade2123055a6a2aeabbf60e5edfa4",
            dest_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/v4.5",
            dest_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/v4.6",
            dest_manifest_list,
            v2s1_manifest,
        )
        m.put("https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag")
        m.get("https://git-server.com/v4_5.yml/raw?ref=master")
        m.get("https://git-server.com/v4_6.yml/raw?ref=master")
        mock_manifest_list_requests(
            m, "https://quay.io/v2/namespace/iib/manifests/v4.5-1", src_manifest_list, v2s1_manifest
        )
        mock_manifest_list_requests(
            m, "https://quay.io/v2/namespace/iib/manifests/v4.6-1", src_manifest_list, v2s1_manifest
        )
        m.delete("https://pyxis-url.com/v1/signatures/id/some-id1")
        m.delete("https://pyxis-url.com/v1/signatures/id/some-id2")
        mock_manifest_list_requests(
            m, "https://some-registry1.com/v2/repo/manifests/1.0", src_manifest_list, v2s1_manifest
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

        push_docker = PushDocker(
            [container_multiarch_push_item_integration, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        push_docker.run()
        signer_wrapper_entry_point.assert_has_calls(
            [
                # msg signing wrapper
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                    ],
                    digest=[
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:5555555555",
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:5555555555",
                    ],
                    task_id="1",
                ),
                # cosign
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                    ],
                    digest=[
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "sha256:1111111111",
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:3333333333",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    identity=[
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                    ],
                ),
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "some-registry1.com/operators/index-image:v4.5",
                        "some-registry1.com/operators/index-image:v4.5-timestamp",
                        "some-registry2.com/operators/index-image:v4.5",
                        "some-registry2.com/operators/index-image:v4.5-timestamp",
                    ],
                    digest=[
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    task_id="1",
                ),
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "some-registry1.com/operators/index-image:v4.6",
                        "some-registry1.com/operators/index-image:v4.6-timestamp",
                        "some-registry2.com/operators/index-image:v4.6",
                        "some-registry2.com/operators/index-image:v4.6-timestamp",
                    ],
                    digest=[
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    task_id="1",
                ),
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "quay.io/some-namespace/operators----index-image:v4.5",
                        "quay.io/some-namespace/operators----index-image:v4.5",
                        "quay.io/some-namespace/operators----index-image:v4.5-timestamp",
                        "quay.io/some-namespace/operators----index-image:v4.5-timestamp",
                        "quay.io/some-namespace/operators----index-image:v4.5",
                        "quay.io/some-namespace/operators----index-image:v4.5-timestamp",
                        "quay.io/some-namespace/operators----index-image:v4.5",
                        "quay.io/some-namespace/operators----index-image:v4.5-timestamp",
                    ],
                    digest=[
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    identity=[
                        "some-registry1.com/operators/index-image:v4.5",
                        "some-registry2.com/operators/index-image:v4.5",
                        "some-registry1.com/operators/index-image:v4.5-timestamp",
                        "some-registry2.com/operators/index-image:v4.5-timestamp",
                        "some-registry1.com/operators/index-image:v4.5",
                        "some-registry1.com/operators/index-image:v4.5-timestamp",
                        "some-registry2.com/operators/index-image:v4.5",
                        "some-registry2.com/operators/index-image:v4.5-timestamp",
                    ],
                ),
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "quay.io/some-namespace/operators----index-image:v4.6",
                        "quay.io/some-namespace/operators----index-image:v4.6",
                        "quay.io/some-namespace/operators----index-image:v4.6-timestamp",
                        "quay.io/some-namespace/operators----index-image:v4.6-timestamp",
                        "quay.io/some-namespace/operators----index-image:v4.6",
                        "quay.io/some-namespace/operators----index-image:v4.6-timestamp",
                        "quay.io/some-namespace/operators----index-image:v4.6",
                        "quay.io/some-namespace/operators----index-image:v4.6-timestamp",
                    ],
                    digest=[
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    identity=[
                        "some-registry1.com/operators/index-image:v4.6",
                        "some-registry2.com/operators/index-image:v4.6",
                        "some-registry1.com/operators/index-image:v4.6-timestamp",
                        "some-registry2.com/operators/index-image:v4.6-timestamp",
                        "some-registry1.com/operators/index-image:v4.6",
                        "some-registry1.com/operators/index-image:v4.6-timestamp",
                        "some-registry2.com/operators/index-image:v4.6",
                        "some-registry2.com/operators/index-image:v4.6-timestamp",
                    ],
                ),
            ]
        )
        assert signer_wrapper_remove_signatures.mock_calls == [
            mock.call([1]),
            # TODO: uncomment when removing of signatures in cosign is enabled
            # mock.call([("operators/index-image", "sha256:6666666666")]),
        ]


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
def test_push_docker_multiarch_simple_workflow(
    mock_run_cmd,
    mock_api_client,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item_integration,
    src_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    fixture_run_in_parallel,
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
    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/stage-namespace/test_namespace----test_repo/tags/list",
            json={"some-data": "value"},
        )
        mock_manifest_list_requests(
            m, "https://quay.io/v2/src/repo/manifests/1", src_manifest_list, v2s1_manifest
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo/manifests/sha256:8ce181d89b7bb7f1639d8df3d65d630b1322d0bb6daff5c492eec24ec53628d5",
            src_manifest_list,
            v2s1_manifest,
        )
        m.put(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
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

        push_docker = PushDocker(
            [container_multiarch_push_item_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        push_docker.run()
        signer_wrapper_entry_point.assert_has_calls(
            [
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                    ],
                    digest=[
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:5555555555",
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:5555555555",
                    ],
                    task_id="1",
                ),
                # cosign
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                    ],
                    digest=[
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "sha256:1111111111",
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:3333333333",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    identity=[
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                    ],
                ),
            ]
        )


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.push_docker.PushDocker.fetch_missing_push_items_digests")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
def test_push_docker_source(
    mock_run_cmd,
    mock_api_client,
    mock_fetch_missing_push_items_digests,
    mock_security_manifest_pusher,
    target_settings,
    container_source_push_item_integration,
    src_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
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

    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m, "https://quay.io/v2/src/repo/manifests/1", src_manifest_list, v2s1_manifest
        )
        m.get(
            "https://quay.io/v2/stage-namespace/test_namespace----test_repo/tags/list",
            json={"some-data": "value"},
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            src_manifest_list,
            v2s1_manifest,
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/1.0",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo/manifests/sha256:8ce181d89b7bb7f1639d8df3d65d630b1322d0bb6daff5c492eec24ec53628d5",
            src_manifest_list,
            v2s1_manifest,
        )

        m.put(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
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

        push_docker = PushDocker(
            [container_source_push_item_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        def mock_fetch_missing_push_items_digests_sf(push_items):
            fake_digest_counter = 0
            ret = {}
            for item in push_items:
                ret["quay.io"] = {
                    "target/repo": {
                        "latest-test-tag": {
                            "application/vnd.docker.distribution.manifest.v2+json": (
                                "fake-digest-%s" % fake_digest_counter,
                                "fake-sign-key",
                            )
                        }
                    }
                }
                fake_digest_counter += 1
            return ret

        mock_fetch_missing_push_items_digests.side_effect = mock_fetch_missing_push_items_digests_sf

        push_docker.run()
        signer_wrapper_entry_point.assert_has_calls(
            [
                mock.call(
                    config_file="test-config.yml",
                    signing_key="fake-sign-key",
                    reference=[
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                    ],
                    digest=["fake-digest-0", "fake-digest-0"],
                    task_id="1",
                ),
                mock.call(
                    config_file="test-config.yml",
                    signing_key="fake-sign-key",
                    reference=[
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                    ],
                    digest=["fake-digest-0", "fake-digest-0"],
                    identity=[
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                    ],
                ),
            ]
        )


@mock.patch("subprocess.Popen")
def test_tag_docker_multiarch_merge_ml(
    mock_popen,
    target_settings,
    tag_docker_push_item_add_integration,
    tag_docker_push_item_remove_no_src_integration,
    src_manifest_list,
    fake_cert_key_paths,
    v2s1_manifest,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
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

    mock_popen.return_value.communicate.return_value = ("Login Succeeded", "err")
    mock_popen.return_value.returncode = 0

    src_manifest_list_missing = deepcopy(src_manifest_list)
    src_manifest_list_missing["manifests"] = src_manifest_list_missing["manifests"][:2]

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
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            src_manifest_list,
            v2s1_manifest,
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
            status_code=404,
            text="Not Found",
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
        # manifests for removal of old signatures
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/sha256:1111111111",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/sha256:5555555555",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        tag_docker_instance = TagDocker(
            [tag_docker_push_item_add_integration, tag_docker_push_item_remove_no_src_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )
        tag_docker_instance.run()
        signer_wrapper_entry_point.assert_has_calls(
            [
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "some-registry1.com/namespace/test_repo:v1.6",
                        "some-registry2.com/namespace/test_repo:v1.6",
                        "some-registry1.com/namespace/test_repo:v1.6",
                        "some-registry2.com/namespace/test_repo:v1.6",
                    ],
                    digest=[
                        "sha256:1111111111",
                        "sha256:1111111111",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    task_id="1",
                ),
                # cosign
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "quay.io/some-namespace/namespace----test_repo:v1.6",
                        "quay.io/some-namespace/namespace----test_repo:v1.6",
                        "quay.io/some-namespace/namespace----test_repo:v1.6",
                        "quay.io/some-namespace/namespace----test_repo:v1.6",
                        "quay.io/some-namespace/namespace----test_repo:v1.6",
                        "quay.io/some-namespace/namespace----test_repo:v1.6",
                    ],
                    digest=[
                        "sha256:1111111111",
                        "sha256:1111111111",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5fd7b41b6f2af60c0dd393623acd01a7010eebbea85a525137cb5de35d19b8e8",
                        "sha256:5fd7b41b6f2af60c0dd393623acd01a7010eebbea85a525137cb5de35d19b8e8",
                    ],
                    identity=[
                        "some-registry1.com/namespace/test_repo:v1.6",
                        "some-registry2.com/namespace/test_repo:v1.6",
                        "some-registry1.com/namespace/test_repo:v1.6",
                        "some-registry2.com/namespace/test_repo:v1.6",
                        "some-registry1.com/namespace/test_repo:v1.6",
                        "some-registry2.com/namespace/test_repo:v1.6",
                    ],
                ),
            ]
        )


@mock.patch("subprocess.Popen")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
def test_tag_docker_source_copy_untag(
    mock_run_cmd,
    mock_api_client,
    mock_popen,
    target_settings,
    tag_docker_push_item_add_integration,
    tag_docker_push_item_remove_no_src_integration,
    v2s2_manifest_data,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {
        "settings": {
            "quay_namespace": "stage-namespace",
            "dest_quay_user": "stage-user",
            "dest_quay_password": "stage-password",
            "signing": [{"enabled": True, "label": "msg_signer", "config_file": "test-config.yml"}],
        }
    }
    hub.worker.get_target_info = mock_get_target_info
    target_settings["propagated_from"] = "test-target"

    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}
    mock_popen.return_value.communicate.side_effect = [
        ("something", "err"),
        ("Login Succeeded", "err"),
        ('{"Architecture": "amd64"}', "err"),
        ('{"Architecture": "amd64"}', "err"),
        ('{"Architecture": "amd64"}', "err"),
        ('{"Architecture": "amd64"}', "err"),
    ]
    mock_popen.return_value.returncode = 0
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
            "https://quay.io/v2/some-namespace/test_repo2/manifests/v1.6",
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
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/stage-namespace/namespace----test_repo2/manifests/v1.8",
            status_code=404,
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/test_repo?includeTags=True",
            json={
                "tags": {
                    "v1.5": {"manifest_digest": "a1a1a1"},
                    "v1.6": {"manifest_digest": "b2b2b2"},
                }
            },
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.6",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.put(
            "https://quay.io/v2/some-namespace/test_repo/manifests/v1.6",
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.8",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/test_repo2?includeTags=True",
            json={"tags": {"v1.8": {"manifest_digest": "c3c3c3", "image_id": "some-id"}}},
        )
        m.put(
            "https://quay.io/v2/some-namespace/test_repo2/manifests/v1.8",
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-namespace/namespace----test_repo2/tag/v1.8",
        )

        # manifest for removal of old signatures
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/sha256:6ef06d8c90c863ba4eb4297f1073ba8cb28c1f6570e2206cdaad2084e2a4715d",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/sha256:6ef06d8c90c863ba4eb4297f1073ba8cb28c1f6570e2206cdaad2084e2a4715d",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        tag_docker_instance = TagDocker(
            [tag_docker_push_item_add_integration, tag_docker_push_item_remove_no_src_integration],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        tag_docker_instance.run()
        signer_wrapper_entry_point.assert_has_calls(
            [
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "some-registry1.com/namespace/test_repo:v1.6",
                        "some-registry2.com/namespace/test_repo:v1.6",
                    ],
                    digest=[
                        "sha256:6ef06d8c90c863ba4eb4297f1073ba8cb28c1f6570e2206cdaad2084e2a4715d",
                        "sha256:6ef06d8c90c863ba4eb4297f1073ba8cb28c1f6570e2206cdaad2084e2a4715d",
                    ],
                    task_id="1",
                ),
                # cosign
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "quay.io/some-namespace/namespace----test_repo:v1.6",
                        "quay.io/some-namespace/namespace----test_repo:v1.6",
                    ],
                    digest=[
                        "sha256:6ef06d8c90c863ba4eb4297f1073ba8cb28c1f6570e2206cdaad2084e2a4715d",
                        "sha256:6ef06d8c90c863ba4eb4297f1073ba8cb28c1f6570e2206cdaad2084e2a4715d",
                    ],
                    identity=[
                        "some-registry1.com/namespace/test_repo:v1.6",
                        "some-registry2.com/namespace/test_repo:v1.6",
                    ],
                ),
            ]
        )


# @mock.patch("subprocess.Popen")
# @mock.patch("pubtools._quay.command_executor.docker.APIClient")
# @mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
# def test_tag_docker_source_copy_untag_missing_source_tags(
#     mock_run_cmd,
#     mock_api_client,
#     mock_popen,
#     target_settings,
#     tag_docker_push_item_add_integration,
#     tag_docker_push_item_remove_no_src_integration,
#     v2s2_manifest_data,
#     fake_cert_key_paths,
#     signer_wrapper_entry_point,
#     signer_wrapper_run_entry_point,
# ):
#     hub = mock.MagicMock()
#     mock_get_target_info = mock.MagicMock()
#     mock_get_target_info.return_value = {
#         "settings": {
#             "quay_namespace": "stage-namespace",
#             "dest_quay_user": "stage-user",
#             "dest_quay_password": "stage-password",
#             "signing": [{"enabled": True, "label": "msg_signer", "config_file": "test-config.yml"}],
#         }
#     }
#     hub.worker.get_target_info = mock_get_target_info
#     target_settings["propagated_from"] = "test-target"
#
#     mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
#     mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}
#     mock_popen.return_value.communicate.side_effect = [
#         ("something", "err"),
#         ("Login Succeeded", "err"),
#         ('{"Architecture": "amd64"}', "err"),
#         ('{"Architecture": "amd64"}', "err"),
#         ('{"Architecture": "amd64"}', "err"),
#         ('{"Architecture": "amd64"}', "err"),
#     ]
#     mock_popen.return_value.returncode = 0
#     signer_wrapper_entry_point.return_value = {
#         "signer_result": {
#             "status": "ok",
#         },
#         "operation": {
#             "references": ["some-registry.com/iib-namespace/new-index-image:8"],
#             "manifests": [
#                 "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6"
#             ],
#         },
#         "operation_results": MSG_SIGNER_OPERATION_RESULT,
#         "signing_key": "sig-key",
#     }
#
#     with requests_mock.Mocker() as m:
#         m.get(
#             "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
#             status_code=404,
#             headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
#         )
#         m.get(
#             "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.5",
#             json=v2s2_manifest_data,
#             headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
#         )
#         m.get(
#             "https://quay.io/v2/some-namespace/test_repo2/manifests/v1.6",
#             json=v2s2_manifest_data,
#             headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
#         )
#         m.get(
#             "https://quay.io/v2/stage-namespace/namespace----test_repo/tags/list",
#             json={
#                 "name": "namespace----test_repo",
#                 "tags": [
#                     "v1.5",
#                     "v1.6",
#                 ],
#             },
#         )
#         m.get(
#             "https://quay.io/v2/some-namespace/namespace----test_repo/tags/list",
#             json={
#                 "name": "namespace----test_repo",
#                 "tags": [
#                     "v1.5",
#                     "v1.6",
#                 ],
#             },
#         )
#         m.get(
#             "https://quay.io/v2/stage-namespace/namespace----test_repo2/tags/list",
#             json={
#                 "name": "namespace----test_repo2",
#                 "tags": [
#                     "v1.5",
#                     "v1.6",
#                 ],
#             },
#         )
#         m.get(
#             "https://quay.io/v2/some-namespace/namespace----test_repo2/tags/list",
#             json={
#                 "name": "namespace----test_repo2",
#                 "tags": [
#                     "v1.5",
#                     "v1.6",
#                 ],
#             },
#         )
#         m.get(
#             "https://quay.io/v2/stage-namespace/namespace----test_repo/manifests/v1.6",
#             json=v2s2_manifest_data,
#             headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
#         )
#         m.get(
#             "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.6",
#             json=v2s2_manifest_data,
#             headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
#         )
#         m.get(
#             "https://quay.io/v2/stage-namespace/namespace----test_repo2/manifests/v1.8",
#             headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
#             json=v2s2_manifest_data,
#         )
#         m.get(
#             "https://quay.io/api/v1/repository/some-namespace/test_repo?includeTags=True",
#             json={
#                 "tags": {
#                     "v1.5": {"manifest_digest": "a1a1a1"},
#                     "v1.6": {"manifest_digest": "b2b2b2"},
#                 }
#             },
#         )
#         m.get(
#             "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.6",
#             status_code=404
#         )
#         m.put(
#             "https://quay.io/v2/some-namespace/test_repo/manifests/v1.6",
#         )
#         m.get(
#             "https://quay.io/v2/some-namespace/namespace----test_repo2/manifests/v1.8",
#             json=v2s2_manifest_data,
#             headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
#         )
#         m.get(
#             "https://quay.io/api/v1/repository/some-namespace/test_repo2?includeTags=True",
#             json={"tags": {"v1.8": {"manifest_digest": "c3c3c3", "image_id": "some-id"}}},
#         )
#         m.put(
#             "https://quay.io/v2/some-namespace/test_repo2/manifests/v1.8",
#         )
#         m.delete(
#             "https://quay.io/api/v1/repository/some-namespace/namespace----test_repo2/tag/v1.8",
#         )
#
#         tag_docker_instance = TagDocker(
#             [tag_docker_push_item_add_integration, tag_docker_push_item_remove_no_src_integration],
#             hub,
#             "1",
#             "some-target",
#             target_settings,
#         )
#         with pytest.raises(BadPushItem):
#             tag_docker_instance.run()


@mock.patch("pubtools._quay.command_executor.docker.APIClient")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
@mock.patch("pubtools._quay.iib_operations.timestamp")
def test_task_iib_add_bundles(
    mock_timestamp,
    mock_run_entrypoint_operator_pusher,
    mock_run_cmd,
    mock_api_client,
    target_settings,
    src_manifest_list,
    fake_cert_key_paths,
    v2s1_manifest,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    fixture_run_in_parallel,
):
    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.side_effect = [("Login Succeeded", "err"), ("Login Succeeded", "err")]
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

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
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/iib-namespace/iib/manifests/8-1",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        m.get(
            "https://quay.io/v2/iib-namespace/iib/manifests/sha256:a1a1a1",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "sha256:a1a1a1",
            },
        )
        # manifest to remove old signatures
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        iib_operations.task_iib_add_bundles(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:5",
            ["bundle3", "bundle4"],
            ["some-key"],
            "1",
            target_settings,
        )
        signer_wrapper_entry_point.assert_has_calls(
            [
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "some-registry1.com/operators/index-image:8",
                        "some-registry1.com/operators/index-image:8-timestamp",
                        "some-registry2.com/operators/index-image:8",
                        "some-registry2.com/operators/index-image:8-timestamp",
                    ],
                    digest=[
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    task_id="1",
                ),
                # cosign
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "quay.io/some-namespace/operators----index-image:8",
                        "quay.io/some-namespace/operators----index-image:8",
                        "quay.io/some-namespace/operators----index-image:8-timestamp",
                        "quay.io/some-namespace/operators----index-image:8-timestamp",
                        "quay.io/some-namespace/operators----index-image:8",
                        "quay.io/some-namespace/operators----index-image:8-timestamp",
                        "quay.io/some-namespace/operators----index-image:8",
                        "quay.io/some-namespace/operators----index-image:8-timestamp",
                    ],
                    digest=[
                        "sha256:a1a1a1",
                        "sha256:a1a1a1",
                        "sha256:a1a1a1",
                        "sha256:a1a1a1",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    identity=[
                        "some-registry1.com/operators/index-image:8",
                        "some-registry2.com/operators/index-image:8",
                        "some-registry1.com/operators/index-image:8-timestamp",
                        "some-registry2.com/operators/index-image:8-timestamp",
                        "some-registry1.com/operators/index-image:8",
                        "some-registry1.com/operators/index-image:8-timestamp",
                        "some-registry2.com/operators/index-image:8",
                        "some-registry2.com/operators/index-image:8-timestamp",
                    ],
                ),
            ]
        )


@mock.patch("pubtools._quay.command_executor.docker.APIClient")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
@mock.patch("pubtools._quay.iib_operations.timestamp")
def test_task_iib_remove_operators(
    mock_timestamp,
    mock_run_entrypoint_operator_pusher,
    mock_run_cmd,
    mock_api_client,
    target_settings,
    src_manifest_list,
    fake_cert_key_paths,
    v2s1_manifest,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    mock_timestamp.return_value = "timestamp"
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}

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
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/iib-namespace/iib/manifests/8-1",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        m.get(
            "https://quay.io/v2/iib-namespace/iib/manifests/sha256:a1a1a1",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "sha256:a1a1a1",
            },
        )
        # manifests for removal of old signatures
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        iib_operations.task_iib_remove_operators(
            ["operator1", "operator2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:5",
            ["some-key"],
            "1",
            target_settings,
        )

    signer_wrapper_entry_point.assert_has_calls(
        [
            mock.call(
                config_file="test-config.yml",
                signing_key="some-key",
                reference=[
                    "some-registry1.com/operators/index-image:8",
                    "some-registry1.com/operators/index-image:8-timestamp",
                    "some-registry2.com/operators/index-image:8",
                    "some-registry2.com/operators/index-image:8-timestamp",
                ],
                digest=[
                    "sha256:5555555555",
                    "sha256:5555555555",
                    "sha256:5555555555",
                    "sha256:5555555555",
                ],
                task_id="1",
            ),
            # cosign
            mock.call(
                config_file="test-config.yml",
                signing_key="some-key",
                reference=[
                    "quay.io/some-namespace/operators----index-image:8",
                    "quay.io/some-namespace/operators----index-image:8",
                    "quay.io/some-namespace/operators----index-image:8-timestamp",
                    "quay.io/some-namespace/operators----index-image:8-timestamp",
                    "quay.io/some-namespace/operators----index-image:8",
                    "quay.io/some-namespace/operators----index-image:8-timestamp",
                    "quay.io/some-namespace/operators----index-image:8",
                    "quay.io/some-namespace/operators----index-image:8-timestamp",
                ],
                digest=[
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:5555555555",
                    "sha256:5555555555",
                    "sha256:5555555555",
                    "sha256:5555555555",
                ],
                identity=[
                    "some-registry1.com/operators/index-image:8",
                    "some-registry2.com/operators/index-image:8",
                    "some-registry1.com/operators/index-image:8-timestamp",
                    "some-registry2.com/operators/index-image:8-timestamp",
                    "some-registry1.com/operators/index-image:8",
                    "some-registry1.com/operators/index-image:8-timestamp",
                    "some-registry2.com/operators/index-image:8",
                    "some-registry2.com/operators/index-image:8-timestamp",
                ],
            ),
        ]
    )


@mock.patch("pubtools._quay.command_executor.docker.APIClient")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_task_iib_build_from_scratch(
    mock_run_entrypoint_operator_pusher,
    mock_run_cmd,
    mock_api_client,
    target_settings,
    src_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:12",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["12-1"],
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}
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
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )
        m.get(
            "https://quay.io/v2/iib-namespace/iib/manifests/sha256:a1a1a1",
            text=json.dumps(src_manifest_list, sort_keys=True),
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "sha256:a1a1a1",
            },
        )
        iib_operations.task_iib_build_from_scratch(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "8",
            ["some-key"],
            "1",
            target_settings,
        )


@mock.patch("pubtools._quay.image_untagger.SecurityManifestPusher.cosign_triangulate_image")
def test_clear_repo(
    mock_triangulate,
    src_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_remove_signatures,
    signer_wrapper_run_entry_point,
):
    signer_wrapper_run_entry_point.return_value = [
        {
            "_id": 1,
            "manifest_digest": "sha256:1111111111",
            "reference": "registry.io/namespace/repo2:3",
            "sig_key_id": "key",
            "repository": "namespace/repo2",
        }
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

        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-org/namespace----repo1/manifests/1",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-org/namespace----repo1/manifests/2",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-org/namespace----repo2/manifests/3",
            src_manifest_list,
            v2s1_manifest,
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
            settings=dict(
                quay_org="some-org",
                quay_api_token="some-api-token",
                quay_user="some-user",
                quay_password="some-password",
                pyxis_server="pyxis-server.com",
                pyxis_ssl_crtfile="/path/to/file.crt",
                pyxis_ssl_keyfile="/path/to/file.key",
                pyxis_request_threads=7,
                signers="msg_signer,cosign_signer",
                signer_configs="/test-config.yml,/test-config.yml",
            ),
        )
        signer_wrapper_remove_signatures.assert_called_with([1])


def test_remove_repo(
    src_manifest_list,
    fake_cert_key_paths,
    signer_wrapper_remove_signatures,
    signer_wrapper_run_entry_point,
    v2s1_manifest,
):
    signer_wrapper_run_entry_point.return_value = [
        {
            "_id": 1,
            "manifest_digest": "sha256:1111111111",
            "reference": "registry.io/namespace/repo2:3",
            "sig_key_id": "key",
            "repository": "namespace/repo2",
        }
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
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-org/namespace----repo1/manifests/1",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-org/namespace----repo1/manifests/2",
            src_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-org/namespace----repo2/manifests/3",
            src_manifest_list,
            v2s1_manifest,
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-org/namespace----repo1",
        )
        m.delete(
            "https://quay.io/api/v1/repository/some-org/namespace----repo2",
        )

        remove_repo.remove_repositories(
            repositories="namespace/repo1,namespace/repo2",
            settings=dict(
                quay_org="some-org",
                quay_api_token="some-api-token",
                quay_user="some-user",
                quay_password="some-password",
                pyxis_server="pyxis-server.com",
                pyxis_ssl_crtfile="/path/to/file.crt",
                pyxis_ssl_keyfile="/path/to/file.key",
                pyxis_request_threads=7,
                signers="msg_signer,cosign_signer",
                signer_configs="/test_config.yml,/test_config.yml",
            ),
        )
        signer_wrapper_remove_signatures.assert_called_with([1])


@mock.patch("pubtools._quay.push_docker.SecurityManifestPusher")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.operator_pusher.pyxis_get_repo_metadata")
def test_push_docker_operator_verify_bundle_fail(
    mock_get_repo_metadata,
    mock_run_cmd,
    mock_run_entrypoint_operator_pusher,
    mock_api_client,
    mock_security_manifest_pusher,
    target_settings,
    container_multiarch_push_item_integration,
    operator_push_item_ok,
    src_manifest_list,
    dest_manifest_list,
    v2s1_manifest,
    fake_cert_key_paths,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    fixture_run_in_parallel_signer,
    fixture_run_in_parallel_push_docker,
    fixture_run_in_parallel_item_processor,
):
    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_run_entrypoint_operator_pusher.side_effect = [
        # pubtools-pyxis-get-operator-indices
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}],
    ]
    mock_get_repo_metadata.side_effect = [
        {"fbc_opt_in": False},
        {"fbc_opt_in": False},
        {"fbc_opt_in": False},
    ]
    mock_run_cmd.return_value = ("Login Succeeded", "err")
    mock_api_client.return_value.exec_start.return_value = b"Login Succeeded"
    mock_api_client.return_value.exec_inspect.return_value = {"ExitCode": 0}
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
            "https://quay.io/v2/some-namespace/target----repo/tags/list",
            json={"name": "target-repo", "tags": ["latest-test-tag"]},
        )
        mock_manifest_list_requests(
            m, "https://quay.io/v2/src/repo/manifests/1", src_manifest_list, v2s1_manifest
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
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/sha256:1111111111",
            text=json.dumps(v2s1_manifest, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            request_headers={"Accept": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/target----repo/manifests/sha256:9daac465523ce42a89e605151734e7b92c5ade2123055a6a2aeabbf60e5edfa4",
            dest_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/v4.5",
            dest_manifest_list,
            v2s1_manifest,
        )
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/v4.6",
            dest_manifest_list,
            v2s1_manifest,
        )
        m.put(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
            text=json.dumps(v2s1_manifest, sort_keys=True),
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

        with pytest.raises(SystemExit, match="1"):
            push_docker.run()

        signer_wrapper_entry_point.assert_has_calls(
            [
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                    ],
                    digest=[
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:5555555555",
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:5555555555",
                    ],
                    task_id="1",
                ),
                mock.call(
                    config_file="test-config.yml",
                    signing_key="some-key",
                    reference=[
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                        "quay.io/some-namespace/target----repo:latest-test-tag",
                    ],
                    digest=[
                        "manifest_list_digest",
                        "manifest_list_digest",
                        "sha256:1111111111",
                        "sha256:1111111111",
                        "sha256:2222222222",
                        "sha256:2222222222",
                        "sha256:3333333333",
                        "sha256:3333333333",
                        "sha256:5555555555",
                        "sha256:5555555555",
                    ],
                    identity=[
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                        "some-registry1.com/target/repo:latest-test-tag",
                        "some-registry2.com/target/repo:latest-test-tag",
                    ],
                ),
            ]
        )
