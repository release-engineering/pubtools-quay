import logging
import mock
import pytest
import requests_mock
from copy import deepcopy

from pubtools._quay.push_docker import PushDocker
from pubtools._quay.tag_docker import TagDocker
from pubtools._quay import iib_operations
from .utils.misc import sort_dictionary_sortable_values, compare_logs

# flake8: noqa: E501


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
    target_settings,
    container_multiarch_push_item_integration,
    operator_push_item_ok,
    src_manifest_list,
    dest_manifest_list,
):
    class IIBRes:
        def __init__(self, index_image, index_image_resolved):
            self.index_image = index_image
            self.index_image_resolved = index_image_resolved

    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {"settings": {"quay_namespace": "stage-namespace"}}
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

    mock_run_cmd.return_value = ("out", "err")

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/api/v1/repository/stage-namespace/test_namespace----test_repo?includeTags=True",
            json={"some-data": "value"},
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/target----repo?includeTags=True",
            json={"tags": {"latest-test-tag": {"manifest_digest": "a1a1a1"}}},
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
            json=dest_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put(
            "https://quay.io/v2/some-namespace/target----repo/manifests/latest-test-tag",
        )
        m.get(
            "https://git-server.com/v4_5.yml/raw?ref=master",
        )
        m.get(
            "https://git-server.com/v4_6.yml/raw?ref=master",
        )
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

        push_docker = PushDocker(
            [container_multiarch_push_item_integration, operator_push_item_ok],
            hub,
            "1",
            "some-target",
            target_settings,
        )

        push_docker.run()


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
    target_settings,
    container_multiarch_push_item_integration,
    src_manifest_list,
):
    class IIBRes:
        def __init__(self, index_image, index_image_resolved):
            self.index_image = index_image
            self.index_image_resolved = index_image_resolved

    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {"settings": {"quay_namespace": "stage-namespace"}}
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
    ]

    mock_run_cmd.return_value = ("out", "err")

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/api/v1/repository/stage-namespace/test_namespace----test_repo?includeTags=True",
            json={"some-data": "value"},
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/target----repo?includeTags=True",
            json={"tags": {"latest-test-tag": {"manifest_digest": "a1a1a1"}}},
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
    target_settings,
    container_source_push_item_integration,
    src_manifest_list,
):
    class IIBRes:
        def __init__(self, index_image, index_image_resolved):
            self.index_image = index_image
            self.index_image_resolved = index_image_resolved

    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {"settings": {"quay_namespace": "stage-namespace"}}
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
    ]

    mock_run_cmd.return_value = ("out", "err")

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/api/v1/repository/stage-namespace/test_namespace----test_repo?includeTags=True",
            json={"some-data": "value"},
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/target----repo?includeTags=True",
            json={"tags": {"latest-test-tag": {"manifest_digest": "a1a1a1"}}},
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
    target_settings,
    container_multiarch_push_item_integration,
    src_manifest_list,
):
    class IIBRes:
        def __init__(self, index_image, index_image_resolved):
            self.index_image = index_image
            self.index_image_resolved = index_image_resolved

    # hub usage has to be mocked
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {"settings": {"quay_namespace": "stage-namespace"}}
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
            "https://quay.io/api/v1/repository/stage-namespace/test_namespace----test_repo?includeTags=True",
            json={"some-data": "value"},
        )
        m.get(
            "https://quay.io/api/v1/repository/some-namespace/target----repo?includeTags=True",
            json={"tags": {"latest-test-tag": {"manifest_digest": "a1a1a1"}}},
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

        with pytest.raises(ValueError, match="something went wrong"):
            push_docker.run()


@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.push_docker.run_entrypoint")
def test_tag_docker_multiarch_merge_ml(
    mock_run_entrypoint_push_docker,
    mock_run_entrypoint_sig_handler,
    mock_claims_handler,
    target_settings,
    tag_docker_push_item_add_integration,
    tag_docker_push_item_remove_no_src_integration,
    src_manifest_list,
):
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {"settings": {"quay_namespace": "stage-namespace"}}
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

    src_manifest_list_missing = deepcopy(src_manifest_list)
    src_manifest_list_missing["manifests"] = src_manifest_list_missing["manifests"][:2]

    with requests_mock.Mocker() as m:

        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            json=src_manifest_list,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/stage-namespace/namespace----test_repo?includeTags=True",
            json={
                "tags": {
                    "v1.5": {"manifest_digest": "a1a1a1"},
                    "v1.6": {"manifest_digest": "b2b2b2"},
                }
            },
        )
        m.get(
            "https://quay.io/api/v1/repository/stage-namespace/namespace----test_repo2?includeTags=True",
            json={
                "tags": {
                    "v1.5": {"manifest_digest": "a1a1a1"},
                    "v1.6": {"manifest_digest": "b2b2b2"},
                }
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


@mock.patch("pubtools._quay.untag_images.send_umb_message")
@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.push_docker.run_entrypoint")
def test_tag_docker_source_copy_untag(
    mock_run_entrypoint_push_docker,
    mock_run_entrypoint_sig_handler,
    mock_claims_handler,
    mock_run_cmd,
    mock_send_umb_message_tag,
    mock_send_umb_message_untag,
    target_settings,
    tag_docker_push_item_add_integration,
    tag_docker_push_item_remove_no_src_integration,
    v2s2_manifest_data,
):
    hub = mock.MagicMock()
    mock_get_target_info = mock.MagicMock()
    mock_get_target_info.return_value = {"settings": {"quay_namespace": "stage-namespace"}}
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

    mock_run_cmd.return_value = ('{"Architecture": "amd64"}', "err")

    with requests_mock.Mocker() as m:

        m.get(
            "https://quay.io/v2/some-namespace/namespace----test_repo/manifests/v1.5",
            json=v2s2_manifest_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/api/v1/repository/stage-namespace/namespace----test_repo?includeTags=True",
            json={
                "tags": {
                    "v1.5": {"manifest_digest": "a1a1a1"},
                    "v1.6": {"manifest_digest": "b2b2b2"},
                }
            },
        )
        m.get(
            "https://quay.io/api/v1/repository/stage-namespace/namespace----test_repo2?includeTags=True",
            json={
                "tags": {
                    "v1.5": {"manifest_digest": "a1a1a1"},
                    "v1.6": {"manifest_digest": "b2b2b2"},
                }
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


@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_task_iib_add_bundles(
    mock_run_entrypoint_operator_pusher,
    mock_manifest_claims_handler,
    mock_run_entrypoint_signature_handler,
    mock_run_cmd,
    mock_send_umb_message,
    target_settings,
    src_manifest_list,
):
    class IIBRes:
        def __init__(self, index_image, index_image_resolved):
            self.index_image = index_image
            self.index_image_resolved = index_image_resolved

    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/new-index-image@sha256:a1a1a1",
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.return_value = ("out", "err")

    mock_hub = mock.MagicMock()

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/iib-namespace/iib/manifests/sha256:a1a1a1",
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


@mock.patch("pubtools._quay.tag_images.send_umb_message")
@mock.patch("pubtools._quay.command_executor.RemoteExecutor._run_cmd")
@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_task_iib_remove_operators(
    mock_run_entrypoint_operator_pusher,
    mock_manifest_claims_handler,
    mock_run_entrypoint_signature_handler,
    mock_run_cmd,
    mock_send_umb_message,
    target_settings,
    src_manifest_list,
):
    class IIBRes:
        def __init__(self, index_image, index_image_resolved):
            self.index_image = index_image
            self.index_image_resolved = index_image_resolved

    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/new-index-image@sha256:a1a1a1",
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.return_value = ("out", "err")

    mock_hub = mock.MagicMock()

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/iib-namespace/iib/manifests/sha256:a1a1a1",
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
    target_settings,
    src_manifest_list,
):
    class IIBRes:
        def __init__(self, index_image, index_image_resolved):
            self.index_image = index_image
            self.index_image_resolved = index_image_resolved

    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/new-index-image@sha256:a1a1a1",
    )
    mock_run_entrypoint_operator_pusher.return_value = build_details
    mock_run_cmd.return_value = ("out", "err")

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
