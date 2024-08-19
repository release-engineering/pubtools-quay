import mock
import pytest

from pubtools._quay import exceptions
from pubtools._quay import iib_operations
from .utils.misc import IIBRes, mock_manifest_list_requests
from .fake_quay_client import FakeQuayClient

import requests_mock

# flake8: noqa: E501

FAKE_MANIFEST_LIST = {
    "manifests": [
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 7143,
            "digest": "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
            "platform": {
                "architecture": "amd64",
                "os": "linux",
            },
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 7143,
            "digest": "sha256:4c8a0e4802b39cad2608a367c6361b5b3cbedf18d8432922e253b80715be94c1",
            "platform": {
                "architecture": "ppc64le",
                "os": "linux",
            },
        },
        {
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "size": 7143,
            "digest": "sha256:20e5e8823781e9de37b20940719f8c803183399db0d91fe1d22fce9b43acfb7f",
            "platform": {
                "architecture": "s390x",
                "os": "linux",
            },
        },
    ]
}

MSG_SIGNER_OPERATION_RESULT = [
    [
        {
            "i": 0,
            "msg": {
                "errors": [],
                "manifest_digest": "sha256:bd6eba96070efe86b64"
                "b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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


@pytest.fixture
def mock_timestamp():
    with mock.patch("pubtools._quay.iib_operations.timestamp") as mocked:
        mocked.return_value = "timestamp"
        yield mocked


@pytest.fixture
def fake_quay_client():
    return FakeQuayClient()


@pytest.fixture
def fake_quay_client_get_operator_quay_client(fake_quay_client):
    with mock.patch("pubtools._quay.iib_operations._get_operator_quay_client") as mocked:
        mocked.return_value = fake_quay_client
        yield fake_quay_client


@pytest.fixture
def msg_signer_wrapper_save_signatures_file():
    with mock.patch(
        "pubtools._quay.signer_wrapper.MsgSignerWrapper._save_signatures_file"
    ) as mocked:
        mocked.return_value.__enter__.return_value.name = "signature_file"
        yield mocked


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


@pytest.fixture
def mock_get_index_image_signatures():
    mock_get_index_image_signatures = mock.MagicMock()
    mock_get_index_image_signatures.return_value = [
        {
            "signature": "value1",
            "_id": "1",
            "reference": "some-registry.com/redhat-namespace/old-index-image:8",
            "repository": "image-repo",
            "manifest_digest": "sha256:a1a1a",
            "sig_key_id": "sig-key",
        },
        {
            "signature": "value2",
            "_id": "2",
            "reference": "some-registry2.com/redhat-namespace/old-index-image:8",
            "repository": "image-repo",
            "manifest_digest": "sha256:b2b2b2",
            "sig_key_id": "sig-key",
        },
    ]
    return mock_get_index_image_signatures


def fake_setup(
    fake_quay_client_get_operator_quay_client,
    mock_iib_add_bundles,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
):
    fake_quay_client_get_operator_quay_client.f_add_manifest(
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        FAKE_MANIFEST_LIST,
        FakeQuayClient.MANIFEST_LIST_TYPE,
        "sha256:a1a1a1",
    )
    build_details = IIBRes(
        "some-registry.com/iib-namespace/new-index-image:8",
        "some-registry.com/iib-namespace/iib@sha256:a1a1a1",
        ["8-1"],
    )
    signer_wrapper_run_entry_point_sf = [
        # get signatures from pyxis
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:5555555555",
                "reference": "some-registry.com/operators/index-image:8",
                "sig_key_id": "key",
                "repository": "operators/index-image",
            }
        ],
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:5555555555",
                "reference": "some-registry.com/operators/index-image:8-timestamp",
                "sig_key_id": "key",
                "repository": "operators/index-image",
            }
        ],
        # filter existing
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:5555555555",
                "reference": "some-registry.com/operators/index-image:8",
                "sig_key_id": "key",
                "repository": "operators/index-image",
            }
        ],
        (True, ["some-registry.com/operators/index-image:8.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["some-registry.com/operators/index-image:8-timestamp.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        (True, ["quay.io/testing/repo:sha256-5555555555.sig"]),
        # store signatures to pyxis
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:5555555555",
                "reference": "some-registry.com/operators/index-image:8",
                "sig_key_id": "key",
                "repository": "operators/index-image",
            }
        ],
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:5555555555",
                "reference": "some-registry.com/operators/index-image:8-timestamp",
                "sig_key_id": "key",
                "repository": "operators/index-image",
            }
        ],
    ]
    signer_wrapper_run_entry_point_sf.append(
        # remove signatures from pyxis (fetch existing)
        [
            {
                "_id": 1,
                "manifest_digest": "sha256:5555555555",
                "reference": "some-registry.com/operators/index-image:8",
                "sig_key_id": "key",
                "repository": "operators/index-image",
            }
        ]
    )
    signer_wrapper_run_entry_point_sf.append((True, ["quay.io/testing/repo:sha256-5555555555.sig"]))
    signer_wrapper_run_entry_point_sf.append((True, ["quay.io/testing/repo:sha256-5555555555.sig"]))

    signer_wrapper_run_entry_point.side_effect = signer_wrapper_run_entry_point_sf

    mock_iib_add_bundles.return_value = build_details
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


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_add_bundles(
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    fake_quay_client_get_operator_quay_client,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    signer_wrapper_remove_signatures,
    msg_signer_wrapper_save_signatures_file,
    target_settings,
    fake_cert_key_paths,
    v2s1_manifest,
    src_manifest_list,
):
    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_add_bundles,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        # manifests for removal of old signatures
        m.get(
            "https://quay.io/v2/"
            "some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )
        iib_operations.task_iib_add_bundles(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:8",
            ["bundle3", "bundle4"],
            ["some-key"],
            "1",
            target_settings,
        )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/redhat-namespace/new-index-image:8",
        deprecation_list=["bundle3", "bundle4"],
        build_tags=["8-1"],
        target_settings=target_settings,
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
    assert signer_wrapper_remove_signatures.mock_calls == [
        mock.call([1]),
        # TODO: Uncomment when cosign removing signatures is enabled
        # mock.call([("operators/index-image", "sha256:5555555555")]),
    ]


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_add_bundles_missing_manifest_list(
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    fake_quay_client_get_operator_quay_client,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    signer_wrapper_remove_signatures,
    msg_signer_wrapper_save_signatures_file,
    target_settings,
    fake_cert_key_paths,
    v2s1_manifest,
    src_manifest_list,
):
    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_add_bundles,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            json=None,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        iib_operations.task_iib_add_bundles(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:8",
            ["bundle3", "bundle4"],
            ["some-key"],
            "1",
            target_settings,
        )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/redhat-namespace/new-index-image:8",
        deprecation_list=["bundle3", "bundle4"],
        build_tags=["8-1"],
        target_settings=target_settings,
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
    assert signer_wrapper_remove_signatures.mock_calls == [
        # TODO: Uncomment when cosign removing signatures is enabled
        # mock.call([]),
        mock.call([]),
    ]


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_add_bundles_operator_ns(
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    msg_signer_wrapper_save_signatures_file,
    signer_wrapper_remove_signatures,
    fake_quay_client_get_operator_quay_client,
    target_settings,
    fake_cert_key_paths,
    src_manifest_list,
    v2s1_manifest,
    fixture_run_in_parallel_signer,
):
    target_settings["quay_operator_namespace"] = "operator-ns"

    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_add_bundles,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/operator-ns/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        # call to remove old signatures
        m.get(
            "https://quay.io/"
            "v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )
        m.get(
            "https://quay.io"
            "/v2/some-namespace/operators----index-image/manifests/sha256:1111111111",
            json=v2s1_manifest,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )
        m.get(
            "https://quay.io"
            "/v2/some-namespace/operators----index-image/manifests/sha256:2222222222",
            json=v2s1_manifest,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )
        m.get(
            "https://quay.io"
            "/v2/some-namespace/operators----index-image/manifests/sha256:3333333333",
            json=v2s1_manifest,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )
        m.get(
            "https://quay.io"
            "/v2/some-namespace/operators----index-image/manifests/sha256:5555555555",
            json=v2s1_manifest,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )
        iib_operations.task_iib_add_bundles(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:8",
            ["bundle3", "bundle4"],
            ["some-key"],
            "1",
            target_settings,
        )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/redhat-namespace/new-index-image:8",
        deprecation_list=["bundle3", "bundle4"],
        build_tags=["8-1"],
        target_settings=target_settings,
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                ],
                task_id="1",
            ),
            # cosign
            mock.call(
                config_file="test-config.yml",
                signing_key="some-key",
                reference=[
                    "quay.io/operator-ns/operators----index-image:8",
                    "quay.io/operator-ns/operators----index-image:8",
                    "quay.io/operator-ns/operators----index-image:8-timestamp",
                    "quay.io/operator-ns/operators----index-image:8-timestamp",
                    "quay.io/operator-ns/operators----index-image:8",
                    "quay.io/operator-ns/operators----index-image:8-timestamp",
                    "quay.io/operator-ns/operators----index-image:8",
                    "quay.io/operator-ns/operators----index-image:8-timestamp",
                ],
                digest=[
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
    signer_wrapper_run_entry_point.assert_has_calls(
        [
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
                "pubtools-pyxis-get-signatures",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--manifest-digest",
                    mock.ANY,
                ],
                {},
            ),
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-upload-signatures"),
                "pubtools-pyxis-upload-signature",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--request-threads",
                    "7",
                    "--signatures",
                    mock.ANY,
                ],
                {},
                False,
            ),
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
                "pubtools-pyxis-get-signatures",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--manifest-digest",
                    mock.ANY,
                ],
                {},
            ),
            # Uncomment when cosign signature removal is enabled
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@manifest_list_digest",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:1111111111",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:2222222222",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:3333333333",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:5555555555",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:1111111111",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:2222222222",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:3333333333",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:5555555555",
            #     ],
            #     {},
            # ),
        ]
    )
    msg_signer_wrapper_save_signatures_file.assert_any_call(
        [
            {
                "manifest_digest": "sha256:bd6eba96070efe86b64b9"
                "a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                "reference": "some-registry.com/iib-namespace/new-index-image:8",
                "repository": "iib-namespace/new-index-image",
                "sig_key_id": "sig-key",
                "signature_data": "claim1",
            }
        ]
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
    assert signer_wrapper_remove_signatures.mock_calls == [
        mock.call([1]),
        # TODO: Uncomment when cosign removing signatures is enabled
        # mock.call([("operators/index-image", "sha256:5555555555")]),
    ]


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_remove_operators")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_remove_operators(
    mock_verify_target_settings,
    mock_iib_remove_operators,
    mock_run_tag_images,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    msg_signer_wrapper_save_signatures_file,
    signer_wrapper_remove_signatures,
    fake_quay_client_get_operator_quay_client,
    target_settings,
    fake_cert_key_paths,
    v2s1_manifest,
    src_manifest_list,
    fixture_run_in_parallel,
):
    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_remove_operators,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )

    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        # manifests for removal of old signatures
        m.get(
            "https://quay.io"
            "/v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )

        iib_operations.task_iib_remove_operators(
            ["operator1", "operator2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:5",
            ["some-key"],
            "1",
            target_settings,
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
    signer_wrapper_remove_signatures.mock_calls == [
        mock.call([1]),
        mock.call([("operators/index-image", "sha256:5555555555")]),
    ]


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_remove_operators")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_remove_operators_missing_manifest_list(
    mock_verify_target_settings,
    mock_iib_remove_operators,
    mock_run_tag_images,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    msg_signer_wrapper_save_signatures_file,
    signer_wrapper_remove_signatures,
    fake_quay_client_get_operator_quay_client,
    target_settings,
    fake_cert_key_paths,
    v2s1_manifest,
    src_manifest_list,
    fixture_run_in_parallel_signer,
):
    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_remove_operators,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            json=None,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        iib_operations.task_iib_remove_operators(
            ["operator1", "operator2"],
            ["arch1", "arch2"],
            "some-registry.com/iib-namespace/new-index-image:8",
            ["some-key"],
            "1",
            target_settings,
        )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_remove_operators.assert_called_once_with(
        operators=["operator1", "operator2"],
        archs=["arch1", "arch2"],
        index_image="some-registry.com/iib-namespace/new-index-image:8",
        build_tags=["8-1"],
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
    signer_wrapper_remove_signatures.mock_calls == [
        mock.call([1]),
        mock.call([("operators/index-image", "sha256:5555555555")]),
    ]


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_remove_operators")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_remove_operators_operator_ns(
    mock_verify_target_settings,
    mock_iib_remove_operators,
    mock_run_tag_images,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    msg_signer_wrapper_save_signatures_file,
    signer_wrapper_remove_signatures,
    fake_quay_client_get_operator_quay_client,
    target_settings,
    fake_cert_key_paths,
    src_manifest_list,
    v2s1_manifest,
    fixture_run_in_parallel_signer,
):
    target_settings["quay_operator_namespace"] = "operator-ns"

    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_remove_operators,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/operator-ns/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        # call to remove old signatures
        mock_manifest_list_requests(
            m,
            "https://quay.io"
            "/v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            src_manifest_list,
            v2s1_manifest,
        )
        iib_operations.task_iib_remove_operators(
            ["operator1", "operator2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:5",
            ["some-key"],
            "1",
            target_settings,
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
    signer_wrapper_remove_signatures.mock_calls == [
        mock.call([1]),
        mock.call([("operators/index-image", "sha256:5555555555")]),
    ]


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_build_from_scratch(
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    msg_signer_wrapper_save_signatures_file,
    signer_wrapper_remove_signatures,
    fake_quay_client_get_operator_quay_client,
    target_settings,
    fake_cert_key_paths,
    src_manifest_list,
    v2s1_manifest,
    fixture_run_in_parallel_signer,
):
    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_add_bundles,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        # call to remove old signatures
        m.get(
            "https://quay.io/v2"
            "/some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest_list_digest",
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

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        build_tags=["8-1"],
        target_settings=target_settings,
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
    signer_wrapper_run_entry_point.assert_has_calls(
        [
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
                "pubtools-pyxis-get-signatures",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--manifest-digest",
                    mock.ANY,
                ],
                {},
            ),
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-upload-signatures"),
                "pubtools-pyxis-upload-signature",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--request-threads",
                    "7",
                    "--signatures",
                    mock.ANY,
                ],
                {},
                False,
            ),
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
                "pubtools-pyxis-get-signatures",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--manifest-digest",
                    mock.ANY,
                ],
                {},
            ),
            # TODO: Uncomment when cosign signature removal is enabled
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@manifest_list_digest",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:1111111111",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:2222222222",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:3333333333",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:5555555555",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:1111111111",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:2222222222",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:3333333333",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:5555555555",
            #     ],
            #     {},
            # ),
        ]
    )
    msg_signer_wrapper_save_signatures_file.assert_any_call(
        [
            {
                "manifest_digest": "sha256:bd6eba96070efe"
                "86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                "reference": "some-registry.com/iib-namespace/new-index-image:8",
                "repository": "iib-namespace/new-index-image",
                "sig_key_id": "sig-key",
                "signature_data": "claim1",
            }
        ]
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


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_build_from_scratch_missing_manifest_list(
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    msg_signer_wrapper_save_signatures_file,
    signer_wrapper_remove_signatures,
    fake_quay_client_get_operator_quay_client,
    target_settings,
    fake_cert_key_paths,
    src_manifest_list,
    v2s1_manifest,
    fixture_run_in_parallel,
):
    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_add_bundles,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            json=None,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        iib_operations.task_iib_build_from_scratch(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "8",
            ["some-key"],
            "1",
            target_settings,
        )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        build_tags=["8-1"],
        target_settings=target_settings,
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
    signer_wrapper_run_entry_point.assert_has_calls(
        [
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-upload-signatures"),
                "pubtools-pyxis-upload-signature",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--request-threads",
                    "7",
                    "--signatures",
                    "@signature_file",
                ],
                {},
                False,
            ),
        ]
    )
    msg_signer_wrapper_save_signatures_file.assert_any_call(
        [
            {
                "manifest_digest": "sha256:bd6eba96070efe"
                "86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                "reference": "some-registry.com/iib-namespace/new-index-image:8",
                "repository": "iib-namespace/new-index-image",
                "sig_key_id": "sig-key",
                "signature_data": "claim1",
            }
        ]
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


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_build_from_scratch_operator_ns(
    mock_verify_target_settings,
    mock_iib_add_bundles,
    mock_run_tag_images,
    mock_timestamp,
    mock_get_index_image_signatures,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    msg_signer_wrapper_save_signatures_file,
    signer_wrapper_remove_signatures,
    fake_quay_client_get_operator_quay_client,
    target_settings,
    fake_cert_key_paths,
    v2s1_manifest,
    src_manifest_list,
    fixture_run_in_parallel_signer,
):
    target_settings["quay_operator_namespace"] = "operator-ns"
    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_add_bundles,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )
    # mock_get_index_image_signatures)
    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/operator-ns/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        # call to remove old signatures
        mock_manifest_list_requests(
            m,
            "https://quay.io"
            "/v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            src_manifest_list,
            v2s1_manifest,
        )
        iib_operations.task_iib_build_from_scratch(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "8",
            ["some-key"],
            "1",
            target_settings,
        )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_bundles.assert_called_once_with(
        bundles=["bundle1", "bundle2"],
        archs=["arch1", "arch2"],
        build_tags=["8-1"],
        target_settings=target_settings,
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
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                ],
                task_id="1",
            ),
            # cosign
            mock.call(
                config_file="test-config.yml",
                signing_key="some-key",
                reference=[
                    "quay.io/operator-ns/operators----index-image:8",
                    "quay.io/operator-ns/operators----index-image:8",
                    "quay.io/operator-ns/operators----index-image:8-timestamp",
                    "quay.io/operator-ns/operators----index-image:8-timestamp",
                    "quay.io/operator-ns/operators----index-image:8",
                    "quay.io/operator-ns/operators----index-image:8-timestamp",
                    "quay.io/operator-ns/operators----index-image:8",
                    "quay.io/operator-ns/operators----index-image:8-timestamp",
                ],
                digest=[
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:a1a1a1",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                    "sha256:bd6eba96070efe86b64b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
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
    signer_wrapper_run_entry_point.assert_has_calls(
        [
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
                "pubtools-pyxis-get-signatures",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--manifest-digest",
                    mock.ANY,
                ],
                {},
            ),
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-upload-signatures"),
                "pubtools-pyxis-upload-signature",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--request-threads",
                    "7",
                    "--signatures",
                    mock.ANY,
                ],
                {},
                False,
            ),
            mock.call(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
                "pubtools-pyxis-get-signatures",
                [
                    "--pyxis-server",
                    "pyxis-url.com",
                    "--pyxis-ssl-crtfile",
                    "/path/to/file.crt",
                    "--pyxis-ssl-keyfile",
                    "/path/to/file.key",
                    "--manifest-digest",
                    mock.ANY,
                ],
                {},
            ),
            # TODO: Uncomment when cosign signature removal is enabled
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@manifest_list_digest",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:1111111111",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:2222222222",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:3333333333",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:5555555555",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:1111111111",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:2222222222",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:3333333333",
            #     ],
            #     {},
            # ),
            # mock.call(
            #     ("pubtools-sign", "modules", "pubtools-sign-cosign-signature-list"),
            #     None,
            #     [
            #         "test-config.yml",
            #         "quay.io/some-namespace/operators----index-image@sha256:5555555555",
            #     ],
            #     {},
            # ),
        ]
    )
    msg_signer_wrapper_save_signatures_file.assert_any_call(
        [
            {
                "manifest_digest": "sha256:bd6eba96070efe86b6"
                "4b9a212680ca6d46a2e30f0a7d8e539f657eabc45c35a6",
                "reference": "some-registry.com/iib-namespace/new-index-image:8",
                "repository": "iib-namespace/new-index-image",
                "sig_key_id": "sig-key",
                "signature_data": "claim1",
            }
        ]
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


@mock.patch("pubtools._quay.iib_operations.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_deprecations")
@mock.patch("pubtools._quay.iib_operations.verify_target_settings")
def test_task_iib_add_deprecations(
    mock_verify_target_settings,
    mock_iib_add_deprecations,
    mock_run_tag_images,
    mock_timestamp,
    signer_wrapper_entry_point,
    signer_wrapper_run_entry_point,
    msg_signer_wrapper_save_signatures_file,
    signer_wrapper_remove_signatures,
    fake_quay_client_get_operator_quay_client,
    target_settings,
    fake_cert_key_paths,
    v2s1_manifest,
    src_manifest_list,
    fixture_run_in_parallel,
):
    fake_setup(
        fake_quay_client_get_operator_quay_client,
        mock_iib_add_deprecations,
        signer_wrapper_entry_point,
        signer_wrapper_run_entry_point,
    )

    with requests_mock.Mocker() as m:
        mock_manifest_list_requests(
            m,
            "https://quay.io/v2/some-namespace/operators----index-image/manifests/8",
            src_manifest_list,
            v2s1_manifest,
        )
        # manifests for removal of old signatures
        m.get(
            "https://quay.io"
            "/v2/some-namespace/operators----index-image/manifests/manifest_list_digest",
            json=src_manifest_list,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json",
                "docker-content-digest": "manifest_list_digest",
            },
        )

        iib_operations.task_iib_add_deprecations(
            "some-registry.com/redhat-namespace/new-index-image:5",
            '{"a": "b"}',
            "operator1",
            ["some-key"],
            "1",
            target_settings,
        )

    mock_verify_target_settings.assert_called_once_with(target_settings)
    mock_iib_add_deprecations.assert_called_once_with(
        index_image="some-registry.com/redhat-namespace/new-index-image:5",
        deprecation_schema='{"a": "b"}',
        operator_package="operator1",
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
    signer_wrapper_remove_signatures.mock_calls == [
        mock.call([1]),
        mock.call([("operators/index-image", "sha256:5555555555")]),
    ]


@mock.patch("pubtools._quay.iib_operations.task_iib_add_bundles")
def test_iib_add_entrypoint(mock_add_bundles, target_settings):
    iib_operations.iib_add_entrypoint(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["bundle3", "bundle4"],
        ["some-key"],
        "1",
        target_settings,
    )

    mock_add_bundles.assert_called_once_with(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["bundle3", "bundle4"],
        ["some-key"],
        "1",
        target_settings,
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_remove_operators")
def test_iib_remove_entrypoint(mock_remove_operators, target_settings):
    iib_operations.iib_remove_entrypoint(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["some-key"],
        "1",
        target_settings,
    )

    mock_remove_operators.assert_called_once_with(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "some-registry.com/index-image:5",
        ["some-key"],
        "1",
        target_settings,
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_build_from_scratch")
def test_iib_from_scratch_entrypoint(mock_build_from_scratch, target_settings):
    iib_operations.iib_from_scratch_entrypoint(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        ["some-key"],
        "1",
        target_settings,
    )

    mock_build_from_scratch.assert_called_once_with(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "12",
        ["some-key"],
        "1",
        target_settings,
    )


@mock.patch("pubtools._quay.iib_operations.task_iib_add_deprecations")
def test_iib_add_deprecations(mock_add_deprecations, target_settings):
    iib_operations.iib_add_deprecations_entrypoint(
        "some-registry.com/redhat-namespace/new-index-image:5",
        '{"a": "b"}',
        "operator1",
        ["some-key"],
        "1",
        target_settings,
    )

    mock_add_deprecations.assert_called_once_with(
        "some-registry.com/redhat-namespace/new-index-image:5",
        '{"a": "b"}',
        "operator1",
        ["some-key"],
        "1",
        target_settings,
    )


@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
def test_task_iib_add_bundles_fail(mock_iib_add_bundles, target_settings):
    mock_iib_add_bundles.return_value = False
    with pytest.raises(SystemExit):
        iib_operations.task_iib_add_bundles(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:5",
            ["bundle3", "bundle4"],
            ["some-key"],
            "1",
            target_settings,
        )


@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_remove_operators")
def test_task_iib_remove_operators_fail(mock_iib_remove_operators, target_settings):
    mock_iib_remove_operators.return_value = False
    with pytest.raises(SystemExit):
        iib_operations.task_iib_remove_operators(
            ["operator1", "operator2"],
            ["arch1", "arch2"],
            "some-registry.com/redhat-namespace/new-index-image:5",
            ["some-key"],
            "1",
            target_settings,
        )


@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_bundles")
def test_task_iib_build_from_scratch_fail(mock_iib_add_bundles, target_settings):
    mock_iib_add_bundles.return_value = False
    with pytest.raises(SystemExit):
        iib_operations.task_iib_build_from_scratch(
            ["bundle1", "bundle2"],
            ["arch1", "arch2"],
            "12",
            ["some-key"],
            "1",
            target_settings,
        )


@mock.patch("pubtools._quay.iib_operations.OperatorPusher.iib_add_deprecations")
def test_task_iib_add_deprecations_fail(mock_iib_add_deprecations, target_settings):
    mock_iib_add_deprecations.return_value = False
    with pytest.raises(SystemExit):
        iib_operations.task_iib_add_deprecations(
            "some-registry.com/redhat-namespace/new-index-image:5",
            '{"a": "b"}',
            "operator1",
            ["some-key"],
            "1",
            target_settings,
        )
