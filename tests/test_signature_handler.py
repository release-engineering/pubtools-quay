import json
import logging
import mock
import pytest
import requests_mock
import requests
import six

from pubtools._quay import exceptions
from pubtools._quay import quay_client
from pubtools._quay import signature_handler
from .utils.misc import sort_dictionary_sortable_values, compare_logs

# flake8: noqa: E501


@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_init(mock_quay_api_client, mock_quay_client, target_settings):
    hub = mock.MagicMock()
    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")

    assert sig_handler.hub == hub
    assert sig_handler.task_id == "1"
    assert sig_handler.dest_registries == ["some-registry1.com", "some-registry2.com"]
    assert sig_handler.target_settings == target_settings
    assert sig_handler.quay_host == "quay.io"
    mock_quay_client.assert_not_called()
    mock_quay_api_client.assert_not_called()

    assert sig_handler.src_quay_client == mock_quay_client.return_value
    assert sig_handler.src_quay_api_client == mock_quay_api_client.return_value
    mock_quay_client.assert_called_once_with("src-quay-user", "src-quay-pass", "quay.io")
    mock_quay_api_client.assert_called_once_with("src-quay-token", "quay.io")


@mock.patch("pubtools._quay.signature_handler.uuid.uuid4")
@mock.patch("pubtools._quay.signature_handler.datetime")
@mock.patch("pubtools._quay.signature_handler.base64.b64encode")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_create_claim_message(
    mock_quay_api_client, mock_quay_client, mock_encode, mock_datetime, mock_uuid, target_settings
):
    hub = mock.MagicMock()
    mock_encode.return_value = b"some-encode"
    mock_uuid.return_value = "7ed1d8fb-77bc-4222-ad6a-89f508f02d75"
    mock_datetime.utcnow.return_value.isoformat.return_value = "2021-03-19T14:45:23.128632"
    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")

    claim_msg = sig_handler.create_manifest_claim_message(
        "some-dest-repo", "key1", "sha256:f4f4f4f", "registry.com/image:1", "image", "1"
    )
    mock_encode.assert_called_with(
        json.dumps(
            {
                "critical": {
                    "type": "atomic container signature",
                    "image": {"docker-manifest-digest": "sha256:f4f4f4f"},
                    "identity": {"docker-reference": "registry.com/image:1"},
                },
                "optional": {"creator": "Red Hat RCM Pub"},
            }
        ).encode("latin1")
    )
    assert claim_msg == {
        "sig_key_id": "key1",
        "claim_file": "some-encode",
        "pub_task_id": "1",
        "request_id": "7ed1d8fb-77bc-4222-ad6a-89f508f02d75",
        "manifest_digest": "sha256:f4f4f4f",
        "repo": "some-dest-repo",
        "image_name": "image",
        "docker_reference": "registry.com/image:1",
        "created": "2021-03-19T14:45:23.128632Z",
    }


@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_get_tagged_image_digests_no_manifest_list(
    mock_quay_api_client, mock_quay_client, target_settings, repo_api_data
):
    hub = mock.MagicMock()
    mock_get_repo_data = mock.MagicMock()
    mock_get_repo_data.return_value = repo_api_data
    mock_quay_api_client.return_value.get_repository_data = mock_get_repo_data

    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")
    digests = sig_handler.get_tagged_image_digests("registry.com/namespace/image:3")

    assert digests == ["sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb"]
    mock_get_repo_data.assert_called_once_with("namespace/image")


@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_get_tagged_image_digests_manifest_list(
    mock_quay_api_client, mock_quay_client, target_settings, repo_api_data, manifest_list_data
):
    hub = mock.MagicMock()
    mock_get_repo_data = mock.MagicMock()
    mock_get_repo_data.return_value = repo_api_data
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = manifest_list_data
    mock_quay_api_client.return_value.get_repository_data = mock_get_repo_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")
    digests = sig_handler.get_tagged_image_digests("registry.com/namespace/image:1")

    assert digests == [
        "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
        "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
        "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
        "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
    ]
    mock_get_repo_data.assert_called_once_with("namespace/image")
    mock_get_manifest.assert_called_once_with("registry.com/namespace/image:1", manifest_list=True)


@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_get_pyxis_signature(
    mock_quay_api_client, mock_quay_client, mock_run_entrypoint, target_settings
):
    hub = mock.MagicMock()
    expected_data1 = [{"some": "data"}, {"other": "data"}]
    expected_data2 = [{"some-other": "data"}]
    mock_run_entrypoint.side_effect = [iter(expected_data1), iter(expected_data2)]

    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")
    sig_handler.MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST = 2
    sig_data = sig_handler.get_signatures_from_pyxis(
        ["sha256:a1a1a1a1a", "sha256:b2b2b2b2", "sha256:c3c3c3c3"]
    )
    for i, data in enumerate(sig_data):
        assert data == (expected_data1 + expected_data2)[i]

    assert mock_run_entrypoint.call_count == 2
    assert mock_run_entrypoint.mock_calls[0] == mock.call(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
        "pubtools-pyxis-get-signatures",
        [
            "--pyxis-server",
            "pyxis-url.com",
            "--pyxis-krb-principal",
            "some-principal@REDHAT.COM",
            "--pyxis-krb-ktfile",
            "/etc/pub/some.keytab",
            "--manifest-digest",
            "sha256:a1a1a1a1a,sha256:b2b2b2b2",
        ],
        {},
    )
    assert mock_run_entrypoint.mock_calls[1] == mock.call(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
        "pubtools-pyxis-get-signatures",
        [
            "--pyxis-server",
            "pyxis-url.com",
            "--pyxis-krb-principal",
            "some-principal@REDHAT.COM",
            "--pyxis-krb-ktfile",
            "/etc/pub/some.keytab",
            "--manifest-digest",
            "sha256:c3c3c3c3",
        ],
        {},
    )


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_pyxis")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_filter_claim_messages(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_signatures,
    target_settings,
    claim_messages,
    existing_signatures,
):
    hub = mock.MagicMock()
    mock_get_signatures.return_value = existing_signatures

    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")
    filtered_msgs = sig_handler.filter_claim_messages(claim_messages)
    mock_get_signatures.assert_called_once_with(
        manifest_digests=["sha256:a2a2a2a", "sha256:b3b3b3b", "sha256:f4f4f4f"]
    )

    assert filtered_msgs == [
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id3",
            "manifest_digest": "sha256:b3b3b3b",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:2",
            "created": "2021-03-19T14:45:23.128632Z",
        }
    ]


@mock.patch("pubtools._quay.signature_handler.proton")
@mock.patch("pubtools._quay.signature_handler.ManifestClaimsHandler")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_get_signatures_from_radas(
    mock_quay_api_client,
    mock_quay_client,
    mock_claim_handler,
    mock_proton,
    target_settings,
    claim_messages,
):
    hub = mock.MagicMock()
    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")

    sig_handler.get_signatures_from_radas(claim_messages)

    assert mock_claim_handler.call_args[1]["umb_urls"] == ["some-url1", "some-url2"]
    radas_addr = "queue://Consumer.msg-producer-pub.1.VirtualTopic.eng.robosignatory.container.sign"
    assert mock_claim_handler.call_args[1]["radas_address"] == radas_addr
    assert mock_claim_handler.call_args[1]["claim_messages"] == [
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id1",
            "manifest_digest": "sha256:f4f4f4f",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id2",
            "manifest_digest": "sha256:a2a2a2a",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id3",
            "manifest_digest": "sha256:b3b3b3b",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:2",
            "created": "2021-03-19T14:45:23.128632Z",
        },
    ]
    assert mock_claim_handler.call_args[1]["pub_cert"] == "/etc/pub/umb-pub-cert-key.pem"
    assert mock_claim_handler.call_args[1]["ca_cert"] == "/etc/pki/tls/certs/ca-bundle.crt"
    assert mock_claim_handler.call_args[1]["timeout"] == 600
    assert mock_claim_handler.call_args[1]["throttle"] == 100
    assert mock_claim_handler.call_args[1]["retry"] == 3

    assert len(mock_proton.mock_calls) == 2


@mock.patch("pubtools._quay.signature_handler.run_entrypoint")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_upload_signatures_pyxis(
    mock_quay_api_client,
    mock_quay_client,
    mock_run_entrypoint,
    target_settings,
    claim_messages,
    signed_messages,
):
    hub = mock.MagicMock()

    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")
    sig_handler.upload_signatures_to_pyxis(claim_messages, signed_messages, 2)

    signatures = [
        {
            "manifest_digest": "sha256:f4f4f4f",
            "reference": "registry.com/image:1",
            "repository": "image",
            "sig_key_id": "key1",
            "signature_data": "binary-data1",
        },
        {
            "manifest_digest": "sha256:a2a2a2a",
            "reference": "registry.com/image:1",
            "repository": "image",
            "sig_key_id": "key1",
            "signature_data": "binary-data2",
        },
        {
            "manifest_digest": "sha256:b3b3b3b",
            "reference": "registry.com/image:2",
            "repository": "image",
            "sig_key_id": "key1",
            "signature_data": "binary-data3",
        },
    ]

    mock_run_entrypoint.call_count == 2
    assert mock_run_entrypoint.mock_calls[0] == mock.call(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-upload-signatures"),
        "pubtools-pyxis-upload-signature",
        [
            "--pyxis-server",
            "pyxis-url.com",
            "--pyxis-krb-principal",
            "some-principal@REDHAT.COM",
            "--pyxis-krb-ktfile",
            "/etc/pub/some.keytab",
            "--signatures",
            json.dumps(signatures[:2]),
        ],
        {},
    )
    assert mock_run_entrypoint.mock_calls[1] == mock.call(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-upload-signatures"),
        "pubtools-pyxis-upload-signature",
        [
            "--pyxis-server",
            "pyxis-url.com",
            "--pyxis-krb-principal",
            "some-principal@REDHAT.COM",
            "--pyxis-krb-ktfile",
            "/etc/pub/some.keytab",
            "--signatures",
            json.dumps(signatures[2:]),
        ],
        {},
    )


@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_validate_radas_msgs(
    mock_quay_api_client, mock_quay_client, target_settings, claim_messages, error_signed_messages
):
    hub = mock.MagicMock()
    sig_handler = signature_handler.SignatureHandler(hub, "1", target_settings, "some-target")

    with pytest.raises(exceptions.SigningError, match="Signing of 2/3 messages has failed"):
        sig_handler.validate_radas_messages(claim_messages, error_signed_messages)


@mock.patch("pubtools._quay.signature_handler.base64.b64encode")
@mock.patch("pubtools._quay.signature_handler.datetime")
@mock.patch("pubtools._quay.signature_handler.uuid.uuid4")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_tagged_image_digests")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_construct_item_claim_messages(
    mock_quay_api_client,
    mock_quay_client,
    mock_get_tagged_digests,
    mock_uuid,
    mock_datetime,
    mock_encode,
    target_settings,
    container_signing_push_item,
):
    hub = mock.MagicMock()
    mock_uuid.side_effect = range(100)
    mock_encode.return_value = b"some-encode"
    mock_datetime.utcnow.return_value.isoformat.return_value = "2021-03-19T14:45:23.128632"
    mock_get_tagged_digests.return_value = [
        "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
        "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
    ]

    sig_handler = signature_handler.ContainerSignatureHandler(
        hub, "1", target_settings, "some-target"
    )

    claim_messages = sig_handler.construct_item_claim_messages(container_signing_push_item)
    with open("tests/test_data/test_expected_claim_messages.json", "r") as f:
        expected_claim_messages = json.loads(f.read())

    assert claim_messages == expected_claim_messages
    mock_get_tagged_digests.assert_called_once_with("some-registry/src/repo:1")
    assert mock_uuid.call_count == 12


@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_remove_duplicate_claim_messages(
    mock_quay_api_client, mock_quay_client, target_settings, container_signing_push_item
):
    hub = mock.MagicMock()
    sig_handler = signature_handler.ContainerSignatureHandler(
        hub, "1", target_settings, "some-target"
    )

    messages = [
        {
            "sig_key_id": "some-key",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "0",
            "manifest_digest": "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            "repo": "some-namespace/target----repo1",
            "image_name": "target/repo1",
            "docker_reference": "some-registry1.com/target/repo1:tag1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
        {
            "sig_key_id": "some-key",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "1",
            "manifest_digest": "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            "repo": "some-namespace/target----repo1",
            "image_name": "target/repo1",
            "docker_reference": "some-registry1.com/target/repo1:tag1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
    ]
    result_messages = sig_handler.remove_duplicate_claim_messages(messages)

    assert result_messages == [messages[0]]


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.filter_claim_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.remove_duplicate_claim_messages")
@mock.patch(
    "pubtools._quay.signature_handler.ContainerSignatureHandler.construct_item_claim_messages"
)
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_container_images(
    mock_quay_api_client,
    mock_quay_client,
    mock_construct_claim_msgs,
    mock_remove_duplicate_claim_msgs,
    mock_filter_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
    container_signing_push_item,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()
    mock_construct_claim_msgs.side_effect = [["msg1", "msg2"], ["msg3", "msg4"]]
    mock_remove_duplicate_claim_msgs.return_value = ["msg1", "msg2", "msg3", "msg4"]
    mock_filter_claim_msgs.return_value = ["msg2", "msg3"]
    mock_get_radas_signatures.return_value = ["sig2", "sig3"]

    sig_handler = signature_handler.ContainerSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    sig_handler.sign_container_images([container_signing_push_item, container_multiarch_push_item])
    assert mock_construct_claim_msgs.call_count == 2
    mock_remove_duplicate_claim_msgs.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_filter_claim_msgs.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_get_radas_signatures.assert_called_once_with(["msg2", "msg3"])
    mock_validate_radas_msgs.assert_called_once_with(["msg2", "msg3"], ["sig2", "sig3"])
    mock_upload_signatures_to_pyxis.assert_called_once_with(["msg2", "msg3"], ["sig2", "sig3"], 100)


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.filter_claim_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.remove_duplicate_claim_messages")
@mock.patch(
    "pubtools._quay.signature_handler.ContainerSignatureHandler.construct_item_claim_messages"
)
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_container_images_no_signatures(
    mock_quay_api_client,
    mock_quay_client,
    mock_construct_claim_msgs,
    mock_remove_duplicate_claim_msgs,
    mock_filter_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
    container_signing_push_item,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()
    mock_construct_claim_msgs.side_effect = [["msg1", "msg2"], ["msg3", "msg4"]]
    mock_remove_duplicate_claim_msgs.return_value = ["msg1", "msg2", "msg3", "msg4"]
    mock_filter_claim_msgs.return_value = []

    sig_handler = signature_handler.ContainerSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    sig_handler.sign_container_images([container_signing_push_item, container_multiarch_push_item])
    assert mock_construct_claim_msgs.call_count == 2
    mock_remove_duplicate_claim_msgs.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_filter_claim_msgs.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_get_radas_signatures.assert_not_called()
    mock_validate_radas_msgs.assert_not_called()
    mock_upload_signatures_to_pyxis.assert_not_called()


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.filter_claim_messages")
@mock.patch(
    "pubtools._quay.signature_handler.ContainerSignatureHandler.construct_item_claim_messages"
)
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_container_images_not_allowed(
    mock_quay_api_client,
    mock_quay_client,
    mock_construct_claim_msgs,
    mock_filter_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
    container_signing_push_item,
):
    hub = mock.MagicMock()
    target_settings["docker_settings"]["docker_container_signing_enabled"] = False
    sig_handler = signature_handler.ContainerSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    sig_handler.sign_container_images([container_signing_push_item])
    mock_construct_claim_msgs.assert_not_called()
    mock_filter_claim_msgs.assert_not_called()
    mock_get_radas_signatures.assert_not_called()
    mock_validate_radas_msgs.assert_not_called()
    mock_upload_signatures_to_pyxis.assert_not_called()


@mock.patch("pubtools._quay.signature_handler.base64.b64encode")
@mock.patch("pubtools._quay.signature_handler.datetime")
@mock.patch("pubtools._quay.signature_handler.uuid.uuid4")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_construct_operator_item_claim_messages(
    mock_quay_api_client,
    mock_quay_client,
    mock_uuid,
    mock_datetime,
    mock_encode,
    target_settings,
    operator_signing_push_item,
    signing_manifest_list_data,
):
    hub = mock.MagicMock()
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = signing_manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest
    mock_uuid.side_effect = range(100)
    mock_datetime.utcnow.return_value.isoformat.return_value = "2021-03-19T14:45:23.128632"
    mock_encode.return_value = b"some-encode"

    sig_handler = signature_handler.OperatorSignatureHandler(
        hub, "1", target_settings, "some-target"
    )

    claim_messages = sig_handler.construct_index_image_claim_messages(
        operator_signing_push_item, "v4.5", ["key1", "key2"]
    )
    print(json.dumps(claim_messages))
    with open("tests/test_data/test_expected_operator_claim_messages.json", "r") as f:
        expected_claim_messages = json.loads(f.read())

    assert claim_messages == expected_claim_messages
    mock_get_manifest.assert_called_once()
    assert mock_uuid.call_count == 8


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch(
    "pubtools._quay.signature_handler.OperatorSignatureHandler.construct_index_image_claim_messages"
)
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_operator_images(
    mock_quay_api_client,
    mock_quay_client,
    mock_construct_index_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
):
    class IIBRes:
        def __init__(self, index_image_resolved):
            self.index_image_resolved = index_image_resolved

    hub = mock.MagicMock()
    mock_construct_index_claim_msgs.side_effect = [["msg1", "msg2"], ["msg3", "msg4"]]
    mock_get_radas_signatures.return_value = ["sig1", "sig2", "sig3", "sig4"]
    iib_results = {
        "v4.5": {
            "iib_result": IIBRes("registry1/iib-namespace/image@sha256:a1a1a1"),
            "signing_keys": ["key1"],
        },
        "v4.6": {
            "iib_result": IIBRes("registry1/iib-namespace/image@sha256:b2b2b2"),
            "signing_keys": ["key2"],
        },
    }

    sig_handler = signature_handler.OperatorSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    sig_handler.sign_operator_images(iib_results)
    assert mock_construct_index_claim_msgs.call_count == 2
    mock_construct_index_claim_msgs.call_args_list[0] == mock.call(
        "quay.io/iib-namespace/iib@sha256:a1a1a1", "v4.5", ["key1"]
    )
    mock_construct_index_claim_msgs.call_args_list[0] == mock.call(
        "quay.io/iib-namespace/iib@sha256:b2b2b2", "v4.6", ["key2"]
    )
    mock_get_radas_signatures.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_validate_radas_msgs.assert_called_once_with(
        ["msg1", "msg2", "msg3", "msg4"], ["sig1", "sig2", "sig3", "sig4"]
    )
    mock_upload_signatures_to_pyxis.assert_called_once_with(
        ["msg1", "msg2", "msg3", "msg4"], ["sig1", "sig2", "sig3", "sig4"], 100
    )


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch(
    "pubtools._quay.signature_handler.OperatorSignatureHandler.construct_index_image_claim_messages"
)
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_operator_images_not_allowed(
    mock_quay_api_client,
    mock_quay_client,
    mock_construct_index_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
):

    hub = mock.MagicMock()
    target_settings["docker_settings"]["docker_container_signing_enabled"] = False

    sig_handler = signature_handler.OperatorSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    sig_handler.sign_operator_images({"nothing": "here"})
    mock_construct_index_claim_msgs.assert_not_called()
    mock_get_radas_signatures.assert_not_called()
    mock_validate_radas_msgs.assert_not_called()
    mock_upload_signatures_to_pyxis.assert_not_called()


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch(
    "pubtools._quay.signature_handler.OperatorSignatureHandler.construct_index_image_claim_messages"
)
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_task_index_image(
    mock_quay_api_client,
    mock_quay_client,
    mock_construct_index_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
):
    class IIBRes:
        def __init__(self, index_image_resolved):
            self.index_image_resolved = index_image_resolved

    hub = mock.MagicMock()
    mock_construct_index_claim_msgs.return_value = ["msg1", "msg2"]
    mock_get_radas_signatures.return_value = ["sig1", "sig2"]
    build_details = IIBRes("registry1/namespace/image:1")

    sig_handler = signature_handler.OperatorSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    sig_handler.sign_task_index_image(["some-key"], "registry1/namespace/image:1", "3")
    mock_construct_index_claim_msgs.assert_called_once_with(
        "registry1/namespace/image:1", "3", ["some-key"]
    )
    mock_get_radas_signatures.assert_called_once_with(["msg1", "msg2"])
    mock_validate_radas_msgs.assert_called_once_with(["msg1", "msg2"], ["sig1", "sig2"])
    mock_upload_signatures_to_pyxis.assert_called_once_with(["msg1", "msg2"], ["sig1", "sig2"], 100)


@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_basic_signature_handler_init(mock_quay_api_client, mock_quay_client, target_settings):
    hub = mock.MagicMock()
    sig_handler = signature_handler.BasicSignatureHandler(hub, target_settings, "some-target")

    assert sig_handler.hub == hub
    assert sig_handler.task_id == "1"
    assert sig_handler.dest_registries == ["some-registry1.com", "some-registry2.com"]
    assert sig_handler.target_settings == target_settings
    assert sig_handler.quay_host == "quay.io"
    mock_quay_client.assert_not_called()
    mock_quay_api_client.assert_not_called()

    assert sig_handler.src_quay_client == mock_quay_client.return_value
    assert sig_handler.src_quay_api_client == mock_quay_api_client.return_value
    mock_quay_client.assert_called_once_with("src-quay-user", "src-quay-pass", "quay.io")
    mock_quay_api_client.assert_called_once_with("src-quay-token", "quay.io")


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.filter_claim_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.remove_duplicate_claim_messages")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_claim_messages(
    mock_quay_api_client,
    mock_quay_client,
    mock_remove_duplicate_claim_msgs,
    mock_filter_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
    container_signing_push_item,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()
    mock_remove_duplicate_claim_msgs.return_value = ["msg1", "msg2", "msg3", "msg4"]
    mock_filter_claim_msgs.return_value = ["msg2", "msg3"]
    mock_get_radas_signatures.return_value = ["sig2", "sig3"]

    sig_handler = signature_handler.BasicSignatureHandler(hub, target_settings, "some-target")
    sig_handler.sign_claim_messages(["msg1", "msg2", "msg3", "msg4"])
    mock_remove_duplicate_claim_msgs.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_filter_claim_msgs.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_get_radas_signatures.assert_called_once_with(["msg2", "msg3"])
    mock_validate_radas_msgs.assert_called_once_with(["msg2", "msg3"], ["sig2", "sig3"])
    mock_upload_signatures_to_pyxis.assert_called_once_with(["msg2", "msg3"], ["sig2", "sig3"], 100)


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.filter_claim_messages")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_claim_messages_not_allowed(
    mock_quay_api_client,
    mock_quay_client,
    mock_filter_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
    container_signing_push_item,
):
    hub = mock.MagicMock()
    target_settings["docker_settings"]["docker_container_signing_enabled"] = False
    sig_handler = signature_handler.BasicSignatureHandler(hub, target_settings, "some-target")
    sig_handler.sign_claim_messages(["msg1", "msg2", "msg3", "msg4"])
    mock_filter_claim_msgs.assert_not_called()
    mock_get_radas_signatures.assert_not_called()
    mock_validate_radas_msgs.assert_not_called()
    mock_upload_signatures_to_pyxis.assert_not_called()


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.filter_claim_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.remove_duplicate_claim_messages")
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_claim_messages_no_signatures(
    mock_quay_api_client,
    mock_quay_client,
    mock_remove_duplicate_claim_msgs,
    mock_filter_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
    container_signing_push_item,
    container_multiarch_push_item,
):
    hub = mock.MagicMock()
    mock_remove_duplicate_claim_msgs.return_value = ["msg1", "msg2", "msg3", "msg4"]
    mock_filter_claim_msgs.return_value = []

    sig_handler = signature_handler.BasicSignatureHandler(hub, target_settings, "some-target")
    sig_handler.sign_claim_messages(["msg1", "msg2", "msg3", "msg4"])
    mock_remove_duplicate_claim_msgs.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_filter_claim_msgs.assert_called_once_with(["msg1", "msg2", "msg3", "msg4"])
    mock_get_radas_signatures.assert_not_called()
    mock_validate_radas_msgs.assert_not_called()
    mock_upload_signatures_to_pyxis.assert_not_called()


@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_construct_item_claim_messages_none_signing_key(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    container_signing_push_item,
):
    hub = mock.MagicMock()

    sig_handler = signature_handler.ContainerSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    push_item_none_key = container_signing_push_item
    push_item_none_key.claims_signing_key = None

    claim_messages = sig_handler.construct_item_claim_messages(push_item_none_key)

    assert claim_messages == []


@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_construct_operator_item_claim_messages_none_signing_key(
    mock_quay_api_client,
    mock_quay_client,
    target_settings,
    operator_signing_push_item,
    signing_manifest_list_data,
):
    hub = mock.MagicMock()
    mock_get_manifest = mock.MagicMock()
    mock_get_manifest.return_value = signing_manifest_list_data
    mock_quay_client.return_value.get_manifest = mock_get_manifest

    sig_handler = signature_handler.OperatorSignatureHandler(
        hub, "1", target_settings, "some-target"
    )

    claim_messages = sig_handler.construct_index_image_claim_messages(
        operator_signing_push_item, "v4.5", [None]
    )

    assert claim_messages == []


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch(
    "pubtools._quay.signature_handler.OperatorSignatureHandler.construct_index_image_claim_messages"
)
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_operator_images_no_signatures(
    mock_quay_api_client,
    mock_quay_client,
    mock_construct_index_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
):
    class IIBRes:
        def __init__(self, index_image_resolved):
            self.index_image_resolved = index_image_resolved

    hub = mock.MagicMock()
    mock_construct_index_claim_msgs.return_value = []
    iib_results = {
        "v4.5": {
            "iib_result": IIBRes("registry1/iib-namespace/image@sha256:a1a1a1"),
            "signing_keys": [None],
        },
    }

    sig_handler = signature_handler.OperatorSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    sig_handler.sign_operator_images(iib_results)
    mock_construct_index_claim_msgs.assert_called_once_with(
        "quay.io/iib-namespace/iib@sha256:a1a1a1", "v4.5", [None]
    )
    mock_get_radas_signatures.assert_not_called()
    mock_validate_radas_msgs.assert_not_called()
    mock_upload_signatures_to_pyxis.assert_not_called()


@mock.patch("pubtools._quay.signature_handler.SignatureHandler.upload_signatures_to_pyxis")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.validate_radas_messages")
@mock.patch("pubtools._quay.signature_handler.SignatureHandler.get_signatures_from_radas")
@mock.patch(
    "pubtools._quay.signature_handler.OperatorSignatureHandler.construct_index_image_claim_messages"
)
@mock.patch("pubtools._quay.signature_handler.QuayClient")
@mock.patch("pubtools._quay.signature_handler.QuayApiClient")
def test_sign_task_index_image_no_signatures(
    mock_quay_api_client,
    mock_quay_client,
    mock_construct_index_claim_msgs,
    mock_get_radas_signatures,
    mock_validate_radas_msgs,
    mock_upload_signatures_to_pyxis,
    target_settings,
):
    hub = mock.MagicMock()
    mock_construct_index_claim_msgs.return_value = []

    sig_handler = signature_handler.OperatorSignatureHandler(
        hub, "1", target_settings, "some-target"
    )
    sig_handler.sign_task_index_image([None], "registry1/namespace/image:1", "3")
    mock_construct_index_claim_msgs.assert_called_once_with(
        "registry1/namespace/image:1", "3", [None]
    )
    mock_get_radas_signatures.assert_not_called()
    mock_validate_radas_msgs.assert_not_called()
    mock_upload_signatures_to_pyxis.assert_not_called()
