import json
import logging
import mock
import pytest
import requests_mock

from pubtools._quay import remove_image
from .utils.misc import compare_logs

# flake8: noqa: E501


@mock.patch("pubtools._quay.remove_image.remove_images")
def test_arg_constructor_required_args(mock_remove_images):
    required_args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
    ]
    remove_image.remove_image_main(required_args)
    _, called_args = mock_remove_images.call_args

    assert called_args["reference"] == ["quay.io/some-namespace/some-image:1"]
    assert called_args["quay_user"] == "some-user"
    assert called_args["quay_password"] == "some-password"
    assert called_args["quay_api_token"] == "some-token"
    assert called_args["pyxis_server"] == "pyxis-url.com"
    assert called_args["pyxis_krb_principal"] == "some-principal"
    assert called_args["umb_topic"] == "VirtualTopic.eng.pub.quay_remove_images"


@mock.patch.dict("os.environ", {"QUAY_API_TOKEN": "api_token", "QUAY_PASSWORD": "some-password"})
@mock.patch("pubtools._quay.remove_image.remove_images")
def test_arg_constructor_all_args(mock_remove_images):
    all_args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--reference",
        "quay.io/some-namespace/some-image:2",
        "--quay-user",
        "some-user",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-url",
        "amqps://url:5672",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--umb-topic",
        "VirtualTopic.eng.pub.remove_images_new",
    ]
    remove_image.remove_image_main(all_args)
    _, called_args = mock_remove_images.call_args

    assert called_args["reference"] == [
        "quay.io/some-namespace/some-image:1",
        "quay.io/some-namespace/some-image:2",
    ]
    assert called_args["quay_user"] == "some-user"
    assert called_args["quay_password"] == "some-password"
    assert called_args["pyxis_server"] == "pyxis-url.com"
    assert called_args["pyxis_krb_principal"] == "some-principal"
    assert called_args["send_umb_msg"] is True
    assert called_args["umb_urls"] == ["amqps://url:5671", "amqps://url:5672"]
    assert called_args["umb_cert"] == "/path/to/file.crt"
    assert called_args["umb_client_key"] == "/path/to/umb.key"
    assert called_args["umb_ca_cert"] == "/path/to/ca_cert.crt"
    assert called_args["quay_api_token"] == "api_token"
    assert called_args["umb_topic"] == "VirtualTopic.eng.pub.remove_images_new"


@mock.patch("pubtools._quay.remove_image.remove_images")
def test_args_missing_reference(mock_remove_images):
    wrong_args = [
        "dummy",
        "--quay-org",
        "quay-organization",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
    ]

    with pytest.raises(SystemExit) as system_error:
        remove_image.remove_image_main(wrong_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_remove_images.assert_not_called()


@mock.patch("pubtools._quay.remove_image.remove_images")
def test_args_missing_api_token(mock_remove_images):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
    ]

    with pytest.raises(ValueError, match="--quay-api-token must be specified"):
        remove_image.remove_image_main(wrong_args)

    mock_remove_images.assert_not_called()


@mock.patch("pubtools._quay.remove_image.remove_images")
def test_args_missing_quay_password(mock_remove_images):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--quay-user",
        "some-user",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
    ]

    with pytest.raises(ValueError, match="--quay-password must be specified"):
        remove_image.remove_image_main(wrong_args)

    mock_remove_images.assert_not_called()


@mock.patch("pubtools._quay.remove_image.send_umb_message")
@mock.patch("pubtools._quay.remove_image.QuayClient")
def test_args_missing_umb_url(mock_quay_client, mock_send_umb_message):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-cert",
        "/path/to/file.crt",
    ]

    with pytest.raises(ValueError, match="UMB URL must be specified.*"):
        remove_image.remove_image_main(wrong_args)

    mock_quay_client.assert_not_called()
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.remove_image.send_umb_message")
@mock.patch("pubtools._quay.remove_image.QuayClient")
def test_args_missing_umb_cert(mock_quay_client, mock_send_umb_message):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
    ]

    with pytest.raises(ValueError, match="A path to a client certificate.*"):
        remove_image.remove_image_main(wrong_args)

    mock_quay_client.assert_not_called()
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.remove_image.send_umb_message")
@mock.patch("pubtools._quay.remove_image.QuayClient")
def test_args_image_by_digest(mock_quay_client, mock_send_umb_message):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image@sha256:a1a1a1",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
    ]

    with pytest.raises(ValueError, match=".*Please specify all images via tag.*"):
        remove_image.remove_image_main(wrong_args)

    mock_quay_client.assert_not_called()
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.remove_image.send_umb_message")
@mock.patch("pubtools._quay.remove_image.QuayClient")
def test_args_namespace_mismatch(mock_quay_client, mock_send_umb_message):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--reference",
        "quay.io/other-namespace/some-image:1",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
    ]

    with pytest.raises(ValueError, match="All images must belong to the same organization.*"):
        remove_image.remove_image_main(wrong_args)

    mock_quay_client.assert_not_called()
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.remove_image.SignatureRemover")
@mock.patch("pubtools._quay.remove_image.send_umb_message")
@mock.patch("pubtools._quay.remove_image.QuayClient")
@mock.patch("pubtools._quay.remove_image.group_images_by_repo")
@mock.patch("pubtools._quay.remove_image.get_repo_images_to_remove")
@mock.patch("pubtools._quay.remove_image.untag_images")
def test_run(
    mock_untag_images,
    mock_get_repo_images_to_remove,
    mock_group_images_by_repo,
    mock_quay_client,
    mock_send_umb_message,
    mock_signature_remover,
):
    args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
    ]

    mock_group_images_by_repo.return_value = {
        "repo1": ["image1", "image2"],
        "repo2": ["image3", "image4"],
    }
    mock_get_repo_images_to_remove.side_effect = [["ref1"], ["ref2", "ref3"]]
    mock_remove_tag_images = mock.MagicMock()
    mock_signature_remover.return_value.remove_tag_signatures = mock_remove_tag_images

    remove_image.remove_image_main(args)

    mock_quay_client.assert_called_once_with("some-user", "some-password")
    mock_group_images_by_repo.assert_called_once_with(["quay.io/some-namespace/some-image:1"])
    assert mock_get_repo_images_to_remove.call_count == 2
    assert mock_get_repo_images_to_remove.call_args_list[0] == mock.call(
        ["image1", "image2"], mock_quay_client.return_value
    )
    assert mock_get_repo_images_to_remove.call_args_list[1] == mock.call(
        ["image3", "image4"], mock_quay_client.return_value
    )
    mock_untag_images.assert_called_once_with(
        ["ref1", "ref2", "ref3"],
        quay_api_token="some-token",
        remove_last=True,
        quay_user="some-user",
        quay_password="some-password",
        send_umb_msg=True,
        umb_urls=None,
        umb_cert=None,
        umb_client_key=None,
        umb_ca_cert=None,
    )
    mock_signature_remover.assert_called_once_with()
    assert mock_remove_tag_images.call_count == 3
    assert mock_remove_tag_images.call_args_list[0] == mock.call(
        "ref1", "pyxis-url.com", "some-principal", None
    )
    assert mock_remove_tag_images.call_args_list[1] == mock.call(
        "ref2", "pyxis-url.com", "some-principal", None
    )
    assert mock_remove_tag_images.call_args_list[2] == mock.call(
        "ref3", "pyxis-url.com", "some-principal", None
    )
    mock_send_umb_message.assert_not_called()


@mock.patch("pubtools._quay.remove_image.SignatureRemover")
@mock.patch("pubtools._quay.remove_image.send_umb_message")
@mock.patch("pubtools._quay.remove_image.QuayClient")
@mock.patch("pubtools._quay.remove_image.group_images_by_repo")
@mock.patch("pubtools._quay.remove_image.get_repo_images_to_remove")
@mock.patch("pubtools._quay.remove_image.untag_images")
def test_run(
    mock_untag_images,
    mock_get_repo_images_to_remove,
    mock_group_images_by_repo,
    mock_quay_client,
    mock_send_umb_message,
    mock_signature_remover,
):
    args = [
        "dummy",
        "--reference",
        "quay.io/some-namespace/some-image:1",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--quay-api-token",
        "some-token",
        "--pyxis-server",
        "pyxis-url.com",
        "--pyxis-krb-principal",
        "some-principal",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-url",
        "amqps://url:5672",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--umb-topic",
        "VirtualTopic.eng.pub.remove_images_new",
    ]

    mock_group_images_by_repo.return_value = {
        "repo1": ["image1", "image2"],
        "repo2": ["image3", "image4"],
    }
    mock_get_repo_images_to_remove.side_effect = [["ref1"], ["ref2", "ref3"]]
    mock_remove_tag_images = mock.MagicMock()
    mock_signature_remover.return_value.remove_tag_signatures = mock_remove_tag_images

    remove_image.remove_image_main(args)

    mock_quay_client.assert_called_once_with("some-user", "some-password")
    mock_group_images_by_repo.assert_called_once_with(["quay.io/some-namespace/some-image:1"])
    assert mock_get_repo_images_to_remove.call_count == 2
    assert mock_get_repo_images_to_remove.call_args_list[0] == mock.call(
        ["image1", "image2"], mock_quay_client.return_value
    )
    assert mock_get_repo_images_to_remove.call_args_list[1] == mock.call(
        ["image3", "image4"], mock_quay_client.return_value
    )
    mock_untag_images.assert_called_once_with(
        ["ref1", "ref2", "ref3"],
        quay_api_token="some-token",
        remove_last=True,
        quay_user="some-user",
        quay_password="some-password",
        send_umb_msg=True,
        umb_urls=["amqps://url:5671", "amqps://url:5672"],
        umb_cert="/path/to/file.crt",
        umb_client_key="/path/to/umb.key",
        umb_ca_cert="/path/to/ca_cert.crt",
    )
    mock_signature_remover.assert_called_once_with()
    assert mock_remove_tag_images.call_count == 3
    assert mock_remove_tag_images.call_args_list[0] == mock.call(
        "ref1", "pyxis-url.com", "some-principal", None
    )
    assert mock_remove_tag_images.call_args_list[1] == mock.call(
        "ref2", "pyxis-url.com", "some-principal", None
    )
    assert mock_remove_tag_images.call_args_list[2] == mock.call(
        "ref3", "pyxis-url.com", "some-principal", None
    )
    mock_send_umb_message.assert_called_once_with(
        ["amqps://url:5671", "amqps://url:5672"],
        {"removed_images": ["ref1", "ref2", "ref3"]},
        "/path/to/file.crt",
        "VirtualTopic.eng.pub.remove_images_new",
        client_key="/path/to/umb.key",
        ca_cert="/path/to/ca_cert.crt",
    )


def test_group_images_by_repo():
    references = [
        "quay.io/namespace/repo1:1",
        "quay.io/namespace/repo1:2",
        "quay.io/namespace/repo2:1",
        "quay.io/namespace/repo3:3",
    ]
    mapping = remove_image.group_images_by_repo(references)
    assert mapping == {
        "repo1": ["quay.io/namespace/repo1:1", "quay.io/namespace/repo1:2"],
        "repo2": ["quay.io/namespace/repo2:1"],
        "repo3": ["quay.io/namespace/repo3:3"],
    }


def test_get_repo_images_to_remove():
    quay_client = mock.MagicMock()
    mock_get_repo_tags = mock.MagicMock()
    quay_client.get_repository_tags = mock_get_repo_tags
    mock_get_manifest_digest = mock.MagicMock()
    quay_client.get_manifest_digest = mock_get_manifest_digest

    references = ["quay.io/namespace/repo1:1", "quay.io/namespace/repo1:2"]
    mock_get_repo_tags.return_value = {"name": "namespace/repo", "tags": ["1", "2", "3", "4", "5"]}
    mock_get_manifest_digest.side_effect = [
        "sha256:a1a1a1",
        "sha256:b2b2b2",
        "sha256:a1a1a1",
        "sha256:c3c3c3",
        "sha256:d4d4d4",
    ]

    refs_to_remove = remove_image.get_repo_images_to_remove(references, quay_client)
    assert refs_to_remove == [
        "quay.io/namespace/repo1:1",
        "quay.io/namespace/repo1:2",
        "quay.io/namespace/repo1:3",
    ]
    mock_get_repo_tags.assert_called_once_with("namespace/repo1")
    assert mock_get_manifest_digest.call_count == 5
    assert mock_get_manifest_digest.call_args_list[0] == mock.call("quay.io/namespace/repo1:1")
    assert mock_get_manifest_digest.call_args_list[1] == mock.call("quay.io/namespace/repo1:2")
    assert mock_get_manifest_digest.call_args_list[2] == mock.call("quay.io/namespace/repo1:3")
    assert mock_get_manifest_digest.call_args_list[3] == mock.call("quay.io/namespace/repo1:4")
    assert mock_get_manifest_digest.call_args_list[4] == mock.call("quay.io/namespace/repo1:5")


def test_get_repo_images_to_remove_missing_image():
    quay_client = mock.MagicMock()
    mock_get_repo_tags = mock.MagicMock()
    quay_client.get_repository_tags = mock_get_repo_tags
    mock_get_manifest_digest = mock.MagicMock()
    quay_client.get_manifest_digest = mock_get_manifest_digest

    references = ["quay.io/namespace/repo1:1", "quay.io/namespace/repo1:2"]
    mock_get_repo_tags.return_value = {"name": "namespace/repo", "tags": ["1", "3", "4", "5"]}
    mock_get_manifest_digest.side_effect = [
        "sha256:a1a1a1",
        "sha256:a1a1a1",
        "sha256:c3c3c3",
        "sha256:d4d4d4",
    ]

    with pytest.raises(ValueError, match=".*doesn't exist"):
        remove_image.get_repo_images_to_remove(references, quay_client)

    mock_get_repo_tags.assert_called_once_with("namespace/repo1")
    assert mock_get_manifest_digest.call_count == 4
    assert mock_get_manifest_digest.call_args_list[0] == mock.call("quay.io/namespace/repo1:1")
    assert mock_get_manifest_digest.call_args_list[1] == mock.call("quay.io/namespace/repo1:3")
    assert mock_get_manifest_digest.call_args_list[2] == mock.call("quay.io/namespace/repo1:4")
    assert mock_get_manifest_digest.call_args_list[3] == mock.call("quay.io/namespace/repo1:5")
