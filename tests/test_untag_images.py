import logging
import mock
import pytest
import requests_mock

from pubtools._quay import untag_images
from .utils.misc import compare_logs

# flake8: noqa: E501


@mock.patch("pubtools._quay.untag_images.untag_images")
def test_arg_constructor_required_args(mock_untag_images):
    required_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--quay-api-token",
        "some-token",
    ]
    untag_images.untag_images_main(required_args)
    _, called_args = mock_untag_images.call_args

    assert called_args["references"] == ["quay.io/repo/some-image:1"]
    assert called_args["quay_api_token"] == "some-token"
    assert called_args["umb_topic"] == "VirtualTopic.eng.pub.quay_untag_image"


@mock.patch.dict("os.environ", {"QUAY_PASSWORD": "robot_token", "QUAY_API_TOKEN": "api_token"})
@mock.patch("pubtools._quay.untag_images.untag_images")
def test_arg_constructor_all_args(mock_untag_images):
    all_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--remove-last",
        "--quay-user",
        "some_user",
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
        "VirtualTopic.eng.pub.untag_image_new",
    ]
    untag_images.untag_images_main(all_args)
    _, called_args = mock_untag_images.call_args

    assert called_args["references"] == ["quay.io/repo/some-image:1"]
    assert called_args["remove_last"] == True
    assert called_args["quay_user"] == "some_user"
    assert called_args["quay_password"] == "robot_token"
    assert called_args["send_umb_msg"] == True
    assert called_args["umb_urls"] == ["amqps://url:5671", "amqps://url:5672"]
    assert called_args["umb_cert"] == "/path/to/file.crt"
    assert called_args["umb_client_key"] == "/path/to/umb.key"
    assert called_args["umb_cacert"] == "/path/to/ca_cert.crt"
    assert called_args["quay_api_token"] == "api_token"
    assert called_args["umb_topic"] == "VirtualTopic.eng.pub.untag_image_new"


@mock.patch("pubtools._quay.untag_images.untag_images")
def test_args_missing_reference(mock_untag_images):
    wrong_args = [
        "dummy",
        "--quay-api-token",
        "some-token",
    ]

    with pytest.raises(SystemExit) as system_error:
        untag_images.untag_images_main(wrong_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_untag_images.assert_not_called()


@mock.patch("pubtools._quay.untag_images.untag_images")
def test_args_missing_api_token(mock_untag_images):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
    ]

    with pytest.raises(ValueError, match="--quay-api-token must be specified"):
        untag_images.untag_images_main(wrong_args)

    mock_untag_images.assert_not_called()


@mock.patch("pubtools._quay.untag_images.ImageUntagger")
def test_args_incorrect_digest_reference(mock_image_untagger):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image@sha256:s5df6sd5f",
        "--quay-api-token",
        "some-token",
    ]

    with pytest.raises(ValueError, match="All references must be specified via tag, not digest"):
        untag_images.untag_images_main(wrong_args)

    mock_image_untagger.assert_not_called()


@mock.patch("pubtools._quay.untag_images.ImageUntagger")
def test_args_missing_quay_credential(mock_image_untagger):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--quay-api-token",
        "some-token",
        "--quay-user",
        "some_user",
    ]

    with pytest.raises(ValueError, match="Both user and password must be.*"):
        untag_images.untag_images_main(wrong_args)

    mock_image_untagger.assert_not_called()


@mock.patch("pubtools._quay.untag_images.ImageUntagger")
def test_args_missing_umb_url(mock_image_untagger):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--quay-api-token",
        "some-token",
        "--send-umb-msg",
        "--umb-cert",
        "/path/to/file.crt",
    ]

    with pytest.raises(ValueError, match="UMB URL must be specified.*"):
        untag_images.untag_images_main(wrong_args)

    mock_image_untagger.assert_not_called()


@mock.patch("pubtools._quay.untag_images.ImageUntagger")
def test_args_missing_umb_url(mock_image_untagger):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--quay-api-token",
        "some-token",
        "--send-umb-msg",
        "--umb-cert",
        "/path/to/file.crt",
    ]

    with pytest.raises(ValueError, match="UMB URL must be specified.*"):
        untag_images.untag_images_main(wrong_args)

    mock_image_untagger.assert_not_called()


@mock.patch("pubtools._quay.untag_images.ImageUntagger")
def test_args_missing_umb_cert(mock_image_untagger):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--quay-api-token",
        "some-token",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
    ]

    with pytest.raises(ValueError, match="A path to a client certificate.*"):
        untag_images.untag_images_main(wrong_args)

    mock_image_untagger.assert_not_called()


@mock.patch("pubtools._quay.untag_images.ImageUntagger")
@mock.patch("pubtools._quay.untag_images.send_umb_message")
def test_send_umb_message(mock_send_umb_message, mock_image_untagger):
    args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--quay-api-token",
        "some-token",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--umb-topic",
        "VirtualTopic.eng.pub.untag_image_new",
    ]
    mock_image_untagger.return_value.untag_images.return_value = ["quay.io/repo/some-image:1"]
    untag_images.untag_images_main(args)

    mock_send_umb_message.assert_called_once_with(
        ["amqps://url:5671"],
        {
            "lost_refs": ["quay.io/repo/some-image:1"],
            "untag_refs": ["quay.io/repo/some-image:1"],
        },
        "/path/to/file.crt",
        "VirtualTopic.eng.pub.untag_image_new",
        ca_cert="/path/to/ca_cert.crt",
        client_key="/path/to/umb.key",
    )


@mock.patch("pubtools._quay.untag_images.send_umb_message")
def test_full_run_remove_last(mock_send_umb_message, repo_api_data, manifest_list_data, caplog):
    args = [
        "dummy",
        "--reference",
        "quay.io/name/repo1:1",
        "--reference",
        "quay.io/name/repo1:2",
        "--quay-api-token",
        "some-token",
        "--remove-last",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--umb-topic",
        "VirtualTopic.eng.pub.untag_image_new",
    ]
    caplog.set_level(logging.INFO)

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/api/v1/repository/name/repo1",
            json=repo_api_data,
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            json=manifest_list_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.delete("https://quay.io/api/v1/repository/name/repo1/tag/1")
        m.delete("https://quay.io/api/v1/repository/name/repo1/tag/2")
        untag_images.untag_images_main(args)

        expected_lost_images = [
            "quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            "quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
        ]

        assert m.call_count == 5

        expected_logs = [
            "Started untagging operation with the following references: .*quay.io/name/repo1:1.*quay.io/name/repo1:2.*",
            "Gathering tags and digests of repository 'name/repo1'",
            "Following images won't be referencable by tag: "
            ".*quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36.*"
            ".*quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee.*"
            ".*quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9.*"
            ".*quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c.*",
            "Removing tag '1' from repository 'name/repo1'",
            "Removing tag '2' from repository 'name/repo1'",
            "Untagging operation succeeded",
            "Sending a UMB message",
        ]
        compare_logs(caplog, expected_logs)

        mock_send_umb_message.assert_called_once_with(
            ["amqps://url:5671"],
            {
                "lost_refs": expected_lost_images,
                "untag_refs": ["quay.io/name/repo1:1", "quay.io/name/repo1:2"],
            },
            "/path/to/file.crt",
            "VirtualTopic.eng.pub.untag_image_new",
            ca_cert="/path/to/ca_cert.crt",
            client_key="/path/to/umb.key",
        )


@mock.patch("pubtools._quay.untag_images.send_umb_message")
def test_full_run_no_lost_digests(mock_send_umb_message, repo_api_data, manifest_list_data, caplog):
    args = [
        "dummy",
        "--reference",
        "quay.io/name/repo1:1",
        "--quay-api-token",
        "some-token",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--umb-topic",
        "VirtualTopic.eng.pub.untag_image_new",
    ]
    caplog.set_level(logging.INFO)

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/api/v1/repository/name/repo1",
            json=repo_api_data,
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            json=manifest_list_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.delete("https://quay.io/api/v1/repository/name/repo1/tag/1")
        untag_images.untag_images_main(args)

        assert m.call_count == 4

        expected_logs = [
            "Started untagging operation with the following references: .*quay.io/name/repo1:1.*",
            "Gathering tags and digests of repository 'name/repo1'",
            "No images will be lost by this untagging operation",
            "Removing tag '1' from repository 'name/repo1'",
            "Untagging operation succeeded",
            "Sending a UMB message",
        ]
        compare_logs(caplog, expected_logs)

        mock_send_umb_message.assert_called_once_with(
            ["amqps://url:5671"],
            {
                "lost_refs": [],
                "untag_refs": ["quay.io/name/repo1:1"],
            },
            "/path/to/file.crt",
            "VirtualTopic.eng.pub.untag_image_new",
            ca_cert="/path/to/ca_cert.crt",
            client_key="/path/to/umb.key",
        )


@mock.patch("pubtools._quay.untag_images.send_umb_message")
def test_full_run_last_error(mock_send_umb_message, repo_api_data, manifest_list_data, caplog):
    args = [
        "dummy",
        "--reference",
        "quay.io/name/repo1:1",
        "--reference",
        "quay.io/name/repo1:2",
        "--quay-api-token",
        "some-token",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--umb-topic",
        "VirtualTopic.eng.pub.untag_image_new",
    ]
    caplog.set_level(logging.INFO)

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/api/v1/repository/name/repo1",
            json=repo_api_data,
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            json=manifest_list_data,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        expected_err_msg = (
            "Following images .*"
            ".*quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36.*"
            ".*quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee.*"
            ".*quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9.*"
            ".*quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c.*"
        )

        with pytest.raises(ValueError, match=expected_err_msg):
            untag_images.untag_images_main(args)

        assert m.call_count == 3

        expected_logs = [
            "Started untagging operation with the following references: .*quay.io/name/repo1:1.*quay.io/name/repo1:2.*",
            "Gathering tags and digests of repository 'name/repo1'",
        ]
        compare_logs(caplog, expected_logs)

        mock_send_umb_message.assert_not_called()
