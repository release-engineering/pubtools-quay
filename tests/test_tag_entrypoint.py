import json
import sys

import mock

from pubtools._quay import tag_images

sys.modules["rhmsg"] = mock.MagicMock()
sys.modules["rhmsg.activemq"] = mock.MagicMock()
module_mock = mock.MagicMock()
sys.modules["rhmsg.activemq.producer"] = module_mock


@mock.patch("pubtools._quay.tag_images.LocalExecutor")
def test_run_tag_entrypoint_local_success(mock_local_executor):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
    ]
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    mock_tag_images = mock.MagicMock()
    mock_local_executor.return_value.tag_images = mock_tag_images

    tag_images.tag_images_main(args)

    mock_local_executor.assert_called_once_with()
    mock_skopeo_login.assert_called_once_with(None, None)
    mock_tag_images.assert_called_once_with(
        "quay.io/repo/souce-image:1", ["quay.io/repo/target-image:1"], False
    )


@mock.patch("pubtools._quay.tag_images.LocalExecutor")
def test_run_tag_entrypoint_local_success_all_arch(mock_local_executor):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--all-arch",
    ]
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    mock_tag_images = mock.MagicMock()
    mock_local_executor.return_value.tag_images = mock_tag_images

    tag_images.tag_images_main(args)

    mock_local_executor.assert_called_once_with()
    mock_skopeo_login.assert_called_once_with(None, None)
    mock_tag_images.assert_called_once_with(
        "quay.io/repo/souce-image:1", ["quay.io/repo/target-image:1"], True
    )


@mock.patch("pubtools._quay.tag_images.RemoteExecutor")
def test_run_tag_entrypoint_remote_success(mock_remote_executor):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--remote-exec",
        "--ssh-remote-host",
        "127.0.0.1",
        "--ssh-reject-unknown-host",
        "--ssh-username",
        "dummy",
        "--ssh-password",
        "123456",
        "--ssh-key-filename",
        "/path/to/file.key",
    ]
    mock_skopeo_login = mock.MagicMock()
    mock_remote_executor.return_value.skopeo_login = mock_skopeo_login
    mock_tag_images = mock.MagicMock()
    mock_remote_executor.return_value.tag_images = mock_tag_images

    tag_images.tag_images_main(args)

    mock_remote_executor.assert_called_once_with(
        "127.0.0.1", "dummy", "/path/to/file.key", "123456", None, False
    )
    mock_skopeo_login.assert_called_once_with(None, None)
    mock_tag_images.assert_called_once_with(
        "quay.io/repo/souce-image:1", ["quay.io/repo/target-image:1"], False
    )


@mock.patch("pubtools._quay.tag_images.LocalExecutor")
@mock.patch("rhmsg.activemq.producer.AMQProducer")
def test_run_tag_entrypoint_send_umb(mock_amq_producer, mock_local_executor):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
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
        "VirtualTopic.eng.pub.tagimage",
    ]
    module_mock.AMQProducer = mock_amq_producer
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    mock_tag_images = mock.MagicMock()
    mock_local_executor.return_value.tag_images = mock_tag_images

    mock_send_msg = mock.MagicMock()
    mock_amq_producer.return_value.send_msg = mock_send_msg

    tag_images.tag_images_main(args)

    mock_local_executor.assert_called_once_with()
    mock_skopeo_login.assert_called_once_with(None, None)
    mock_tag_images.assert_called_once_with(
        "quay.io/repo/souce-image:1", ["quay.io/repo/target-image:1"], False
    )

    mock_amq_producer.assert_called_once_with(
        urls=["amqps://url:5671"],
        certificate="/path/to/file.crt",
        private_key="/path/to/umb.key",
        topic="VirtualTopic.eng.pub.tagimage",
        trusted_certificates="/path/to/ca_cert.crt",
    )
    expected = {
        "source_ref": "quay.io/repo/souce-image:1",
        "dest_refs": ["quay.io/repo/target-image:1"],
    }
    mock_send_msg.assert_called_once_with(
        expected, json.dumps(expected).encode("utf-8")
    )
