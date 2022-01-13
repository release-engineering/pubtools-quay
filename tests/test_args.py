import mock
import pytest

from pubtools._quay import tag_images
from pubtools._quay.utils import misc


def test_argument_groups(capsys):
    args = {
        ("--arg1",): {
            "group": "Group 1",
            "help": "Argument 1",
            "required": True,
            "type": str,
        },
        ("--arg2",): {
            "group": "Group 1",
            "help": "Argument 2",
            "required": True,
            "type": str,
        },
        ("--arg3",): {
            "group": "Group 2",
            "help": "Argument 3",
            "required": True,
            "type": str,
        },
        ("--arg4",): {
            "group": "Group 2",
            "help": "Argument 4",
            "required": True,
            "type": str,
        },
    }

    parser = misc.setup_arg_parser(args)
    parser.print_help()
    out, _ = capsys.readouterr()

    assert "Group 1:" in out
    assert "Group 2:" in out


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_required_args(mock_tag_images):
    required_args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
    ]
    tag_images.tag_images_main(required_args)

    assert mock_tag_images.call_args == mock.call(
        source_ref="quay.io/repo/souce-image:1",
        all_arch=False,
        quay_user=None,
        quay_password=None,
        source_quay_user=None,
        source_quay_password=None,
        remote_exec=False,
        ssh_remote_host=None,
        ssh_remote_host_port=None,
        ssh_reject_unknown_host=False,
        ssh_username=None,
        ssh_password=None,
        ssh_key_filename=None,
        container_exec=False,
        container_image=None,
        docker_url="unix://var/run/docker.sock",
        docker_timeout=None,
        docker_verify_tls=False,
        docker_cert_path=None,
        send_umb_msg=False,
        umb_cert=None,
        umb_client_key=None,
        umb_ca_cert=None,
        registry_username=None,
        registry_password=None,
        umb_topic="VirtualTopic.eng.pub.quay_tag_image",
        dest_refs=["quay.io/repo/target-image:1"],
        umb_urls=None,
    )


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_full_args(mock_tag_images):
    full_args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--source-quay-user",
        "robot_user_for_source",
        "--source-quay-password",
        "robot_token_for_source",
        "--quay-user",
        "robot_user",
        "--quay-password",
        "robot_token",
        "--remote-exec",
        "--ssh-remote-host",
        "127.0.0.1",
        "--ssh-remote-host-port",
        "5000",
        "--ssh-reject-unknown-host",
        "--ssh-username",
        "dummy",
        "--ssh-password",
        "123456",
        "--ssh-key-filename",
        "/path/to/file.key",
        "--container-exec",
        "--container-image",
        "quay.io/namespace/image:1",
        "--docker-url",
        "https://some-url.com",
        "--docker-timeout",
        "120",
        "--docker-verify-tls",
        "--docker-cert-path",
        "/some/path",
        "--registry-username",
        "registry_user",
        "--registry-password",
        "registry_passwd",
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
    tag_images.tag_images_main(full_args)

    assert mock_tag_images.call_args == mock.call(
        source_ref="quay.io/repo/souce-image:1",
        all_arch=False,
        quay_user="robot_user",
        quay_password="robot_token",
        source_quay_user="robot_user_for_source",
        source_quay_password="robot_token_for_source",
        remote_exec=True,
        ssh_remote_host="127.0.0.1",
        ssh_remote_host_port=5000,
        ssh_reject_unknown_host=True,
        ssh_username="dummy",
        ssh_password="123456",
        ssh_key_filename="/path/to/file.key",
        container_exec=True,
        container_image="quay.io/namespace/image:1",
        docker_url="https://some-url.com",
        docker_timeout="120",
        docker_verify_tls=True,
        docker_cert_path="/some/path",
        registry_username="registry_user",
        registry_password="registry_passwd",
        send_umb_msg=True,
        umb_cert="/path/to/file.crt",
        umb_client_key="/path/to/umb.key",
        umb_ca_cert="/path/to/ca_cert.crt",
        umb_topic="VirtualTopic.eng.pub.tagimage",
        dest_refs=["quay.io/repo/target-image:1"],
        umb_urls=["amqps://url:5671"],
    )


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_multiple_args(mock_tag_images):
    multi_args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:2",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url1:5671",
        "--umb-url",
        "amqps://url2:5671",
        "--umb-cert",
        "/path/to/file.crt",
    ]
    tag_images.tag_images_main(multi_args)

    assert mock_tag_images.call_args == mock.call(
        source_ref="quay.io/repo/souce-image:1",
        all_arch=False,
        quay_user=None,
        quay_password=None,
        source_quay_user=None,
        source_quay_password=None,
        remote_exec=False,
        ssh_remote_host=None,
        ssh_remote_host_port=None,
        ssh_reject_unknown_host=False,
        ssh_username=None,
        ssh_password=None,
        ssh_key_filename=None,
        container_exec=False,
        container_image=None,
        docker_url="unix://var/run/docker.sock",
        docker_timeout=None,
        docker_verify_tls=False,
        docker_cert_path=None,
        send_umb_msg=True,
        umb_cert="/path/to/file.crt",
        umb_client_key=None,
        umb_ca_cert=None,
        registry_username=None,
        registry_password=None,
        umb_topic="VirtualTopic.eng.pub.quay_tag_image",
        dest_refs=["quay.io/repo/target-image:1", "quay.io/repo/target-image:2"],
        umb_urls=["amqps://url1:5671", "amqps://url2:5671"],
    )


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_required_missing_source(mock_tag_images):
    missing_source = ["dummy", "--dest-ref", "quay.io/repo/target-image:1"]

    with pytest.raises(SystemExit) as system_error:
        tag_images.tag_images_main(missing_source)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_tag_images.assert_not_called()


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_required_missing_dest(mock_tag_images):
    missing_dest = ["dummy", "--source-ref", "quay.io/repo/souce-image:1"]

    with pytest.raises(SystemExit) as system_error:
        tag_images.tag_images_main(missing_dest)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_tag_images.assert_not_called()


def test_arg_parser_missing_hostname():
    missing_hostname = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--remote-exec",
    ]

    with pytest.raises(ValueError, match="Remote host is missing.*"):
        tag_images.tag_images_main(missing_hostname)


def test_arg_parser_missing_quay_user_or_password():
    missing_password = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--quay-user",
        "robot_user",
    ]

    with pytest.raises(ValueError, match="Both user and password must be present.*"):
        tag_images.tag_images_main(missing_password)

    missing_user = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--quay-password",
        "robot_token",
    ]

    with pytest.raises(ValueError, match="Both user and password must be present.*"):
        tag_images.tag_images_main(missing_user)

    missing_source_password = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--quay-user",
        "robot_user",
        "--quay-password",
        "robot_token",
        "--source-quay-user",
        "robot_user_for_source",
    ]

    with pytest.raises(ValueError, match="Both source quay user and password must be present.*"):
        tag_images.tag_images_main(missing_source_password)

    missing_source_user = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--quay-user",
        "robot_user",
        "--quay-password",
        "robot_token",
        "--source-quay-password",
        "robot_token_for_source",
    ]

    with pytest.raises(ValueError, match="Both source quay user and password must be present.*"):
        tag_images.tag_images_main(missing_source_user)


def test_arg_parser_missing_umb_url():
    missing_umb_url = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--send-umb-msg",
        "--umb-cert",
        "/path/to/file.crt",
    ]

    with pytest.raises(ValueError, match="UMB URL must be specified.*"):
        tag_images.tag_images_main(missing_umb_url)


def test_arg_parser_missing_umb_cert():
    missing_umb_url = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url1:5671",
    ]

    with pytest.raises(ValueError, match="A path to a client certificate.*"):
        tag_images.tag_images_main(missing_umb_url)


def test_arg_parser_missing_container_image():
    missing_umb_url = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--container-exec",
    ]

    with pytest.raises(ValueError, match="Container image is missing when.*"):
        tag_images.tag_images_main(missing_umb_url)


@mock.patch.dict(
    "os.environ",
    {
        "SOURCE_QUAY_PASSWORD": "robot_token_for_source",
        "QUAY_PASSWORD": "robot_token",
        "SSH_PASSWORD": "123456",
        "REGISTRY_PASSWORD": "registry_passwd",
    },
)
@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_env_variables(mock_tag_images):
    full_args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--source-quay-user",
        "robot_user_for_source",
        "--quay-user",
        "robot_user",
        "--remote-exec",
        "--ssh-remote-host",
        "127.0.0.1",
        "--ssh-reject-unknown-host",
        "--ssh-username",
        "dummy",
        "--ssh-key-filename",
        "/path/to/file.key",
        "--send-umb-msg",
        "--umb-url",
        "amqps://url:5671",
        "--umb-cert",
        "/path/to/file.crt",
        "--umb-client-key",
        "/path/to/umb.key",
        "--umb-ca-cert",
        "/path/to/ca_cert.crt",
        "--registry-username",
        "registry_user",
        "--umb-topic",
        "VirtualTopic.eng.pub.tagimage",
    ]
    tag_images.tag_images_main(full_args)

    assert mock_tag_images.call_args == mock.call(
        source_ref="quay.io/repo/souce-image:1",
        all_arch=False,
        quay_user="robot_user",
        quay_password="robot_token",
        source_quay_user="robot_user_for_source",
        source_quay_password="robot_token_for_source",
        remote_exec=True,
        ssh_remote_host="127.0.0.1",
        ssh_remote_host_port=None,
        ssh_reject_unknown_host=True,
        ssh_username="dummy",
        ssh_password="123456",
        ssh_key_filename="/path/to/file.key",
        container_exec=False,
        container_image=None,
        docker_url="unix://var/run/docker.sock",
        docker_timeout=None,
        docker_verify_tls=False,
        docker_cert_path=None,
        send_umb_msg=True,
        umb_cert="/path/to/file.crt",
        umb_client_key="/path/to/umb.key",
        umb_ca_cert="/path/to/ca_cert.crt",
        registry_username="registry_user",
        registry_password="registry_passwd",
        umb_topic="VirtualTopic.eng.pub.tagimage",
        dest_refs=["quay.io/repo/target-image:1"],
        umb_urls=["amqps://url:5671"],
    )
