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
    called_args, _ = mock_tag_images.call_args

    assert called_args[0].source_ref == "quay.io/repo/souce-image:1"
    assert called_args[0].dest_ref == ["quay.io/repo/target-image:1"]
    assert called_args[0].quay_user is None
    assert called_args[0].quay_password is None
    assert called_args[0].remote_exec is None
    assert called_args[0].ssh_remote_host is None
    assert called_args[0].ssh_reject_unknown_host is None
    assert called_args[0].ssh_username is None
    assert called_args[0].ssh_password is None
    assert called_args[0].ssh_key_filename is None
    assert called_args[0].send_umb_msg is None
    assert called_args[0].umb_url is None
    assert called_args[0].umb_cert is None
    assert called_args[0].umb_client_key is None
    assert called_args[0].umb_ca_cert is None
    assert called_args[0].umb_topic is None


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_full_args(mock_tag_images):
    full_args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--quay-user",
        "robot_user",
        "--quay-password",
        "robot_token",
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
    called_args, _ = mock_tag_images.call_args

    assert called_args[0].source_ref == "quay.io/repo/souce-image:1"
    assert called_args[0].dest_ref == ["quay.io/repo/target-image:1"]
    assert called_args[0].quay_user == "robot_user"
    assert called_args[0].quay_password == "robot_token"
    assert called_args[0].remote_exec is True
    assert called_args[0].ssh_remote_host == "127.0.0.1"
    assert called_args[0].ssh_reject_unknown_host is True
    assert called_args[0].ssh_username == "dummy"
    assert called_args[0].ssh_password == "123456"
    assert called_args[0].ssh_key_filename == "/path/to/file.key"
    assert called_args[0].send_umb_msg is True
    assert called_args[0].umb_url == ["amqps://url:5671"]
    assert called_args[0].umb_cert == "/path/to/file.crt"
    assert called_args[0].umb_client_key == "/path/to/umb.key"
    assert called_args[0].umb_ca_cert == "/path/to/ca_cert.crt"
    assert called_args[0].umb_topic == "VirtualTopic.eng.pub.tagimage"


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
    called_args, _ = mock_tag_images.call_args

    assert called_args[0].source_ref == "quay.io/repo/souce-image:1"
    assert called_args[0].dest_ref == [
        "quay.io/repo/target-image:1",
        "quay.io/repo/target-image:2",
    ]
    assert called_args[0].send_umb_msg is True
    assert called_args[0].umb_url == ["amqps://url1:5671", "amqps://url2:5671"]


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


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_missing_hostname(mock_tag_images):
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

    mock_tag_images.assert_not_called()


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_missing_quay_user_or_password(mock_tag_images):
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

    mock_tag_images.assert_not_called()


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_missing_umb_url(mock_tag_images):
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

    mock_tag_images.assert_not_called()


@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_missing_umb_cert(mock_tag_images):
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

    mock_tag_images.assert_not_called()


@mock.patch.dict(
    "os.environ", {"QUAY_PASSWORD": "robot_token", "SSH_PASSWORD": "123456"}
)
@mock.patch("pubtools._quay.tag_images.tag_images")
def test_arg_parser_env_variables(mock_tag_images):
    full_args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
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
        "--umb-topic",
        "VirtualTopic.eng.pub.tagimage",
    ]
    tag_images.tag_images_main(full_args)
    called_args, _ = mock_tag_images.call_args

    assert called_args[0].source_ref == "quay.io/repo/souce-image:1"
    assert called_args[0].dest_ref == ["quay.io/repo/target-image:1"]
    assert called_args[0].quay_user == "robot_user"
    assert called_args[0].quay_password == "robot_token"
    assert called_args[0].remote_exec is True
    assert called_args[0].ssh_remote_host == "127.0.0.1"
    assert called_args[0].ssh_reject_unknown_host is True
    assert called_args[0].ssh_username == "dummy"
    assert called_args[0].ssh_password == "123456"
    assert called_args[0].ssh_key_filename == "/path/to/file.key"
    assert called_args[0].send_umb_msg is True
    assert called_args[0].umb_url == ["amqps://url:5671"]
    assert called_args[0].umb_cert == "/path/to/file.crt"
    assert called_args[0].umb_client_key == "/path/to/umb.key"
    assert called_args[0].umb_ca_cert == "/path/to/ca_cert.crt"
    assert called_args[0].umb_topic == "VirtualTopic.eng.pub.tagimage"
