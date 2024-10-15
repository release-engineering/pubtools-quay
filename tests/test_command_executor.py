import mock
import paramiko
import pytest
import logging

from pubtools._quay import command_executor
from .utils.misc import compare_logs


def test_local_executor_init():
    executor = command_executor.LocalExecutor({"some_param": "value"})

    assert executor.params["some_param"] == "value"
    assert executor.params["universal_newlines"] is True
    assert executor.params["stderr"] == -1
    assert executor.params["stdout"] == -1
    assert executor.params["stdin"] == -1


@mock.patch("pubtools._quay.command_executor.subprocess.Popen")
def test_local_executor_run(mock_popen):
    executor = command_executor.LocalExecutor({"some_param": "value"})

    mock_communicate = mock.MagicMock()
    mock_communicate.return_value = ("outlog", "errlog")
    mock_popen.return_value.communicate = mock_communicate
    mock_popen.return_value.returncode = 0

    out, err = executor._run_cmd("pwd", stdin="input")
    assert out == "outlog"
    assert err == "errlog"
    mock_popen.assert_called_once_with(
        ["pwd"],
        some_param="value",
        universal_newlines=True,
        stderr=-1,
        stdout=-1,
        stdin=-1,
    )
    mock_communicate.assert_called_once_with(input="input")


@mock.patch("pubtools._quay.command_executor.subprocess.Popen")
def test_local_executor_context_manager(mock_popen):
    mock_communicate = mock.MagicMock()
    mock_communicate.return_value = ("outlog", "errlog")
    mock_popen.return_value.communicate = mock_communicate
    mock_popen.return_value.returncode = 0

    with command_executor.LocalExecutor({"some_param": "value"}) as executor:
        out, err = executor._run_cmd("pwd", stdin="input")
    assert out == "outlog"
    assert err == "errlog"
    mock_popen.assert_called_once_with(
        ["pwd"],
        some_param="value",
        universal_newlines=True,
        stderr=-1,
        stdout=-1,
        stdin=-1,
    )
    mock_communicate.assert_called_once_with(input="input")


@mock.patch("pubtools._quay.command_executor.subprocess.Popen")
def test_local_executor_run_error(mock_popen):
    executor = command_executor.LocalExecutor({"some_param": "value"})

    mock_communicate = mock.MagicMock()
    mock_communicate.return_value = ("outlog", "errlog")
    mock_popen.return_value.communicate = mock_communicate
    mock_popen.return_value.returncode = -1

    with pytest.raises(RuntimeError, match="An error has occured when executing.*"):
        executor._run_cmd("pwd", stdin="input")


@mock.patch("pubtools._quay.command_executor.subprocess.Popen")
def test_local_executor_run_long_error(mock_popen, caplog):
    caplog.set_level(logging.ERROR)
    executor = command_executor.LocalExecutor({"some_param": "value"})

    err_msg = " ".join(["Very long error message."] * 40)

    mock_communicate = mock.MagicMock()
    mock_communicate.return_value = ("outlog", err_msg)
    mock_popen.return_value.communicate = mock_communicate
    mock_popen.return_value.returncode = -1

    expected_logs = [
        ".*failed with the following error:",
        "    Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message.",
        "    Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message.",
        "    Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message.",
        "    Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message.",
        "    Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message. Very long error message. "
        "Very long error message. Very long error message.",
    ]

    with pytest.raises(RuntimeError, match="An error has occured when executing.*"):
        executor._run_cmd("pwd", stdin="input")

    compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.command_executor.subprocess.Popen")
def test_local_executor_run_error_custom_message(mock_popen):
    executor = command_executor.LocalExecutor({"some_param": "value"})

    mock_communicate = mock.MagicMock()
    mock_communicate.return_value = ("outlog", "errlog")
    mock_popen.return_value.communicate = mock_communicate
    mock_popen.return_value.returncode = -1

    with pytest.raises(RuntimeError, match="Custom error"):
        executor._run_cmd("pwd", stdin="input", err_msg="Custom error")


@mock.patch("pubtools._quay.command_executor.subprocess.Popen")
def test_local_executor_run_tolerate_err(mock_popen):
    executor = command_executor.LocalExecutor({"some_param": "value"})

    mock_communicate = mock.MagicMock()
    mock_communicate.return_value = ("outlog", "errlog")
    mock_popen.return_value.communicate = mock_communicate
    mock_popen.return_value.returncode = -1

    out, err = executor._run_cmd("pwd", stdin="input", tolerate_err=True)
    assert out == "outlog"
    assert err == "errlog"
    mock_popen.assert_called_once_with(
        ["pwd"],
        some_param="value",
        universal_newlines=True,
        stderr=-1,
        stdout=-1,
        stdin=-1,
    )
    mock_communicate.assert_called_once_with(input="input")


def test_remote_executor_init():
    executor = command_executor.RemoteExecutor(
        "127.0.0.1",
        username="dummy",
        key_filename="path/to/file.key",
        password="123456",
        accept_unknown_host=False,
    )

    assert executor.hostname == "127.0.0.1"
    assert executor.username == "dummy"
    assert executor.key_filename == "path/to/file.key"
    assert executor.password == "123456"
    assert isinstance(executor.missing_host_policy, paramiko.client.RejectPolicy)

    executor2 = command_executor.RemoteExecutor("127.0.0.1")

    assert isinstance(executor2.missing_host_policy, paramiko.client.WarningPolicy)


@mock.patch("pubtools._quay.command_executor.paramiko.client.SSHClient")
def test_remote_executor_run(mock_sshclient):
    executor = command_executor.RemoteExecutor(
        "127.0.0.1",
        username="dummy",
        key_filename="path/to/file.key",
        password="123456",
        accept_unknown_host=True,
    )

    mock_load_host_keys = mock.MagicMock()
    mock_sshclient.return_value.load_system_host_keys = mock_load_host_keys
    mock_set_keys = mock.MagicMock()
    mock_sshclient.return_value.set_missing_host_key_policy = mock_set_keys
    mock_connect = mock.MagicMock()
    mock_sshclient.return_value.connect = mock_connect

    mock_in = mock.MagicMock()
    mock_out = mock.MagicMock()
    mock_out.read.return_value = b"outlog"
    mock_recv_exit_status = mock.MagicMock()
    mock_recv_exit_status.return_value = 0
    mock_out.channel.recv_exit_status = mock_recv_exit_status
    mock_err = mock.MagicMock()
    mock_err.read.return_value = b"errlog"
    mock_send = mock.MagicMock()
    mock_shutdown_write = mock.MagicMock()
    mock_in.channel.send = mock_send
    mock_in.channel.shutdown_write = mock_shutdown_write
    mock_exec_command = mock.MagicMock()
    mock_exec_command.return_value = (mock_in, mock_out, mock_err)
    mock_sshclient.return_value.exec_command = mock_exec_command

    out, err = executor._run_cmd("skopeo", stdin="input")

    mock_load_host_keys.assert_called_once()
    assert mock_set_keys.call_count == 1
    assert isinstance(mock_set_keys.call_args[0][0], paramiko.client.WarningPolicy)
    # mock_set_keys.assert_called_once_with(paramiko.client.WarningPolicy)
    mock_connect.assert_called_once_with(
        "127.0.0.1",
        username="dummy",
        password="123456",
        port=22,
        key_filename="path/to/file.key",
    )
    mock_exec_command.assert_called_once_with("'skopeo --authfile $HOME/.docker/config.json'")
    mock_send.assert_called_once_with("input")
    mock_shutdown_write.assert_called_once()
    mock_recv_exit_status.assert_called_once()

    assert out == "outlog"
    assert err == "errlog"


@mock.patch("pubtools._quay.command_executor.paramiko.client.SSHClient")
def test_remote_executor_run_error(mock_sshclient):
    executor = command_executor.RemoteExecutor(
        "127.0.0.1",
        username="dummy",
        key_filename="path/to/file.key",
        password="123456",
        accept_unknown_host=True,
    )

    mock_load_host_keys = mock.MagicMock()
    mock_sshclient.return_value.load_system_host_keys = mock_load_host_keys
    mock_set_keys = mock.MagicMock()
    mock_sshclient.return_value.set_missing_host_key_policy = mock_set_keys
    mock_connect = mock.MagicMock()
    mock_sshclient.return_value.connect = mock_connect

    mock_in = mock.MagicMock()
    mock_out = mock.MagicMock()
    mock_out.read.return_value = b"outlog"
    mock_recv_exit_status = mock.MagicMock()
    mock_recv_exit_status.return_value = -1
    mock_out.channel.recv_exit_status = mock_recv_exit_status
    mock_err = mock.MagicMock()
    mock_err.read.return_value = b"errlog"
    mock_send = mock.MagicMock()
    mock_shutdown_write = mock.MagicMock()
    mock_in.channel.send = mock_send
    mock_in.channel.shutdown_write = mock_shutdown_write
    mock_exec_command = mock.MagicMock()
    mock_exec_command.return_value = (mock_in, mock_out, mock_err)
    mock_sshclient.return_value.exec_command = mock_exec_command

    with pytest.raises(RuntimeError, match="An error has occured when executing.*"):
        executor._run_cmd("pwd", stdin="input")


@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_init(mock_api_client, mock_tls_config, mock_isdir):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
        registry_username="registry_user",
        registry_password="registry_passwd",
    ):
        pass

    mock_tls_config.assert_called_once_with(
        client_cert=("/some/path/cert.pem", "/some/path/key.pem"), verify="/some/path/ca.pem"
    )
    mock_api_client.assert_called_once_with(
        base_url="some-url.com", version="auto", timeout=120, tls=mock_tls_config.return_value
    )
    mock_create_container.assert_called_once_with("quay.io/some/image:1", detach=True, tty=True)
    mock_start.assert_called_once_with("123")
    mock_remove_container.assert_called_once_with("123", force=True)
    mock_api_client.return_value.login.assert_called_once_with(
        username="registry_user", password="registry_passwd", registry="quay.io", reauth=True
    )
    mock_api_client.return_value.pull.assert_called_once_with("quay.io/some/image", tag="1")


@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_run_cmd(mock_api_client, mock_tls_config, mock_isdir):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_exec_create = mock.MagicMock()
    mock_exec_create.return_value = {"Id": "321"}
    mock_api_client.return_value.exec_create = mock_exec_create
    mock_exec_start = mock.MagicMock()
    mock_exec_start.return_value = b"some output"
    mock_api_client.return_value.exec_start = mock_exec_start
    mock_exec_inspect = mock.MagicMock()
    mock_exec_inspect.return_value = {"ExitCode": 0}
    mock_api_client.return_value.exec_inspect = mock_exec_inspect

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        stdout, stderr = executor._run_cmd("cat file.txt")

    assert stdout == "some output"
    assert stderr == "some output"

    mock_exec_create.assert_called_once_with("123", "cat file.txt")
    mock_exec_start.assert_called_once_with("321")
    mock_exec_inspect.assert_called_once_with("321")


@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_run_cmd_error(mock_api_client, mock_tls_config, mock_isdir):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_exec_create = mock.MagicMock()
    mock_exec_create.return_value = {"Id": "321"}
    mock_api_client.return_value.exec_create = mock_exec_create
    mock_exec_start = mock.MagicMock()
    mock_exec_start.return_value = b"some output"
    mock_api_client.return_value.exec_start = mock_exec_start
    mock_exec_inspect = mock.MagicMock()
    mock_exec_inspect.return_value = {"ExitCode": 1}
    mock_api_client.return_value.exec_inspect = mock_exec_inspect

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        with pytest.raises(RuntimeError, match="An error has occured when executing a command."):
            stdout, stderr = executor._run_cmd("cat file.txt")


@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_run_cmd_error_tolerate_error(
    mock_api_client, mock_tls_config, mock_isdir
):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_exec_create = mock.MagicMock()
    mock_exec_create.return_value = {"Id": "321"}
    mock_api_client.return_value.exec_create = mock_exec_create
    mock_exec_start = mock.MagicMock()
    mock_exec_start.return_value = b"some output"
    mock_api_client.return_value.exec_start = mock_exec_start
    mock_exec_inspect = mock.MagicMock()
    mock_exec_inspect.return_value = {"ExitCode": 1}
    mock_api_client.return_value.exec_inspect = mock_exec_inspect

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        executor._run_cmd("cat file.txt", tolerate_err=True)


@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_run_cmd_no_output(mock_api_client, mock_tls_config, mock_isdir):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_exec_create = mock.MagicMock()
    mock_exec_create.return_value = {"Id": "321"}
    mock_api_client.return_value.exec_create = mock_exec_create
    mock_exec_start = mock.MagicMock()
    mock_exec_start.return_value = None
    mock_api_client.return_value.exec_start = mock_exec_start
    mock_exec_inspect = mock.MagicMock()
    mock_exec_inspect.return_value = {"ExitCode": 0}
    mock_api_client.return_value.exec_inspect = mock_exec_inspect

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        stdout, stderr = executor._run_cmd("cat file.txt")

    assert stdout == ""
    assert stderr == ""


@mock.patch("pubtools._quay.command_executor.time.time")
@mock.patch("pubtools._quay.command_executor.tarfile.TarInfo")
@mock.patch("pubtools._quay.command_executor.tarfile.TarFile")
@mock.patch("pubtools._quay.command_executor.io.BytesIO")
@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_add_file(
    mock_api_client,
    mock_tls_config,
    mock_isdir,
    mock_bytesio,
    mock_tarfile,
    mock_tarinfo,
    mock_time,
):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_add_file = mock.MagicMock()
    mock_tarfile.return_value.addfile = mock_add_file
    mock_close = mock.MagicMock()
    mock_tarfile.return_value.close = mock_close
    mock_bytesio1 = mock.MagicMock()
    mock_bytesio2 = mock.MagicMock()
    mock_bytesio.side_effect = [mock_bytesio1, mock_bytesio2]
    mock_seek = mock.MagicMock()
    mock_bytesio1.seek = mock_seek
    mock_put_archive = mock.MagicMock()
    mock_put_archive.return_value = True
    mock_api_client.return_value.put_archive = mock_put_archive

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        executor._add_file("abcdefg", "some-file.txt")

    assert mock_bytesio.call_count == 2
    mock_tarfile.assert_called_once_with(fileobj=mock_bytesio1, mode="w")
    mock_tarinfo.assert_called_once_with(name="some-file.txt")
    mock_add_file.assert_called_once_with(mock_tarinfo.return_value, mock_bytesio2)
    mock_close.assert_called_once_with()
    mock_seek.assert_called_once_with(0)
    mock_put_archive.assert_called_once_with(
        container="123", path="/tmp", data=mock_bytesio1  # nosec B108
    )


@mock.patch("pubtools._quay.command_executor.time.time")
@mock.patch("pubtools._quay.command_executor.tarfile.TarInfo")
@mock.patch("pubtools._quay.command_executor.tarfile.TarFile")
@mock.patch("pubtools._quay.command_executor.io.BytesIO")
@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_add_file_fail(
    mock_api_client,
    mock_tls_config,
    mock_isdir,
    mock_bytesio,
    mock_tarfile,
    mock_tarinfo,
    mock_time,
):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_add_file = mock.MagicMock()
    mock_tarfile.return_value.addfile = mock_add_file
    mock_close = mock.MagicMock()
    mock_tarfile.return_value.close = mock_close
    mock_bytesio1 = mock.MagicMock()
    mock_bytesio2 = mock.MagicMock()
    mock_bytesio.side_effect = [mock_bytesio1, mock_bytesio2]
    mock_seek = mock.MagicMock()
    mock_bytesio1.seek = mock_seek
    mock_put_archive = mock.MagicMock()
    mock_put_archive.return_value = False
    mock_api_client.return_value.put_archive = mock_put_archive

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        with pytest.raises(RuntimeError, match="File was not successfully added to the container"):
            executor._add_file("abcdefg", "some-file.txt")


@mock.patch("random.SystemRandom.choice")
@mock.patch("pubtools._quay.command_executor.ContainerExecutor._add_file")
@mock.patch("pubtools._quay.command_executor.ContainerExecutor._run_cmd")
@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_skopeo_login(
    mock_api_client, mock_tls_config, mock_isdir, mock_run_cmd, mock_add_file, mock_choice
):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_run_cmd.side_effect = [("not logged in", "nothing"), ("Login Succeeded", "nothing")]
    mock_choice.return_value = "0"

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        executor.skopeo_login("some-host", "some-name", "some-password")

    assert mock_run_cmd.call_count == 2
    assert mock_run_cmd.call_args_list[0] == mock.call(
        "skopeo login --get-login some-host", tolerate_err=True
    )
    assert mock_run_cmd.call_args_list[1] == mock.call(
        " sh -c 'cat /tmp/skopeo_password-0000000000.txt | skopeo login --authfile "
        "$HOME/.docker/config.json "
        '-u "some-name" --password-stdin some-host\''
    )
    mock_add_file.assert_called_once_with("some-password", "skopeo_password-0000000000.txt")


@mock.patch("pubtools._quay.command_executor.ContainerExecutor._add_file")
@mock.patch("pubtools._quay.command_executor.ContainerExecutor._run_cmd")
@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_skopeo_login_already_logged(
    mock_api_client, mock_tls_config, mock_isdir, mock_run_cmd, mock_add_file
):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_run_cmd.return_value = ("some-name", "nothing")

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        executor.skopeo_login("some-host", "some-name", "some-password")

    mock_run_cmd.assert_called_once_with("skopeo login --get-login some-host", tolerate_err=True)
    mock_add_file.assert_not_called()


@mock.patch("pubtools._quay.command_executor.ContainerExecutor._add_file")
@mock.patch("pubtools._quay.command_executor.ContainerExecutor._run_cmd")
@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_skopeo_login_missing_credential(
    mock_api_client, mock_tls_config, mock_isdir, mock_run_cmd, mock_add_file
):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True

    mock_run_cmd.side_effect = [("not logged in", "nothing"), ("Login Succeeded", "nothing")]

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        with pytest.raises(ValueError, match="Skopeo login credentials are not present.*"):
            executor.skopeo_login("some-host", "some-name")

    mock_run_cmd.assert_called_once_with("skopeo login --get-login some-host", tolerate_err=True)
    mock_add_file.assert_not_called()


@mock.patch("random.SystemRandom.choice")
@mock.patch("pubtools._quay.command_executor.ContainerExecutor._add_file")
@mock.patch("pubtools._quay.command_executor.ContainerExecutor._run_cmd")
@mock.patch("pubtools._quay.command_executor.os.path.isdir")
@mock.patch("pubtools._quay.command_executor.docker.tls.TLSConfig")
@mock.patch("pubtools._quay.command_executor.docker.APIClient")
def test_container_executor_skopeo_login_fail(
    mock_api_client, mock_tls_config, mock_isdir, mock_run_cmd, mock_add_file, mock_choice
):
    mock_create_container = mock.MagicMock()
    mock_create_container.return_value = {"Id": "123"}
    mock_api_client.return_value.create_container = mock_create_container
    mock_start = mock.MagicMock()
    mock_api_client.return_value.start = mock_start
    mock_remove_container = mock.MagicMock()
    mock_api_client.return_value.remove_container = mock_remove_container
    mock_isdir.return_value = True
    mock_choice.return_value = "0"

    mock_run_cmd.side_effect = [("not logged in", "nothing"), ("Login Failed", "nothing")]

    with command_executor.ContainerExecutor(
        "quay.io/some/image:1",
        base_url="some-url.com",
        timeout=120,
        verify_tls=True,
        cert_path="/some/path",
    ) as executor:
        with pytest.raises(RuntimeError, match="Login command didn't generate expected output.*"):
            executor.skopeo_login("some-host", "some-name", "some-password")

    assert mock_run_cmd.call_count == 2
    assert mock_run_cmd.call_args_list[0] == mock.call(
        "skopeo login --get-login some-host", tolerate_err=True
    )
    assert mock_run_cmd.call_args_list[1] == mock.call(
        " sh -c 'cat /tmp/skopeo_password-0000000000.txt | skopeo login --authfile "
        "$HOME/.docker/config.json "
        '-u "some-name" --password-stdin some-host\''
    )
    mock_add_file.assert_called_once_with("some-password", "skopeo_password-0000000000.txt")


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_login_already_logged(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    mock_run_cmd.return_value = ("quay_user", "")
    executor.skopeo_login("quay_host", "quay_user", "quay_token")
    mock_run_cmd.assert_called_once_with("skopeo login --get-login quay_host", tolerate_err=True)


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_login_missing_credentials(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    mock_run_cmd.return_value = ("not logged into quay", "")
    with pytest.raises(ValueError, match=".*login credentials are not present.*"):
        executor.skopeo_login("some-host")


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_login_success(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    mock_run_cmd.side_effect = [("not logged into quay", ""), ("Login Succeeded", "")]
    executor.skopeo_login("quay_host", "quay_user", "quay_token")
    assert mock_run_cmd.call_args_list == [
        mock.call("skopeo login --get-login quay_host", tolerate_err=True),
        mock.call(
            "skopeo login -u quay_user --password-stdin quay_host",
            stdin="quay_token",
        ),
    ]


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_login_failed(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    mock_run_cmd.side_effect = [("not logged into quay", ""), ("", "Login failed")]
    with pytest.raises(RuntimeError, match="Login command didn't generate.*"):
        executor.skopeo_login("quay_host", "quay_user", "quay_token")


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_tag_images(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    executor.tag_images("quay.io/repo/image:1", ["quay.io/repo/dest:1", "quay.io/repo/dest:2"])
    assert mock_run_cmd.call_args_list == [
        mock.call("skopeo copy docker://quay.io/repo/image:1 docker://quay.io/repo/dest:1"),
        mock.call("skopeo copy docker://quay.io/repo/image:1 docker://quay.io/repo/dest:2"),
    ]


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_tag_images_all_arch(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    executor.tag_images(
        "quay.io/repo/image:1", ["quay.io/repo/dest:1", "quay.io/repo/dest:2"], True
    )
    assert mock_run_cmd.call_args_list == [
        mock.call("skopeo copy --all docker://quay.io/repo/image:1 docker://quay.io/repo/dest:1"),
        mock.call("skopeo copy --all docker://quay.io/repo/image:1 docker://quay.io/repo/dest:2"),
    ]


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_inspect(mock_run_cmd):
    mock_run_cmd.return_value = ('{"aaa":"bbb"}', "")
    executor = command_executor.LocalExecutor()

    ret = executor.skopeo_inspect("quay.io/repo/image:1")
    mock_run_cmd.assert_called_once_with("skopeo inspect docker://quay.io/repo/image:1")
    assert ret == {"aaa": "bbb"}

    ret = executor.skopeo_inspect("quay.io/repo/image:1", raw=True)
    assert ret == '{"aaa":"bbb"}'
