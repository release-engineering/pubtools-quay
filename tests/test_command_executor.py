import mock
import paramiko
import pytest

from pubtools._quay import command_executor


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
def test_local_executor_run_error(mock_popen):
    executor = command_executor.LocalExecutor({"some_param": "value"})

    mock_communicate = mock.MagicMock()
    mock_communicate.return_value = ("outlog", "errlog")
    mock_popen.return_value.communicate = mock_communicate
    mock_popen.return_value.returncode = -1

    with pytest.raises(RuntimeError, match="An error has occured when executing.*"):
        executor._run_cmd("pwd", stdin="input")


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
    assert executor.missing_host_policy == paramiko.client.RejectPolicy

    executor2 = command_executor.RemoteExecutor("127.0.0.1")

    assert executor2.missing_host_policy == paramiko.client.WarningPolicy


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
    mock_sshclient.return_value.__enter__.return_value.load_system_host_keys = (
        mock_load_host_keys
    )
    mock_set_keys = mock.MagicMock()
    mock_sshclient.return_value.__enter__.return_value.set_missing_host_key_policy = (
        mock_set_keys
    )
    mock_connect = mock.MagicMock()
    mock_sshclient.return_value.__enter__.return_value.connect = mock_connect

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
    mock_sshclient.return_value.__enter__.return_value.exec_command = mock_exec_command

    out, err = executor._run_cmd("pwd", stdin="input")

    mock_load_host_keys.assert_called_once()
    mock_set_keys.assert_called_once_with(paramiko.client.WarningPolicy)
    mock_connect.assert_called_once_with(
        "127.0.0.1",
        username="dummy",
        password="123456",
        port=22,
        key_filename="path/to/file.key",
    )
    mock_exec_command.assert_called_once_with("pwd")
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
    mock_sshclient.return_value.__enter__.return_value.load_system_host_keys = (
        mock_load_host_keys
    )
    mock_set_keys = mock.MagicMock()
    mock_sshclient.return_value.__enter__.return_value.set_missing_host_key_policy = (
        mock_set_keys
    )
    mock_connect = mock.MagicMock()
    mock_sshclient.return_value.__enter__.return_value.connect = mock_connect

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
    mock_sshclient.return_value.__enter__.return_value.exec_command = mock_exec_command

    with pytest.raises(RuntimeError, match="An error has occured when executing.*"):
        executor._run_cmd("pwd", stdin="input")


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_login_already_logged(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    mock_run_cmd.return_value = ("Already logged in!", "")
    executor.skopeo_login("quay_user", "quay_token")
    mock_run_cmd.assert_called_once_with(
        "skopeo login --get-login quay.io", tolerate_err=True
    )


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_login_missing_credentials(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    mock_run_cmd.return_value = ("not logged into quay", "")
    with pytest.raises(ValueError, match=".*login credentials are not present.*"):
        executor.skopeo_login()


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_login_success(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    mock_run_cmd.side_effect = [("not logged into quay", ""), ("Login Succeeded", "")]
    executor.skopeo_login("quay_user", "quay_token")
    assert mock_run_cmd.call_args_list == [
        mock.call("skopeo login --get-login quay.io", tolerate_err=True),
        mock.call(
            "skopeo login --authfile $HOME/.docker/config.json -u quay_user "
            "--password-stdin quay.io",
            stdin="quay_token",
        ),
    ]


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_login_failed(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    mock_run_cmd.side_effect = [("not logged into quay", ""), ("", "Login failed")]
    with pytest.raises(RuntimeError, match="Login command didn't generate.*"):
        executor.skopeo_login("quay_user", "quay_token")


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_tag_images(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    executor.tag_images(
        "quay.io/repo/image:1", ["quay.io/repo/dest:1", "quay.io/repo/dest:2"]
    )
    assert mock_run_cmd.call_args_list == [
        mock.call(
            "skopeo copy docker://quay.io/repo/image:1 docker://quay.io/repo/dest:1"
        ),
        mock.call(
            "skopeo copy docker://quay.io/repo/image:1 docker://quay.io/repo/dest:2"
        ),
    ]


@mock.patch("pubtools._quay.command_executor.LocalExecutor._run_cmd")
def test_skopeo_tag_images_all_arch(mock_run_cmd):
    executor = command_executor.LocalExecutor()

    executor.tag_images(
        "quay.io/repo/image:1", ["quay.io/repo/dest:1", "quay.io/repo/dest:2"], True
    )
    assert mock_run_cmd.call_args_list == [
        mock.call(
            "skopeo copy --all docker://quay.io/repo/image:1 docker://quay.io/repo/dest:1"
        ),
        mock.call(
            "skopeo copy --all docker://quay.io/repo/image:1 docker://quay.io/repo/dest:2"
        ),
    ]
