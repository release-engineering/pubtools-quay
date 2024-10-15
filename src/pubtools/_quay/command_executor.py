import contextlib
import io
import json
import logging
import os
import random
import shlex
import string
import subprocess
import tarfile
import time
import textwrap
from types import TracebackType
from typing import Any, Optional, Type, Generator, List, Dict, Tuple
from typing_extensions import Self

import docker
import paramiko
from shlex import quote

from pubtools.tracing import get_trace_wrapper

tw = get_trace_wrapper()
LOG = logging.getLogger("pubtools.quay")


# Python 2.6 version of paramiko doesn't support the usage
# of SSHClient as a context manager. This wrapper adds the functionality
@contextlib.contextmanager
def open_ssh_client() -> Generator[paramiko.client.SSHClient, None, None]:
    """Use SSHClient as a context manager."""
    client = paramiko.client.SSHClient()
    try:
        yield client
    finally:
        client.close()


class Executor(object):
    """
    Base executor class.

    Implementation of command execution should be done in
    descendant classes. Common pre- and post-processing should be
    implemented in this class.
    """

    def __enter__(self) -> Self:
        """Use the class as context manager. Returns instance upon invocation."""
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Cleanup when used as context manager. No-op by default."""
        pass

    def _run_cmd(
        self,
        cmd: str,
        err_msg: Optional[str] = None,
        tolerate_err: bool = False,
        stdin: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Run a bash command."""
        raise NotImplementedError  # pragma: no cover"

    def skopeo_login(
        self, host: str = "quay.io", username: Optional[str] = None, password: Optional[str] = None
    ) -> None:
        """
        Attempt to login to Quay if no login credentials are present.

        Args:
            host (str):
                docker registry host (quay.io as default)
            username (str):
                Username for login.
            password (str):
                Password for login.
        """
        cmd_check = "skopeo login --get-login %s" % host
        out, err = self._run_cmd(cmd_check, tolerate_err=True)
        if username and username in out:
            LOG.info("Already logged in to Quay.io")
            return

        if not username or not password:
            raise ValueError(
                "Skopeo login credentials are not present. Quay user and token must be provided."
            )
        LOG.info("Logging in to Quay with provided credentials")

        cmd_login = ("skopeo login -u {0} --password-stdin %s" % host).format(quote(username))
        out, err = self._run_cmd(cmd_login, stdin=password)

        if "Login Succeeded" in out:
            LOG.info("Login successful")
        else:
            raise RuntimeError(
                "Login command didn't generate expected output. "
                "STDOUT: '{0}', STDERR: '{1}'".format(out, err)
            )

    def tag_images(self, source_ref: str, dest_refs: List[str], all_arch: bool = False) -> None:
        """
        Copy image from source to destination(s) using skopeo.

        Args:
            source_ref (str):
                Reference of the source image.
            dest_refs ([str]):
                List of target references to copy the image to.
            all_arch (bool):
                Whether to copy all architectures (if multiarch image)
        """
        if all_arch:
            cmd = "skopeo copy --all docker://{0} docker://{1}"
        else:
            cmd = "skopeo copy docker://{0} docker://{1}"

        for dest_ref in dest_refs:
            LOG.info("Tagging source '{0}' to destination '{1}'".format(source_ref, dest_ref))
            self._run_cmd(cmd.format(quote(source_ref), quote(dest_ref)))
            LOG.info("Destination image {0} has been tagged.".format(dest_ref))

        LOG.info("Tagging complete.")

    def skopeo_inspect(self, image_ref: str, raw: bool = False) -> Any:
        """
        Run skopeo inspect and return the result.

        NOTE: inspect command will not be run with the --raw argument. This option only returns an
        image manifest, which can be gathered by QuayClient. 'raw' argument in this function
        denotes if the result should be parsed or returned raw.

        Args:
            image_ref (str):
                Image reference to inspect.
            raw (bool):
                Whether to parse the returned JSON, or return raw.
        Returns (dict|str):
            Result of skopeo inspect.
        """
        cmd = "skopeo inspect docker://{0}".format(image_ref)
        out, _ = self._run_cmd(cmd)

        if raw:
            return out
        else:
            return json.loads(out)


class LocalExecutor(Executor):
    """Run commands locally."""

    def __init__(self, params: Dict[str, Any] = {}) -> None:
        """
        Initialize.

        Args:
            params (dict):
                Custom parameters to be applied when running the shell commands.
        """
        self.params = params
        self.params.setdefault("universal_newlines", True)
        self.params.setdefault("stderr", subprocess.PIPE)
        self.params.setdefault("stdout", subprocess.PIPE)
        self.params.setdefault("stdin", subprocess.PIPE)

    @tw.instrument_func(args_to_attr=True)
    def _run_cmd(
        self,
        cmd: str,
        err_msg: Optional[str] = None,
        tolerate_err: bool = False,
        stdin: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Run a command locally.

        Args:
            cmd (str):
                Shell command to be executed.
            error_msg (str):
                Error message written when the command fails.
            tolerate_err (bool):
                Whether to tolerate a failed command.
            stdin (str):
                String to send to standard input for a command.

        Returns (str, str):
            Tuple of stdout and stderr generated by the command.
        """
        err_msg = err_msg or "An error has occured when executing a command."

        p = subprocess.Popen(shlex.split(cmd), **self.params)
        out, err = p.communicate(input=stdin)

        if p.returncode != 0 and not tolerate_err:
            LOG.error("Command {0} failed with the following error:".format(cmd))
            for line in textwrap.wrap(err, 200):
                LOG.error(f"    {line}")
            raise RuntimeError(err_msg)

        return out, err


class RemoteExecutor(Executor):
    """Run commands remotely via SSH."""

    def __init__(
        self,
        hostname: str,
        username: Optional[str] = None,
        key_filename: Optional[str] = None,
        password: Optional[str] = None,
        port: Optional[int] = None,
        accept_unknown_host: bool = True,
    ) -> None:
        """
        Initialize.

        Args:
            hostname (str):
                Host to connect to.
            username (str):
                Username to authenticate as. Defaults to local username.
            key_filename (str):
                Path to a private key for authentication. Default location will be used if omitted.
            password (str):
                Password for ssh authentication. Has lower precedence than private key.
            port (int):
                Optional port of the host.
            accept_unknown_host (bool):
                Whether to accept an unknown host key. Defaults to True.
        """
        self.hostname = hostname
        self.username = username
        self.key_filename = key_filename
        self.password = password
        if accept_unknown_host:
            self.missing_host_policy: (
                paramiko.client.WarningPolicy | paramiko.client.RejectPolicy
            ) = paramiko.client.WarningPolicy()  # noqa: E501
        else:
            self.missing_host_policy = paramiko.client.RejectPolicy()
        self.port = port if port else 22

    def _run_cmd(
        self,
        cmd: str,
        err_msg: Optional[str] = None,
        tolerate_err: bool = False,
        stdin: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Run a command remotely via SSH.

        Args:
            cmd (str):
                Shell command to be executed.
            error_msg (str):
                Error message written when the command fails.
            tolerate_err (bool):
                Whether to tolerate a failed command.
            stdin (str):
                String to send to standard input for a command.

        Returns (str, str):
            Tuple of stdout and stderr generated by the command.
        """
        err_msg = err_msg or "An error has occured when executing a command."
        with open_ssh_client() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(self.missing_host_policy)
            client.connect(
                self.hostname,
                username=self.username,
                port=self.port,
                password=self.password,
                key_filename=self.key_filename,
            )

            if cmd.startswith("skopeo"):
                cmd = cmd + " --authfile $HOME/.docker/config.json"
            ssh_in, out, err = client.exec_command(quote(cmd))  # nosec B601
            if stdin:
                ssh_in.channel.send(stdin)  # type: ignore
                ssh_in.channel.shutdown_write()

            out_text = out.read().decode("utf-8")
            err_text = err.read().decode("utf-8")
            if out.channel.recv_exit_status() != 0 and not tolerate_err:
                LOG.error("Command {0} failed with the following error:".format(cmd))
                for line in err_text.splitlines():
                    LOG.error(f"    {line}")
                raise RuntimeError(err_msg)

        return out_text, err_text


class ContainerExecutor(Executor):
    """Run commands in a Docker container."""

    def __init__(
        self,
        image: str,
        base_url: str = "unix://var/run/docker.sock",
        timeout: Optional[int] = None,
        verify_tls: bool = False,
        cert_path: Optional[str] = None,
        registry_username: Optional[str] = None,
        registry_password: Optional[str] = None,
    ) -> None:
        """
        Initialize.

        Args:
            image (str):
                Path to an image which will be used for performing skopeo operations. Must be
                downloadable by Docker.
            base_url (str):
                Base URL of the Docker client.
            timeout (int):
                Default timeout for API calls, in seconds.
            verify_tls (bool):
                Whether to use TLS verification.
            cert_path (str|None):
                Custom path to TLS certificates. If not specified, '~/.docker' is used.
            registry_username (str|None):
                Username to login to registry containing the specified image. If not provided,
                login will be assumed to not be needed.
            registry_password (str|None):
                Password to login to registry containing the specified image. If not provided,
                login will be assumed to not be needed.
        """
        self.image = image

        kwargs: Dict[Any, Any] = {}
        kwargs["base_url"] = base_url
        kwargs["version"] = "auto"
        if timeout:
            kwargs["timeout"] = timeout
        if verify_tls:
            kwargs["base_url"] = kwargs["base_url"].replace("tcp://", "https://")
            cert_path = cert_path or os.path.join(os.path.expanduser("~"), ".docker")
            if os.path.isdir(cert_path):
                kwargs["tls"] = docker.tls.TLSConfig(
                    client_cert=(
                        os.path.join(cert_path, "cert.pem"),
                        os.path.join(cert_path, "key.pem"),
                    ),
                    verify=os.path.join(cert_path, "ca.pem"),
                )

        self.client = docker.APIClient(**kwargs)
        repo, tag = self.image.split(":", 1)
        if registry_username and registry_password:
            self.client.login(
                username=registry_username,
                password=registry_password,
                registry=image.split("/")[0] if "/" in image else None,
                reauth=True,
            )
        self.client.pull(repo, tag=tag)
        self.container = self.client.create_container(self.image, detach=True, tty=True)
        self.client.start(self.container["Id"])

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        """Cleanup the container when used as a context manager."""
        self.client.remove_container(self.container["Id"], force=True)

    def _run_cmd(
        self,
        cmd: str,
        err_msg: Optional[str] = None,
        tolerate_err: bool = False,
        stdin: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Run a command locally.

        NOTE: Older versions of Docker API don't support demuxing of stdout and stderr.
        This means that data from both streams will be mixed together. To maintain compatibility
        with the other classes, same output will be returned twice as a tuple. Each string
        will contain the same mix of stdout and stderr messages.

        Args:
            cmd (str):
                Shell command to be executed.
            error_msg (str):
                Error message written when the command fails.
            tolerate_err (bool):
                Whether to tolerate a failed command.
            stdin (None|str):
                This parameter exists only for compatibility with parent class. Sending input
                to containers is not supported.

        Returns (str, str):
            Tuple of stdout and stderr generated by the command.
        """
        err_msg = err_msg or "An error has occured when executing a command."
        cmd_exec = self.client.exec_create(self.container["Id"], cmd)
        # Unfortunately, older versions of Docker API don't support demuxing stdout and stderr
        stdout = self.client.exec_start(cmd_exec["Id"])

        if self.client.exec_inspect(cmd_exec["Id"]).get("ExitCode") != 0 and not tolerate_err:
            LOG.error("Command {0} failed with the following error:".format(cmd))
            for line in stdout.splitlines():
                LOG.error(f"    {line}")
            raise RuntimeError(err_msg)

        if stdout is None:
            stdout = b""
        out_str = stdout.decode("utf-8")

        return (out_str, out_str)

    def _add_file(self, data: str, file_name: str) -> None:
        """
        Add a text file to the running container.

        The primary use-case is to store a secret which will be accessed from inside the container.
        File will be stored in the path /tmp/<file_name>.

        Args:
            data (str):
                Data that should be stored in the container.
            file_name (str):
                Name of the file.
        """
        data_stream = io.BytesIO()
        data_tar = tarfile.TarFile(fileobj=data_stream, mode="w")
        encoded_data = data.encode("utf-8")
        tarinfo = tarfile.TarInfo(name=file_name)
        tarinfo.size = len(encoded_data)
        tarinfo.mtime = int(time.time())
        data_tar.addfile(tarinfo, io.BytesIO(encoded_data))
        data_tar.close()

        data_stream.seek(0)
        success = self.client.put_archive(
            container=self.container["Id"], path="/tmp", data=data_stream  # nosec B108
        )

        if not success:
            raise RuntimeError("File was not successfully added to the container")

    def skopeo_login(
        self, host: str = "quay.io", username: Optional[str] = None, password: Optional[str] = None
    ) -> None:
        """
        Attempt to login to Quay if no login credentials are present.

        This method is reimplemented because it uses a different approach to input the password.

        Args:
            host (str):
                docker registry host (quay.io as default)
            username (str):
                Username for login.
            password (str):
                Password for login.
        """
        cmd_check = "skopeo login --get-login %s" % host
        out, err = self._run_cmd(cmd_check, tolerate_err=True)
        if username and username in out:
            LOG.info("Already logged in to Quay.io")
            return

        if not username or not password:
            raise ValueError(
                "Skopeo login credentials are not present. Quay user and token must be provided."
            )
        LOG.info("Logging in to Quay with provided credentials")

        suffix = "".join(
            random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(10)
        )
        password_file = "skopeo_password-{0}.txt".format(suffix)
        self._add_file(password, password_file)

        cmd_login = (
            " sh -c 'cat /tmp/{1} | skopeo login --authfile $HOME/.docker/config.json"
            ' -u "{0}" --password-stdin %s\'' % host
        ).format(quote(username), password_file)
        out, err = self._run_cmd(cmd_login)

        if "Login Succeeded" in out:
            LOG.info("Login successful")
        else:
            raise RuntimeError(
                "Login command didn't generate expected output. "
                "STDOUT: '{0}', STDERR: '{1}'".format(out, err)
            )
