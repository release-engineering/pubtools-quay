import contextlib
import json
import logging
import shlex
import subprocess
from six.moves import shlex_quote

import paramiko

LOG = logging.getLogger("PubLogger")
LOG.setLevel(logging.INFO)


# Python 2.6 version of paramiko doesn't support the usage
# of SSHClient as a context manager. This wrapper adds the functionality
@contextlib.contextmanager
def open_ssh_client():
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

    def _run_cmd(self, cmd, err_msg=None, tolerate_err=False, stdin=None):
        """Run a bash command."""
        raise NotImplementedError  # pragma: no cover"

    def skopeo_login(self, username=None, password=None):
        """
        Attempt to login to Quay if no login credentials are present.

        Args:
            username (str):
                Username for login.
            password (str):
                Password for login.
        """
        cmd_check = "skopeo login --get-login quay.io"
        out, err = self._run_cmd(cmd_check, tolerate_err=True)
        if "not logged into" not in err and "not logged into" not in out:
            LOG.info("Already logged in to Quay.io")
            return

        if not username or not password:
            raise ValueError(
                "Skopeo login credentials are not present. Quay user and token must be provided."
            )
        LOG.info("Logging in to Quay with provided credentials")

        cmd_login = (
            "skopeo login --authfile $HOME/.docker/config.json -u {0} --password-stdin quay.io"
        ).format(shlex_quote(username))
        out, err = self._run_cmd(cmd_login, stdin=password)

        if "Login Succeeded" in out:
            LOG.info("Login successful")
        else:
            raise RuntimeError(
                "Login command didn't generate expected output. "
                "STDOUT: '{0}', STDERR: '{1}'".format(out, err)
            )

    def tag_images(self, source_ref, dest_refs, all_arch=False):
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
            self._run_cmd(cmd.format(shlex_quote(source_ref), shlex_quote(dest_ref)))
            LOG.info("Destination image {0} has been tagged.".format(dest_ref))

        LOG.info("Tagging complete.")

    def skopeo_inspect(self, image_ref, raw=False):
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

    def __init__(self, params={}):
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

    def _run_cmd(self, cmd, err_msg=None, tolerate_err=False, stdin=None):
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
            LOG.error("Command {0} failed with {1}".format(cmd, err))
            raise RuntimeError(err_msg)

        return out, err


class RemoteExecutor(Executor):
    """Run commands remotely via SSH."""

    def __init__(
        self,
        hostname,
        username=None,
        key_filename=None,
        password=None,
        port=None,
        accept_unknown_host=True,
    ):
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
            self.missing_host_policy = paramiko.client.WarningPolicy()
        else:
            self.missing_host_policy = paramiko.client.RejectPolicy()
        self.port = port if port else 22

    def _run_cmd(self, cmd, err_msg=None, tolerate_err=False, stdin=None):
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

            ssh_in, out, err = client.exec_command(cmd)
            if stdin:
                ssh_in.channel.send(stdin)
                ssh_in.channel.shutdown_write()

            out_text = out.read().decode("utf-8")
            err_text = err.read().decode("utf-8")
            if out.channel.recv_exit_status() != 0 and not tolerate_err:
                LOG.error("Command {0} failed with {1}".format(cmd, err_text))
                raise RuntimeError(err_msg)

        return out_text, err_text
