import functools
import logging

from pubtools.pluggy import pm, task_context

from .utils.misc import setup_arg_parser, add_args_env_variables
from .command_executor import LocalExecutor, RemoteExecutor, ContainerExecutor

LOG = logging.getLogger("pubtools.quay")

TAG_IMAGES_ARGS = {
    ("--source-ref",): {
        "help": "Source image reference.",
        "required": True,
        "type": str,
    },
    ("--dest-ref",): {
        "help": "Destination image reference. Multiple can be specified.",
        "required": True,
        "type": str,
        "action": "append",
    },
    ("--all-arch",): {
        "help": "Flag of whether to copy all architectures of an image (if multiatch image)",
        "required": False,
        "type": bool,
    },
    ("--quay-user",): {
        "help": "Username for Quay login.",
        "required": False,
        "type": str,
    },
    ("--quay-password",): {
        "help": "Password for Quay. Can be specified by env variable QUAY_PASSWORD.",
        "required": False,
        "type": str,
        "env_variable": "QUAY_PASSWORD",
    },
    ("--source-quay-host",): {
        "help": "Host of source_ref.",
        "required": False,
        "type": str,
    },
    ("--source-quay-user",): {
        "help": "Username for source_ref registry login.",
        "required": False,
        "type": str,
    },
    ("--source-quay-password",): {
        "help": "Password for source_ref registry. Can be specified by env "
        "variable SOURCE_QUAY_PASSWORD.",
        "required": False,
        "type": str,
        "env_variable": "SOURCE_QUAY_PASSWORD",
    },
    ("--remote-exec",): {
        "help": "Flag of whether the commands should be executed on a remote server.",
        "required": False,
        "type": bool,
    },
    ("--ssh-remote-host",): {
        "help": "Hostname for remote execution.",
        "required": False,
        "type": str,
    },
    ("--ssh-remote-host-port",): {
        "help": "Port of the remote host",
        "required": False,
        "type": int,
    },
    ("--ssh-reject-unknown-host",): {
        "help": "Flag of whether to reject an SSH host when it's not found among known hosts.",
        "required": False,
        "type": bool,
    },
    ("--ssh-username",): {
        "help": "Username for SSH connection. Defaults to local username.",
        "required": False,
        "type": str,
    },
    ("--ssh-password",): {
        "help": "Password for SSH. Will only be used if key-based validation is not available. "
        "Can be specified by env variable SSH_PASSWORD",
        "required": False,
        "type": str,
        "env_variable": "SSH_PASSWORD",
    },
    ("--ssh-key-filename",): {
        "help": "Path to the private key file for SSH authentication.",
        "required": False,
        "type": str,
    },
    ("--container-exec",): {
        "help": "Whether to execute the commands in a Docker container.",
        "required": False,
        "type": bool,
    },
    ("--container-image",): {
        "help": "Path to the container image in which to execute the commands. Must be "
        "downloadable without extra permissions.",
        "required": False,
        "type": str,
    },
    ("--docker-url",): {
        "help": "URL of the docker client that should run the container. Local socket by default.",
        "required": False,
        "type": str,
        "default": "unix://var/run/docker.sock",
    },
    ("--docker-timeout",): {
        "help": "Timeout for executing Docker commands. Disabled by default.",
        "required": False,
        "type": str,
    },
    ("--docker-verify-tls",): {
        "help": "Whether to perform TLS verification with the Docker client. Disabled by default.",
        "required": False,
        "type": bool,
    },
    ("--docker-cert-path",): {
        "help": "Path to Docker certificates for TLS authentication. '~/.docker' by default.",
        "required": False,
        "type": str,
    },
    ("--registry-username",): {
        "help": "Username to login to registry containing the specified image. If not provided, "
        "login will be assumed to not be needed.",
        "required": False,
        "type": str,
    },
    ("--registry-password",): {
        "help": "Password to login to registry containing the specified image. If not provided, "
        "login will be assumed to not be needed. "
        "Can be specified by env variable REGISTRY_PASSWORD.",
        "required": False,
        "type": str,
        "env_variable": "REGISTRY_PASSWORD",
    },
}


def construct_kwargs(args):
    """
    Construct a kwargs dictionary based on the entered command line arguments.

    Args:
        args (argparse.Namespace):
            Parsed command line arguments.
    Returns (dict):
        Keyword arguments for the 'tag_images' function.
    """
    kwargs = args.__dict__

    # in args.__dict__ unspecified bool values have 'None' instead of 'False'
    for name, attributes in TAG_IMAGES_ARGS.items():
        if attributes["type"] is bool:
            bool_var = name[0].lstrip("-").replace("-", "_")
            if kwargs[bool_var] is None:
                kwargs[bool_var] = False

    # some exceptions have to be remapped
    kwargs["dest_refs"] = kwargs.pop("dest_ref")

    return kwargs


def tag_images(
    source_ref,
    dest_refs,
    all_arch=False,
    quay_user=None,
    quay_password=None,
    source_quay_host=None,
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
    registry_username=None,
    registry_password=None,
):
    """
    Tag images in Quay.

    Args:
        source_ref (str):
            Source image reference.
        dest_refs ([str]):
            List of destination image references.
        all_arch (bool):
            Whether to copy all architectures.
        quay_user (str):
            Quay username for Docker HTTP API.
        quay_password (str):
            Quay password for Docker HTTP API.
        source_quay_host (str):
            Host of source ref.
        source_quay_user (str):
            Quay username for Docker HTTP API for the source ref.
        source_quay_password (str):
            Quay password for Docker HTTP API for the source ref.
        remote_exec (bool):
            Whether to execute the command remotely. Takes precedence over container_exec.
        ssh_remote_host (str):
            Hostname for remote execution.
        ssh_remote_host_port (str):
            Port of the remote host.
        ssh_reject_unknown_host (bool):
            whether to reject an SSH host when it's not found among known hosts.
        ssh_username (str):
            Username for SSH connection. Defaults to local username.
        ssh_password (str):
            Password for SSH. Will only be used if key-based validation is not available.
        ssh_key_filename (str):
            Path to the private key file for SSH authentication.
        container_exec (bool):
            Whether to execute the commands in a Docker container.
        container_image (str):
            Path to the container image in which to execute the commands. Must be downloadable
            without extra permissions.
        docker_url (str):
            URL of the docker client that should run the container. Local socket by default.
        docker_timeout (int):
            Timeout for executing Docker commands. Disabled by default.
        docker_verify_tls (bool):
            Whether to perform TLS verification with the Docker client. Disabled by default.
        docker_cert_path (str):
            Path to Docker certificates for TLS authentication. '~/.docker' by default.
        registry_username (str):
            Username to login to registry containing the specified image. If not provided,
            login will be assumed to not be needed.
        registry_password (str):
            Password to login to registry containing the specified image. If not provided,
            login will be assumed to not be needed.
    """
    verify_tag_images_args(
        quay_user,
        quay_password,
        source_quay_user,
        source_quay_password,
        remote_exec,
        ssh_remote_host,
        container_exec,
        container_image,
    )

    if remote_exec:
        accept_host = not ssh_reject_unknown_host if ssh_reject_unknown_host else True
        executor_class = functools.partial(
            RemoteExecutor,
            ssh_remote_host,
            ssh_username,
            ssh_key_filename,
            ssh_password,
            ssh_remote_host_port,
            accept_host,
        )
    elif container_exec:
        if isinstance(docker_timeout, str):
            docker_timeout = int(docker_timeout)
        executor_class = functools.partial(
            ContainerExecutor,
            container_image,
            docker_url,
            docker_timeout,
            docker_verify_tls,
            docker_cert_path,
            registry_username,
            registry_password,
        )
    else:
        executor_class = functools.partial(LocalExecutor)

    with executor_class() as executor:
        dest_host = dest_refs[0].split("/", 1)[0]
        executor.skopeo_login(dest_host, quay_user, quay_password)
        if source_quay_host and source_quay_user and source_quay_password:
            executor.skopeo_login(source_quay_host, source_quay_user, source_quay_password)
        executor.tag_images(source_ref, dest_refs, all_arch)

    pm.hook.quay_images_tagged(source_ref=source_ref, dest_refs=sorted(dest_refs))


def verify_tag_images_args(
    quay_user,
    quay_password,
    source_quay_user,
    source_quay_password,
    remote_exec,
    ssh_remote_host,
    container_exec,
    container_image,
):
    """Verify the presence of input parameters."""
    if remote_exec:
        if not ssh_remote_host:
            raise ValueError("Remote host is missing when remote execution was specified.")

    if container_exec:
        if not container_image:
            raise ValueError("Container image is missing when container execution was specified.")

    if (quay_user and not quay_password) or (quay_password and not quay_user):
        raise ValueError("Both user and password must be present when attempting to log in.")

    if (source_quay_user and not source_quay_password) or (
        source_quay_password and not source_quay_user
    ):
        raise ValueError(
            "Both source quay user and password must be present when attempting to log in."
        )


def setup_args():
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(TAG_IMAGES_ARGS)


def tag_images_main(sysargs=None):
    """Entrypoint for image tagging."""
    logging.basicConfig(level=logging.INFO)

    parser = setup_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"
    args = add_args_env_variables(args, TAG_IMAGES_ARGS)

    kwargs = construct_kwargs(args)
    with task_context():
        tag_images(**kwargs)
