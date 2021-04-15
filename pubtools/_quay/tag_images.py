import logging

from .utils.misc import setup_arg_parser, add_args_env_variables, send_umb_message
from .command_executor import LocalExecutor, RemoteExecutor

LOG = logging.getLogger("PubLogger")
LOG.setLevel(logging.INFO)

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
    ("--send-umb-msg",): {
        "help": "Flag of whether to send a UMB message",
        "required": False,
        "type": bool,
    },
    ("--umb-url",): {
        "help": "UMB URL. More than one can be specified.",
        "required": False,
        "type": str,
        "action": "append",
    },
    ("--umb-cert",): {
        "help": "Path to the UMB certificate for SSL authentication.",
        "required": False,
        "type": str,
    },
    ("--umb-client-key",): {
        "help": "Path to the UMB private key for accessing the certificate.",
        "required": False,
        "type": str,
    },
    ("--umb-ca-cert",): {
        "help": "Path to the UMB CA certificate.",
        "required": False,
        "type": str,
    },
    ("--umb-topic",): {
        "help": "UMB topic to send the message to.",
        "required": False,
        "type": str,
        "default": "VirtualTopic.eng.pub.quay_tag_image",
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
    kwargs["umb_urls"] = kwargs.pop("umb_url")

    return kwargs


def tag_images(
    source_ref,
    dest_refs,
    all_arch=False,
    quay_user=None,
    quay_password=None,
    remote_exec=False,
    ssh_remote_host=None,
    ssh_remote_host_port=None,
    ssh_reject_unknown_host=False,
    ssh_username=None,
    ssh_password=None,
    ssh_key_filename=None,
    send_umb_msg=False,
    umb_urls=[],
    umb_cert=None,
    umb_client_key=None,
    umb_ca_cert=None,
    umb_topic="VirtualTopic.eng.pub.quay_tag_image",
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
        remote_exec (bool):
            Whether to execute the command remotely.
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
        send_umb_msg (bool):
            Whether to send UMB messages about the untagged images.
        umb_urls ([str]):
            AMQP broker URLs to connect to.
        umb_cert (str):
            Path to a certificate used for UMB authentication.
        umb_client_key (str):
            Path to a client key to decrypt the certificate (if necessary).
        umb_ca_cert (str):
            Path to a CA certificate (for mutual authentication).
        umb_topic (str):
            Topic to send the UMB messages to.
    """
    verify_tag_images_args(
        quay_user,
        quay_password,
        remote_exec,
        ssh_remote_host,
        send_umb_msg,
        umb_urls,
        umb_cert,
    )

    if remote_exec:
        accept_host = not ssh_reject_unknown_host if ssh_reject_unknown_host else True
        executor = RemoteExecutor(
            ssh_remote_host,
            ssh_username,
            ssh_key_filename,
            ssh_password,
            ssh_remote_host_port,
            accept_host,
        )
    else:
        executor = LocalExecutor()

    executor.skopeo_login(quay_user, quay_password)
    executor.tag_images(source_ref, dest_refs, all_arch)

    if send_umb_msg:
        props = {"source_ref": source_ref, "dest_refs": dest_refs}
        send_umb_message(
            umb_urls,
            props,
            umb_cert,
            umb_topic,
            client_key=umb_client_key,
            ca_cert=umb_ca_cert,
        )


def verify_tag_images_args(
    quay_user,
    quay_password,
    remote_exec,
    ssh_remote_host,
    send_umb_msg,
    umb_urls,
    umb_cert,
):
    """Verify the presence of input parameters."""
    if remote_exec:
        if not ssh_remote_host:
            raise ValueError("Remote host is missing when remote execution was specified.")

    if (quay_user and not quay_password) or (quay_password and not quay_user):
        raise ValueError("Both user and password must be present when attempting to log in.")

    if send_umb_msg:
        if not umb_urls:
            raise ValueError("UMB URL must be specified if sending a UMB message was requested.")
        if not umb_cert:
            raise ValueError(
                "A path to a client certificate must be provided when sending a UMB message."
            )


def tag_images_main(sysargs=None):
    """Entrypoint for image tagging."""
    parser = setup_arg_parser(TAG_IMAGES_ARGS)
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"
    args = add_args_env_variables(args, TAG_IMAGES_ARGS)

    kwargs = construct_kwargs(args)
    tag_images(**kwargs)
