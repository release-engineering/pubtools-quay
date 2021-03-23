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
        Keyword arguments for the 'untag_images' function.
    """
    dest_refs = args.dest_ref if isinstance(args.dest_ref, list) else [args.dest_ref]
    kwargs = {"source_ref": args.source_ref, "dest_refs": dest_refs}
    if args.all_arch:
        kwargs["all_arch"] = args.all_arch
    if args.quay_user:
        kwargs["quay_user"] = args.quay_user
    if args.quay_password:
        kwargs["quay_password"] = args.quay_password
    if args.remote_exec:
        kwargs["remote_exec"] = args.remote_exec
    if args.ssh_remote_host:
        kwargs["ssh_remote_host"] = args.ssh_remote_host
    if args.ssh_remote_host_port:
        kwargs["ssh_remote_host_port"] = args.ssh_remote_host_port
    if args.ssh_reject_unknown_host:
        kwargs["ssh_reject_unknown_host"] = args.ssh_reject_unknown_host
    if args.ssh_username:
        kwargs["ssh_username"] = args.ssh_username
    if args.ssh_password:
        kwargs["ssh_password"] = args.ssh_password
    if args.ssh_key_filename:
        kwargs["ssh_key_filename"] = args.ssh_key_filename
    if args.send_umb_msg:
        kwargs["send_umb_msg"] = args.send_umb_msg
    if args.umb_url:
        umb_urls = args.umb_url if isinstance(args.umb_url, list) else [args.umb_url]
        kwargs["umb_urls"] = umb_urls
    if args.umb_cert:
        kwargs["umb_cert"] = args.umb_cert
    if args.umb_client_key:
        kwargs["umb_client_key"] = args.umb_client_key
    if args.umb_ca_cert:
        kwargs["umb_cacert"] = args.umb_ca_cert
    if args.umb_topic:
        kwargs["umb_topic"] = args.umb_topic

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
    umb_cacert=None,
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
        umb_cacert (str):
            Path to a CA certificate (for mutual authentication).
        umb_topic (str):
            Topic to send the UMB messages to.
    """
    verify_tag_images_args(
        quay_user, quay_password, remote_exec, ssh_remote_host, send_umb_msg, umb_urls, umb_cert,
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
            umb_urls, props, umb_cert, umb_topic, client_key=umb_client_key, ca_cert=umb_cacert,
        )


def verify_tag_images_args(
    quay_user, quay_password, remote_exec, ssh_remote_host, send_umb_msg, umb_urls, umb_cert,
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
                "A path to a client certificate must be provided " "when sending a UMB message."
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
