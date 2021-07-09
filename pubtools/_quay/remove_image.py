import logging

from .signature_remover import SignatureRemover
from .quay_client import QuayClient
from .untag_images import untag_images
from .utils.misc import (
    setup_arg_parser,
    add_args_env_variables,
    send_umb_message,
)

LOG = logging.getLogger("pubtools.quay")

REMOVE_IMAGE_ARGS = {
    ("--reference",): {
        "help": "Image reference to remove. Must be specified by tag. Multiple can be specified",
        "required": True,
        "type": str,
        "action": "append",
    },
    ("--quay-api-token",): {
        "help": "OAuth token for Quay REST API.",
        "required": False,
        "type": str,
        "env_variable": "QUAY_API_TOKEN",
    },
    ("--quay-user",): {
        "help": "Username for Quay login.",
        "required": True,
        "type": str,
    },
    ("--quay-password",): {
        "help": "Password for Quay. Can be specified by env variable QUAY_PASSWORD.",
        "required": False,
        "type": str,
        "env_variable": "QUAY_PASSWORD",
    },
    ("--pyxis-server",): {
        "help": "Pyxis service hostname",
        "required": True,
        "type": str,
    },
    ("--pyxis-krb-principal",): {
        "help": "Pyxis kerberos principal in form: name@REALM",
        "required": True,
        "type": str,
    },
    ("--pyxis-krb-ktfile",): {
        "help": "Pyxis Kerberos client keytab. Optional. Used for login if TGT is not available.",
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
        "default": "VirtualTopic.eng.pub.quay_remove_images",
    },
}


def construct_kwargs(args):
    """
    Construct a kwargs dictionary based on the entered command line arguments.

    Args:
        args (argparse.Namespace):
            Parsed command line arguments.

    Returns (dict):
        Keyword arguments for the 'remove_repository' function.
    """
    kwargs = args.__dict__

    # in args.__dict__ unspecified bool values have 'None' instead of 'False'
    for name, attributes in REMOVE_IMAGE_ARGS.items():
        if attributes["type"] is bool:
            bool_var = name[0].lstrip("-").replace("-", "_")
            if kwargs[bool_var] is None:
                kwargs[bool_var] = False

    # some exceptions have to be remapped
    kwargs["umb_urls"] = kwargs.pop("umb_url")

    return kwargs


def verify_remove_image_args(references, send_umb_msg, umb_urls, umb_cert):
    """
    Verify the presence and correctness of input parameters.

    Args:
        references ([str]):
            Image references to remove.
        send_umb_msg (bool):
            Whether to send UMB messages about the untagged images.
        umb_urls ([str]):
            AMQP broker URLs to connect to.
        umb_cert (str):
            Path to a certificate used for UMB authentication.
    """
    first_organization = None
    for reference in references:
        if "@" in reference:
            raise ValueError(
                "Image {0} is specified via digest. Please specify all images via tag".format(
                    reference
                )
            )

        organization = reference.split(":")[0].split("/")[1]
        if first_organization is None:
            first_organization = organization
        if first_organization != organization:
            raise ValueError(
                "All images must belong to the same organization. Mismatch: {0} <-> {1}".format(
                    organization, first_organization
                )
            )

    if send_umb_msg:
        if not umb_urls:
            raise ValueError("UMB URL must be specified if sending a UMB message was requested.")
        if not umb_cert:
            raise ValueError(
                "A path to a client certificate must be provided when sending a UMB message."
            )


def group_images_by_repo(references):
    """
    Sort images into groups where all images are in the same repo.

    Args:
        references ([str]):
            Image references to sort.
    Returns ({str: [str]}):
        Mapping of repo name -> list of references contained in this repo.
    """
    repo_images_mapping = {}
    for reference in references:
        repo = reference.split(":")[0].split("/")[-1]
        repo_images_mapping.setdefault(repo, []).append(reference)

    return repo_images_mapping


def get_repo_images_to_remove(repo_images, quay_client):
    """
    Get a list of images that should be removed based on the specified input.

    Args:
        repo_images ([str]):
            List of images belonging to the same repo.
        quay_client (QuayClient):
            QuayClient instance.
    Returns [str]:
        Images which should be removed.
    """
    full_repository = repo_images[0].split(":")[0]
    repository = full_repository.split("/", 1)[1]
    repo_tags = quay_client.get_repository_tags(repository)
    tag_digest_mapping = {}
    digest_tag_mapping = {}
    references_to_remove = []

    for tag in repo_tags["tags"]:
        image = "{0}:{1}".format(full_repository, tag)
        digest = quay_client.get_manifest_digest(image)
        tag_digest_mapping[tag] = digest
        digest_tag_mapping.setdefault(digest, []).append(tag)

    for image in repo_images:
        tag = image.split(":")[-1]
        if tag not in tag_digest_mapping:
            raise ValueError("Image {0} doesn't exist".format(image))

        remove_tags = digest_tag_mapping[tag_digest_mapping[tag]]
        references_to_remove += ["{0}:{1}".format(full_repository, tag) for tag in remove_tags]

    return sorted(list(set(references_to_remove)))


# TODO: integration tests
def remove_images(
    reference,
    quay_api_token,
    quay_user,
    quay_password,
    pyxis_server,
    pyxis_krb_principal,
    pyxis_krb_ktfile,
    send_umb_msg=False,
    umb_urls=[],
    umb_cert=None,
    umb_client_key=None,
    umb_ca_cert=None,
    umb_topic="VirtualTopic.eng.pub.quay_remove_images",
):
    """
    Remove quay images. All tags referencing a given image will be removed.

    The purpose of this entrypoint is to get image to the state where it will be garbage
    collected in the future (no tag references it). V2S2 manifests and manifest lists will be
    treated as separate categories. In other words, partial ML removal is not supported, and
    single-arch images will not be  removed if also a part of multiarch image.

    Args:
        reference (str):
            Images specified by tags to remove. Comma separated values.
        quay_api_token (str):
            OAuth token for authentication of Quay REST API.
        quay_user (str):
            Quay username for Docker HTTP API.
        quay_password (str):
            Quay password for Docker HTTP API.
        pyxis_server (str):
            Pyxis service hostname:
        pyxis_krb_principal (str):
            Pyxis kerberos principal in form: name@REALM.
        pyxis_krb_ktfile (str):
            Pyxis Kerberos client keytab.
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
    verify_remove_image_args(reference, send_umb_msg, umb_urls, umb_cert)
    quay_client = QuayClient(quay_user, quay_password)

    references_to_remove = []
    repo_images_mapping = group_images_by_repo(reference)

    for references in sorted(repo_images_mapping.values()):
        references_to_remove += get_repo_images_to_remove(references, quay_client)

    references_to_remove = sorted(list(set(references_to_remove)))

    sig_remover = SignatureRemover()
    sig_remover.set_quay_client(quay_client)
    for reference in references_to_remove:
        sig_remover.remove_tag_signatures(
            reference, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile
        )

    untag_images(
        references_to_remove,
        quay_api_token=quay_api_token,
        remove_last=True,
        quay_user=quay_user,
        quay_password=quay_password,
        send_umb_msg=True,
        umb_urls=umb_urls,
        umb_cert=umb_cert,
        umb_client_key=umb_client_key,
        umb_ca_cert=umb_ca_cert,
    )

    LOG.info("Images have been removed")
    if send_umb_msg:
        LOG.info("Sending a UMB message")
        props = {"removed_images": references_to_remove}
        send_umb_message(
            umb_urls,
            props,
            umb_cert,
            umb_topic,
            client_key=umb_client_key,
            ca_cert=umb_ca_cert,
        )


def remove_image_main(sysargs=None):
    """Entrypoint for removing images."""
    logging.basicConfig(level=logging.INFO)

    parser = setup_arg_parser(REMOVE_IMAGE_ARGS)
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"
    args = add_args_env_variables(args, REMOVE_IMAGE_ARGS)

    if not args.quay_password:
        raise ValueError("--quay-password must be specified")
    if not args.quay_api_token:
        raise ValueError("--quay-api-token must be specified")

    kwargs = construct_kwargs(args)
    remove_images(**kwargs)
