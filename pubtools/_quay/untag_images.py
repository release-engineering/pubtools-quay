import logging

from pubtools.pluggy import pm, task_context

from .image_untagger import ImageUntagger
from .utils.misc import setup_arg_parser, add_args_env_variables

LOG = logging.getLogger("pubtools.quay")

UNTAG_IMAGES_ARGS = {
    ("--reference",): {
        "help": "Image reference to untag. Must be specified by tag. Multiple can be specified.",
        "required": True,
        "type": str,
        "action": "append",
    },
    ("--remove-last",): {
        "help": "Whether to remove a tag even if it's the last reference of some image.",
        "required": False,
        "type": bool,
    },
    ("--quay-api-token",): {
        "help": "OAuth token for Quay REST API.",
        "required": False,
        "type": str,
        "env_variable": "QUAY_API_TOKEN",
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
    kwargs = args.__dict__

    # in args.__dict__ unspecified bool values have 'None' instead of 'False'
    for name, attributes in UNTAG_IMAGES_ARGS.items():
        if attributes["type"] is bool:
            bool_var = name[0].lstrip("-").replace("-", "_")
            if kwargs[bool_var] is None:
                kwargs[bool_var] = False

    # some exceptions have to be remapped
    kwargs["references"] = kwargs.pop("reference")

    return kwargs


def verify_untag_images_args(references, quay_user, quay_password):
    """
    Verify the presence and correctness of input parameters.

    Args:
        references ([str]):
            List of image references to untag.
        quay_user (str):
            Quay username for Docker HTTP API.
        quay_password (str):
            Quay password for Docker HTTP API.
    """
    for reference in references:
        if "@" in reference:
            raise ValueError("All references must be specified via tag, not digest")

    if (quay_user and not quay_password) or (quay_password and not quay_user):
        raise ValueError("Both user and password must be present when attempting to log in.")


def untag_images(
    references,
    quay_api_token,
    remove_last=False,
    quay_user=None,
    quay_password=None,
):
    """
    Untag images from Quay.

    Args:
        references ([str]):
            List of image references to untag.
        quay_api_token (str):
            OAuth token for authentication of Quay REST API.
        remove_last (bool):
            Whether to remove a tag when it's the last reference of an image (in that repo).
        quay_user (str):
            Quay username for Docker HTTP API.
        quay_password (str):
            Quay password for Docker HTTP API.
    """
    verify_untag_images_args(references, quay_user, quay_password)

    LOG.info("Started untagging operation with the following references: {0}".format(references))
    untagger = ImageUntagger(references, quay_api_token, remove_last, quay_user, quay_password)
    lost_images = untagger.untag_images()

    LOG.info("Untagging operation succeeded")
    pm.hook.quay_images_untagged(untag_refs=sorted(references), lost_refs=sorted(lost_images))


def setup_args():
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(UNTAG_IMAGES_ARGS)


def untag_images_main(sysargs=None):
    """Entrypoint for untagging images."""
    logging.basicConfig(level=logging.INFO)

    parser = setup_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"
    args = add_args_env_variables(args, UNTAG_IMAGES_ARGS)

    if not args.quay_api_token:
        raise ValueError("--quay-api-token must be specified")

    kwargs = construct_kwargs(args)

    with task_context():
        untag_images(**kwargs)
