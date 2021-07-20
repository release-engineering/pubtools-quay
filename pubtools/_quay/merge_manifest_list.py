import logging

from pubtools.pluggy import task_context

from .utils.misc import setup_arg_parser, add_args_env_variables
from .manifest_list_merger import ManifestListMerger

LOG = logging.getLogger("pubtools.quay")

MERGE_MANIFEST_LIST_ARGS = {
    ("--source-ref",): {
        "help": "Source image reference. Manifest list data of this image will "
        "overwrite destination's manifest list",
        "required": True,
        "type": str,
    },
    ("--dest-ref",): {
        "help": "Destination image reference. Must be specified by tag. New manifest list will be "
        "uploaded to this image reference.",
        "required": True,
        "type": str,
    },
    ("--source-quay-user",): {
        "help": "Quay username to get source image.",
        "required": True,
        "type": str,
    },
    ("--source-quay-password",): {
        "help": "Quay password to get source image. "
        "Can be specified by env variable SOURCE_QUAY_PASSWORD.",
        "required": False,
        "type": str,
        "env_variable": "SOURCE_QUAY_PASSWORD",
    },
    ("--dest-quay-user",): {
        "help": "Quay username to get dest image.",
        "required": True,
        "type": str,
    },
    ("--dest-quay-password",): {
        "help": "Quay password to get dest image. "
        "Can be specified by env variable DEST_QUAY_PASSWORD.",
        "required": False,
        "type": str,
        "env_variable": "DEST_QUAY_PASSWORD",
    },
}


def verify_merge_manifest_list_args(args):
    """Verify the presence and correctness of input parameters."""
    if "@" in args.dest_ref:
        raise ValueError("Destination must be specified via tag, not digest")

    if not args.source_quay_password or not args.dest_quay_password:
        raise ValueError("Quay password must be set for both source and dest images")


def setup_args():
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(MERGE_MANIFEST_LIST_ARGS)


def merge_manifest_list_main(sysargs=None):
    """Entrypoint for manifest list merging."""
    logging.basicConfig(level=logging.INFO)

    parser = setup_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"
    args = add_args_env_variables(args, MERGE_MANIFEST_LIST_ARGS)

    verify_merge_manifest_list_args(args)
    merger = ManifestListMerger(
        args.source_ref,
        args.dest_ref,
        args.source_quay_user,
        args.source_quay_password,
        args.dest_quay_user,
        args.dest_quay_password,
    )

    with task_context():
        merger.merge_manifest_lists()
