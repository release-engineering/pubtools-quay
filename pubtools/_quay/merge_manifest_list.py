import logging

from .utils.misc import setup_arg_parser, add_args_env_variables
from .manifest_list_merger import ManifestListMerger

LOG = logging.getLogger("PubLogger")
logging.basicConfig()
LOG.setLevel(logging.INFO)

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
}


def verify_merge_manifest_list_args(args):
    """Verify the presence and correctness of input parameters."""
    if "@" in args.dest_ref:
        raise ValueError("Destination must be specified via tag, not digest")

    if not args.quay_password:
        raise ValueError("Quay password must be set")


def merge_manifest_list_main(sysargs=None):
    """Entrypoint for manifest list merging."""
    parser = setup_arg_parser(MERGE_MANIFEST_LIST_ARGS)
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"
    args = add_args_env_variables(args, MERGE_MANIFEST_LIST_ARGS)

    verify_merge_manifest_list_args(args)
    merger = ManifestListMerger(args.source_ref, args.dest_ref, args.quay_user, args.quay_password)
    merger.merge_manifest_lists()
