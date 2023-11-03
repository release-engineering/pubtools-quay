import logging

from pubtools.pluggy import pm, task_context

from .quay_client import QuayClient
from .quay_api_client import QuayApiClient
from .utils.misc import (
    setup_arg_parser,
    add_args_env_variables,
    get_internal_container_repo_name,
)
from .item_processor import (
    ItemProcesor,
    ReferenceProcessorInternal,
    ContentExtractor,
    VirtualPushItem,
)
from .signer_wrapper import SIGNER_BY_LABEL

LOG = logging.getLogger("pubtools.quay")

REMOVE_REPO_ARGS = {
    ("--repositories",): {
        "help": "External repositories to remove as CSV.",
        "required": True,
        "type": str,
    },
    ("--quay-org",): {
        "help": "Quay organization in which repositories reside.",
        "required": True,
        "type": str,
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
    ("--pyxis-ssl-crtfile",): {
        "help": "Path to .crt file for the SSL authentication",
        "required": True,
        "type": str,
    },
    ("--pyxis-ssl-keyfile",): {
        "help": "Path to .key file for the SSL authentication",
        "required": True,
        "type": str,
    },
    ("--pyxis-request-threads",): {
        "help": "Maximum number of threads to use for parallel pyxis request",
        "required": False,
        "default": 7,
        "type": int,
    },
    ("--signers",): {
        "help": "Comma separated list of signerrs",
        "required": False,
        "type": str,
        "default": "",
    },
    ("--signer-configs",): {
        "help": "Comma separated list of signerrs",
        "required": False,
        "type": str,
        "default": "",
    },
}


def remove_repositories(repositories, settings):
    """
    Remove Quay repository.

    Args:
        repositories (str):
            External repositories to remove. Comma separated values.
        quay_org (str):
            Quay organization in which repositories reside.
        quay_api_token (str):
            OAuth token for authentication of Quay REST API.
        quay_user (str):
            Quay username for Docker HTTP API.
        quay_password (str):
            Quay password for Docker HTTP API.
        pyxis_server (str):
            Pyxis service hostname:
        pyxis_ssl_crtfile (str):
            Path to .crt file for SSL authentication.
        pyxis_ssl_keyfile (str):
            Path to .key file for SSL authentication.
        pyxis_request_threads:
            Maximum number of threads to use for parallel pyxis request.
    """
    parsed_repositories = repositories.split(",")

    LOG.info("Removing repositories '{0}'".format(repositories))
    quay_api_client = QuayApiClient(settings["quay_api_token"])
    quay_client = QuayClient(settings["quay_user"], settings["quay_password"])

    extractor = ContentExtractor(quay_client=quay_client)
    reference_processor = ReferenceProcessorInternal(settings["quay_org"])
    item_processor = ItemProcesor(
        extractor=extractor,
        reference_processor=reference_processor,
        reference_registries=[],
        source_registry="quay.io",
    )
    item = VirtualPushItem(
        metadata={"tags": {repo: [] for repo in parsed_repositories}},
        repos={repo: [] for repo in parsed_repositories},
    )
    existing_tags = item_processor.generate_existing_tags(item)
    repo_tags_map = {}
    for _, repo, tag in existing_tags:
        repo_tags_map.setdefault(repo, []).append(tag)
    item2 = VirtualPushItem(
        metadata={"tags": {repo: repo_tags_map[repo]} for repo in parsed_repositories},
        repos={repo: [] for repo in parsed_repositories},
    )
    existing_manifests = item_processor.generate_existing_manifests(item2)
    signers = settings["signers"].split(",")
    signer_configs = settings["signer_configs"].split(",")
    outdated_manifests = []
    for repo, tag, mad in existing_manifests:
        outdated_manifests.append((mad.digest, tag, repo))

    for n, signer in enumerate(signers):
        signercls = SIGNER_BY_LABEL[signer]
        signer = signercls(config_file=signer_configs[0], settings=settings)
        signer.remove_signatures(outdated_manifests, _exclude=[])

    for repository in parsed_repositories:
        internal_repo = "{0}/{1}".format(
            settings["quay_org"], get_internal_container_repo_name(repository)
        )
        quay_api_client.delete_repository(internal_repo)

    LOG.info("Repositories have been removed")
    pm.hook.quay_repositories_removed(repository_ids=sorted(parsed_repositories))


def setup_args():
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(REMOVE_REPO_ARGS)


def remove_repositories_main(sysargs=None):
    """Entrypoint for removing repositories."""
    logging.basicConfig(level=logging.INFO)

    parser = setup_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"
    args = add_args_env_variables(args, REMOVE_REPO_ARGS)

    if not args.quay_api_token:
        raise ValueError("--quay-api-token must be specified")
    if not args.quay_password:
        raise ValueError("--quay-password must be specified")

    kwargs = args.__dict__

    with task_context():
        repositories = kwargs.pop("repositories")
        remove_repositories(repositories, kwargs)
