import logging

from pubtools.pluggy import pm, task_context

from .signature_remover import SignatureRemover
from .quay_api_client import QuayApiClient
from .utils.misc import (
    setup_arg_parser,
    add_args_env_variables,
    get_internal_container_repo_name,
)

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
}


def remove_repositories(
    repositories,
    quay_org,
    quay_api_token,
    quay_user,
    quay_password,
    pyxis_server,
    pyxis_ssl_crtfile,
    pyxis_ssl_keyfile,
):
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
    """
    parsed_repositories = repositories.split(",")

    LOG.info("Removing repositories '{0}'".format(repositories))
    quay_api_client = QuayApiClient(quay_api_token)

    sig_remover = SignatureRemover(quay_user=quay_user, quay_password=quay_password)

    for repository in parsed_repositories:
        sig_remover.remove_repository_signatures(
            repository,
            quay_org,
            pyxis_server,
            pyxis_ssl_crtfile,
            pyxis_ssl_keyfile,
        )

        internal_repo = "{0}/{1}".format(quay_org, get_internal_container_repo_name(repository))
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
        remove_repositories(**kwargs)
