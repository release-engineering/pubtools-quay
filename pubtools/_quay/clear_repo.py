import logging

from pubtools.pluggy import task_context, pm

from .signature_remover import SignatureRemover
from .quay_client import QuayClient
from .untag_images import untag_images
from .utils.misc import (
    setup_arg_parser,
    add_args_env_variables,
    get_internal_container_repo_name,
)

LOG = logging.getLogger("pubtools.quay")

CLEAR_REPO_ARGS = {
    ("--repositories",): {
        "help": "External repositories to clear as CSV.",
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


def clear_repositories(
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
    Clear Quay repository.

    Args:
        repository (str):
            External repositories to clear. Comma separated values.
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

    LOG.info("Clearing repositories '{0}'".format(repositories))
    quay_client = QuayClient(quay_user, quay_password)

    sig_remover = SignatureRemover()
    sig_remover.set_quay_client(quay_client)

    refrences_to_remove = []
    for repository in parsed_repositories:
        sig_remover.remove_repository_signatures(
            repository,
            quay_org,
            pyxis_server,
            pyxis_ssl_crtfile,
            pyxis_ssl_keyfile,
        )

        internal_repo = "{0}/{1}".format(quay_org, get_internal_container_repo_name(repository))
        repo_data = quay_client.get_repository_tags(internal_repo)

        for tag in repo_data["tags"]:
            refrences_to_remove.append("{0}/{1}:{2}".format("quay.io", internal_repo, tag))

    untag_images(
        sorted(refrences_to_remove),
        quay_api_token,
        remove_last=True,
        quay_user=quay_user,
        quay_password=quay_password,
    )

    LOG.info("Repositories have been cleared")
    pm.hook.quay_repositories_cleared(repository_ids=sorted(parsed_repositories))


def setup_args():
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(CLEAR_REPO_ARGS)


def clear_repositories_main(sysargs=None):
    """Entrypoint for clearing repositories."""
    logging.basicConfig(level=logging.INFO)

    parser = setup_args()
    if sysargs:
        args = parser.parse_args(sysargs[1:])
    else:
        args = parser.parse_args()  # pragma: no cover"
    args = add_args_env_variables(args, CLEAR_REPO_ARGS)

    if not args.quay_api_token:
        raise ValueError("--quay-api-token must be specified")
    if not args.quay_password:
        raise ValueError("--quay-password must be specified")

    kwargs = args.__dict__

    with task_context():
        clear_repositories(**kwargs)
