import argparse
import logging
import os
from typing import Any, Dict, List, cast, Optional

from pubtools.pluggy import task_context, pm

from .quay_client import QuayClient
from .untag_images import untag_images
from .utils.misc import (
    setup_arg_parser,
    add_args_env_variables,
    get_internal_container_repo_name,
)
from .item_processor import (
    item_processor_for_internal_data,
    VirtualPushItem,
)
from .signer_wrapper import SIGNER_BY_LABEL

LOG = logging.getLogger("pubtools.quay")

CLEAR_REPO_ARGS = {
    ("--repositories",): {
        "help": "External repositories to clear as CSV.",
        "required": True,
        "type": str,
    },
    ("--quay-host",): {
        "help": "Quay host name",
        "required": False,
        "type": str,
        "default": "quay.io",
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
        "help": "Comma separated list of signers",
        "required": False,
        "type": str,
        "default": "",
    },
    ("--signer-configs",): {
        "help": "Comma separated list of paths to signer configs",
        "required": False,
        "type": str,
        "default": "",
    },
}


def clear_repositories(repositories: str, settings: Dict[str, Any]) -> None:
    """
    Clear Quay repository.

    Args:
        repository (str):
            External repositories to clear. Comma separated values.
        settings (dict):
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

    LOG.info("Clearing repositories '{0}'".format(repositories))
    quay_client = QuayClient(settings["quay_user"], settings["quay_password"])
    item_processor = item_processor_for_internal_data(
        quay_client, "quay.io", [""], 5, settings["quay_org"]
    )
    item_processor.extractor.full_extract = True

    signer_settings = {k: v for k, v in settings.items() if k not in ["quay_org"]}
    signer_settings["quay_namespace"] = settings["quay_org"]
    signer_settings["dest_quay_api_token"] = os.environ.get("QUAY_API_TOKEN")
    signer_settings["quay_host"] = "quay.io"

    # Clear repository doesn't work with pushitem so we need to create a virtual push item
    # to use existing code to generate needed data for clearing the repository
    item = VirtualPushItem(
        metadata={"tags": {repo: [] for repo in parsed_repositories}},
        repos={repo: [] for repo in parsed_repositories},
    )
    existing_manifests = item_processor.generate_all_existing_manifests_metadata(item)
    signers = settings["signers"].split(",")
    signer_configs = settings["signer_configs"].split(",")
    outdated_manifests = []
    for repo, tag, mad in existing_manifests:
        if not mad:
            continue
        outdated_manifests.append((mad.digest, tag, repo))

    for n, signer in enumerate(signers):
        signercls = SIGNER_BY_LABEL[signer]
        if not signercls.pre_push:
            continue
        _signer = signercls(config_file=signer_configs[n], settings=settings)
        _signer.remove_signatures(outdated_manifests, _exclude=[])

    refrences_to_remove = []
    for repository in parsed_repositories:
        internal_repo = "{0}/{1}".format(
            settings["quay_org"], get_internal_container_repo_name(repository)
        )
        repo_data = cast(Dict[str, List[str]], quay_client.get_repository_tags(internal_repo))

        for tag in repo_data["tags"]:
            refrences_to_remove.append("{0}/{1}:{2}".format("quay.io", internal_repo, tag))

    untag_images(
        sorted(refrences_to_remove),
        settings["quay_api_token"],
        remove_last=True,
        quay_user=settings["quay_user"],
        quay_password=settings["quay_password"],
    )

    LOG.info("Repositories have been cleared")
    pm.hook.quay_repositories_cleared(repository_ids=sorted(parsed_repositories))


def setup_args() -> argparse.ArgumentParser:
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(CLEAR_REPO_ARGS)


def clear_repositories_main(sysargs: Optional[List[str]] = None) -> None:
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
    repositories = kwargs.pop("repositories")

    with task_context():
        clear_repositories(repositories, kwargs)
