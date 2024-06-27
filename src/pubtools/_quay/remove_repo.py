import os
import logging
import argparse
from typing import Any, Optional, List, Dict

from pubtools.pluggy import pm, task_context

from .quay_client import QuayClient
from .quay_api_client import QuayApiClient
from .utils.misc import (
    setup_arg_parser,
    add_args_env_variables,
    get_internal_container_repo_name,
)
from .item_processor import item_processor_for_internal_data, VirtualPushItem
from .signer_wrapper import SIGNER_BY_LABEL

LOG = logging.getLogger("pubtools.quay")

REMOVE_REPO_ARGS = {
    ("--repositories",): {
        "help": "External repositories to remove as CSV.",
        "required": True,
        "type": str,
    },
    ("--quay-host",): {
        "help": "quay host name",
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


def remove_repositories(repositories: str, settings: Dict[str, Any]) -> None:
    """
    Remove Quay repository.

    Args:
        repositories (str):
            External repositories to remove. Comma separated values.
        settings (dict):
            Settings dictionary with following keys:
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
    quay_client = QuayClient(settings["quay_user"], settings["quay_password"], "quay.io")
    item_processor = item_processor_for_internal_data(
        quay_client, "quay.io", [""], 5, settings["quay_org"]
    )
    item_processor.extractor.full_extract = True
    # Remove repository doesn't work with push item by default, therefore we create VirtualPushItem
    # to support existing code to generate needed repository data.
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

    signer_settings = {k: v for k, v in settings.items() if k not in ["quay_org"]}
    signer_settings["quay_namespace"] = settings["quay_org"]
    signer_settings["dest_quay_api_token"] = os.environ.get("QUAY_API_TOKEN")
    signer_settings["quay_host"] = "quay.io"

    for n, signer in enumerate(signers):
        signercls = SIGNER_BY_LABEL[signer]
        if not signercls.pre_push:
            continue
        signer = signercls(config_file=signer_configs[0], settings=signer_settings)
        signer.remove_signatures(outdated_manifests, _exclude=[])

    for repository in parsed_repositories:
        internal_repo = "{0}/{1}".format(
            settings["quay_org"], get_internal_container_repo_name(repository)
        )
        quay_api_client.delete_repository(internal_repo)

    LOG.info("Repositories have been removed")

    pm.hook.quay_repositories_removed(repository_ids=sorted(parsed_repositories))


def setup_args() -> argparse.ArgumentParser:
    """Set up argparser without extra parameters, this method is used for auto doc generation."""
    return setup_arg_parser(REMOVE_REPO_ARGS)


def remove_repositories_main(sysargs: Optional[List[str]] = None) -> None:
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
