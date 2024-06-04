import logging
from typing import Optional

import requests

from .quay_session import QuaySession

LOG = logging.getLogger("pubtools.quay")


class QuayApiClient:
    """Class for performing Quay REST API queries."""

    def __init__(self, token: str, host: Optional[str] = None) -> None:
        """
        Initialize.

        Args:
            token (str):
                Quay API token for authentication.
            host (str):
                Quay registry URL.
        """
        self.token = token
        self.session = QuaySession(hostname=host, api="quay")
        self.session.set_auth_token(self.token)

    def delete_tag(self, repository: str, tag: str) -> requests.Response:
        """
        Delete a tag from a repository.

        Args:
            repository (str):
                Repository in which the tag resides.
            tag (str):
                Tag to get its referenced images from.

        Returns (Response):
            Request library's Response object.
        """
        endpoint = "repository/{0}/tag/{1}".format(repository, tag)
        response = self.session.delete(endpoint)

        # Tag not existing is a tolerable error
        if response.status_code == 404:
            LOG.warning("Tag '{0}' already doesn't exist in repo '{1}'".format(tag, repository))
        else:
            response.raise_for_status()
        return response

    def delete_repository(self, repository: str) -> requests.Response:
        """
        Delete a Quay repository.

        Args:
            repository (str):
                Repository to remove.

        Returns (Response):
            Request library's Response object.
        """
        endpoint = "repository/{0}".format(repository)
        response = self.session.delete(endpoint)

        # API doesn't return 404 even if repo doesn't exist. Thus no exception needs to be made
        response.raise_for_status()
        return response
