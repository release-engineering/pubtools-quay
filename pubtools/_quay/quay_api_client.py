import logging

from .quay_session import QuaySession

LOG = logging.getLogger()
LOG.setLevel(logging.INFO)


class QuayApiClient:
    """Class for performing Quay REST API queries."""

    def __init__(self, token, host=None):
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

    def get_repository_data(self, repository, raw=False):
        """
        Get repository data including its tags.

        Args:
            repository (str):
                Full repository path including the namespace.
            raw (bool):
                Whether to return the data as raw JSON.

        Returns (dict|str):
            Returned repository data.
        """
        endpoint = "repository/{0}".format(repository)
        kwargs = {"params": {"includeTags": True}}
        response = self.session.get(endpoint, **kwargs)
        response.raise_for_status()

        if raw:
            return response.text
        else:
            return response.json()

    def delete_tag(self, repository, tag):
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
        if "Invalid repository tag" not in response.text:
            response.raise_for_status()
        else:
            LOG.warning("Tag '{0}' already doesn't exist in repo '{1}'".format(tag, repository))

        return response
