import logging

from .quay_client import QuayClient
from .quay_api_client import QuayApiClient

LOG = logging.getLogger("pubtools.quay")


class ImageUntagger:
    """Class containing logic for untagging images and deciding if they should be untagged."""

    def __init__(
        self,
        references,
        quay_api_token,
        remove_last=False,
        quay_user=None,
        quay_password=None,
        host=None,
    ):
        """
        Initialize.

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
            host (str):
                Custom Quay hostname (if required).
        """
        for reference in references:
            if "@" in reference:
                raise ValueError(
                    "Reference '{0}' must be specified via tag, not digest".format(reference)
                )

        if isinstance(host, str) and host[-1] == "/":
            host = host[:-1]
        self.host = host or "quay.io"

        self.references = references
        self.remove_last = remove_last

        if quay_user and quay_password:
            self._quay_client = QuayClient(quay_user, quay_password, self.host)
        else:
            self._quay_client = None
        self._quay_api_client = QuayApiClient(quay_api_token, self.host)

    def set_quay_client(self, quay_client):
        """
        Set client instance to be used for the HTTP API operations.

        Args:
            quay_client (QuayClient):
                Instance of QuayClient.
        """
        self._quay_client = quay_client

    def get_repository_tags_mapping(self):
        """
        Get a mapping of which tags would be removed from given repos based on provided refs.

        Returns ({str: [str]}):
            Mapping of repository->tags.
        """
        repo_tag_mapping = {}
        for reference in self.references:
            tag = reference.split(":")[-1]
            repo_path = reference.split(":")[0]
            # Take only last two parts of the url, which are namespace + repo
            repository = "/".join(repo_path.split("/")[-2:])
            repo_tag_mapping.setdefault(repository, []).append(tag)

        return repo_tag_mapping

    def construct_tag_digest_mappings(self, repository):
        """
        Create a mappings of tags->digests as well as digests->tags.

        Tags->digests mapping answers the question "Which digests does a given tag reference?".
        Digests->tags mapping answers the question "Which tags reference a given digest?".
        Tag may reference one digest (if image manifest), or multiple (if manifest list).

        Args:
            repository (str):
                Quay repository.

        Returns (({str: [str]}), ({str: [str]})):
            Tuple of dictionaries mapping tags->digests and digests->tags.
        """
        LOG.info("Gathering tags and digests of repository '{0}'".format(repository))
        tag_digest_mapping = {}
        digest_tag_mapping = {}
        image_schema = "{0}/{1}:{2}"
        repo_tags = self._quay_client.get_repository_tags(repository)

        for tag in repo_tags["tags"]:
            image = image_schema.format(self.host, repository, tag)
            manifest = self._quay_client.get_manifest(image)
            digest = self._quay_client.get_manifest_digest(image)

            # Option 1: No manifest list, only manifest
            if manifest["mediaType"] == QuayClient.MANIFEST_V2S2_TYPE:
                tag_digest_mapping[tag] = [digest]
                digest_tag_mapping.setdefault(digest, []).append(tag)

            # Option 2: We need to get digests of all architectures
            else:
                tag_digest_mapping[tag] = [digest]
                digest_tag_mapping.setdefault(digest, []).append(tag)

                for arch_manifest in manifest["manifests"]:
                    tag_digest_mapping[tag].append(arch_manifest["digest"])
                    digest_tag_mapping.setdefault(arch_manifest["digest"], []).append(tag)

        return (tag_digest_mapping, digest_tag_mapping)

    def get_lost_digests(self, tags, tag_digest_mapping, digest_tag_mapping):
        """
        Calculate a list of digests that would be lost if the provided tags were removed.

        Args:
            tags ([str]):
                List of tags that would be removed from a repo.
            tag_digest_mapping ({str: [str]}):
                Mapping of which digests are referenced by a given tag.
            digest_tag_mapping ({str: [str]}):
                Mapping of which tags reference a given digest.

        Returns ([str]):
            Digests that would be lost if given tags were removed.
        """
        remove_digests = []
        lost_digests = []
        for tag in tags:
            for digest in tag_digest_mapping.get(tag, []):
                if digest not in remove_digests:
                    remove_digests.append(digest)

        for digest in remove_digests:
            # which tags would remain referencing a given digest?
            remaining_tags = set(digest_tag_mapping[digest]) - set(tags)
            if len(remaining_tags) == 0:
                lost_digests.append(digest)

        return lost_digests

    def untag_images(self):
        """
        Determine if the specified tags may be removed and remove them.

        Returns ([str]):
            List of image references lost by the untagging.
        """
        if not self._quay_client:
            raise RuntimeError("QuayClient instance must be set")

        repo_tag_mapping = self.get_repository_tags_mapping()
        schema = "{0}/{1}@{2}"
        lost_imgs = []

        for repo in repo_tag_mapping:
            tag_digest_mapping, digest_tag_mapping = self.construct_tag_digest_mappings(repo)

            lost_digests = self.get_lost_digests(
                repo_tag_mapping[repo], tag_digest_mapping, digest_tag_mapping
            )
            if len(lost_digests) > 0:
                lost_imgs += [schema.format(self.host, repo, digest) for digest in lost_digests]

        if not self.remove_last and lost_imgs:
            raise ValueError(
                "Following images would no longer be referencable by tag after"
                " the untagging operation: '{0}'. Please specify --remove-last"
                " if this is not a concern.".format(lost_imgs)
            )

        if lost_imgs and self.remove_last:
            LOG.warning("Following images won't be referencable by tag: {0}".format(lost_imgs))
        if not lost_imgs:
            LOG.info("No images will be lost by this untagging operation")

        for reference in self.references:
            tag = reference.split(":")[-1]
            repo_path = reference.split(":")[0]
            # Take only last two parts of the url, which are namespace + repo
            repository = "/".join(repo_path.split("/")[-2:])
            LOG.info("Removing tag '{0}' from repository '{1}'".format(tag, repository))
            self._quay_api_client.delete_tag(repository, tag)

        return lost_imgs
