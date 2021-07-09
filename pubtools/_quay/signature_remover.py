import logging
import json
import tempfile

import requests

from .utils.misc import (
    get_internal_container_repo_name,
    run_entrypoint,
    get_external_container_repo_name,
)
from .quay_client import QuayClient

LOG = logging.getLogger("pubtools.quay")


class SignatureRemover:
    """Class used for finding the signatures that should be removed and removing them."""

    MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST = 50

    def __init__(self, quay_api_token=None, quay_user=None, quay_password=None, quay_host=None):
        """
        Initialize.

        Args:
            quay_user (str):
                User name for Quay Docker registry API.
            quay_password (str):
                Password for Quay Docker registry API.
            quay_host (str):
                Quay base host URL. Defaults to 'quay.io'.
        """
        self.quay_host = quay_host.rstrip("/") if quay_host else "quay.io"
        self.quay_user = quay_user
        self.quay_password = quay_password

        self._quay_client = None

    @property
    def quay_client(self):
        """Create and access QuayClient."""
        if self._quay_client is None:
            if not self.quay_user or not self.quay_password:
                raise ValueError(
                    "No instance of QuayClient is available. Please provide "
                    "'quay_user' and 'quay_password' or set the instance via 'set_quay_client'"
                )

            self._quay_client = QuayClient(self.quay_user, self.quay_password, self.quay_host)
        return self._quay_client

    def set_quay_client(self, quay_client):
        """
        Set a QuayClient instance.

        Args:
            quay_client (QuayClient):
                QuayClient instance.
        """
        self._quay_client = quay_client

    def get_signatures_from_pyxis(
        self,
        manifest_digests,
        pyxis_server,
        pyxis_krb_principal,
        pyxis_krb_ktfile=None,
    ):
        """
        Get existing signatures from Pyxis based on the specified criteria (currently only digests).

        NOTE: In the current implementation, only manifest digests are being used to search for
        existing signatures. Also, the search is performed in chunks, their size being limited by
        MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST.

        NOTE: This method is copied from SignatureHandler, although it doesn't utilize
        'target_settings' in order to be more versatile.

        Args:
            manifest_digests ([str]):
                Digests for which to return signatures.
            pyxis_server (str):
                URL of the Pyxis service.
            pyxis_krb_principal (str):
                Kerberos principal to use for Pyxis authentication.
            pyxis_krb_ktfile (str|None):
                Path to Kerberos keytab file. Optional

            Yields (dict):
                Existing signatures as returned by Pyxis based on specified criteria. The returned
                sturcture is an iterator to reduce memory requirements.
        """
        chunk_size = self.MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST

        for chunk_start in range(0, len(manifest_digests), chunk_size):
            chunk = manifest_digests[chunk_start : chunk_start + chunk_size]  # noqa: E203

            args = [
                "--pyxis-server",
                pyxis_server,
                "--pyxis-krb-principal",
                pyxis_krb_principal,
            ]
            if pyxis_krb_ktfile:
                args += ["--pyxis-krb-ktfile", pyxis_krb_ktfile]
            if manifest_digests:
                args += ["--manifest-digest", ",".join(chunk)]

            env_vars = {}
            chunk_results = run_entrypoint(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
                "pubtools-pyxis-get-signatures",
                args,
                env_vars,
            )
            for result in chunk_results:
                yield result

    def remove_signatures_from_pyxis(
        self, signatures_to_remove, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile=None
    ):
        """
        Remove signatures from Pyxis by using a pubtools-pyxis entrypoint.

        Args:
            signatures_to_remove ([str]):
                List of signature ids to be removed.
            pyxis_server (str):
                URL of the Pyxis service.
            pyxis_krb_principal (str):
                Kerberos principal to use for Pyxis authentication.
            pyxis_krb_ktfile (str|None):
                Path to Kerberos keytab file. Optional
        """
        LOG.info("Removing outdated signatures from pyxis")

        args = [
            "--pyxis-server",
            pyxis_server,
            "--pyxis-krb-principal",
            pyxis_krb_principal,
        ]
        if pyxis_krb_ktfile:
            args += ["--pyxis-krb-ktfile", pyxis_krb_ktfile]
        with tempfile.NamedTemporaryFile(mode="w") as temp:
            json.dump(signatures_to_remove, temp)
            temp.flush()

            args += ["--ids", "@%s" % temp.name]

            env_vars = {}
            run_entrypoint(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-delete-signatures"),
                "pubtools-pyxis-delete-signatures",
                args,
                env_vars,
            )

    def get_repository_digests(self, repository):
        """
        Get all digests of all images in a given repository.

        NOTE: Digests of manifest lists are not returned, as signing is not performed on them.

        Args:
            repository (str):
                Full Quay repository, including namespace.
        Returns ([str]):
            Digests of all images in a given repo.
        """
        image_schema = "{host}/{repo}:{tag}"
        digests = []
        repo_tags = self.quay_client.get_repository_tags(repository)

        for tag in repo_tags["tags"]:
            image = image_schema.format(host=self.quay_host, repo=repository, tag=tag)
            manifest = self.quay_client.get_manifest(image)
            # if V2S2, we want to include its digest
            if manifest["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json":
                digests.append(self.quay_client.get_manifest_digest(image))
            else:
                for arch_manifest in manifest["manifests"]:
                    digests.append(arch_manifest["digest"])

        return sorted(list(set(digests)))

    def remove_repository_signatures(
        self, repository, namespace, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile=None
    ):
        """
        Remove all signatures of all images in a given Quay repository.

        Args:
            repository (str):
                External name for a repository whose signatures should be removed.
            namespace (str):
                Quay namespace in which the repository resides.
            pyxis_server (str):
                URL of the Pyxis service.
            pyxis_krb_principal (str):
                Kerberos principal to use for Pyxis authentication.
            pyxis_krb_ktfile (str|None):
                Path to Kerberos keytab file. Optional
        """
        LOG.info("Removing signatures of all images of repository '{0}'".format(repository))

        internal_repo = "{0}/{1}".format(namespace, get_internal_container_repo_name(repository))
        remove_signature_ids = []
        digests = self.get_repository_digests(internal_repo)

        for signature in self.get_signatures_from_pyxis(
            digests, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile
        ):
            if signature["repository"] == repository:
                remove_signature_ids.append(signature["_id"])

        if len(remove_signature_ids) > 0:
            LOG.info("{0} signatures will be removed".format(len(remove_signature_ids)))

            self.remove_signatures_from_pyxis(
                remove_signature_ids, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile
            )
        else:
            LOG.info("No signatures need to be removed")

    def remove_tag_signatures(
        self,
        reference,
        pyxis_server,
        pyxis_krb_principal,
        pyxis_krb_ktfile=None,
        exclude_by_claims=None,
        remove_archs=None,
    ):
        """
        Remove signatures of an image specified by a tag.

        Source and multiarch images are supported. Signatures may be excluded from removal by
        specifying a list of claim messages. If existing signature and a claim messages matches,
        it is not removed, as the same exact signature would be recreated afterwards. Additionally,
        it's also possible to only specify certain architectures whose signatures will be removed.
        This option only has an effect when the image is a manifest list.

        Args:
            reference (str):
                Image reference whose signatures are to be removed.
            pyxis_server (str):
                URL of the Pyxis service.
            pyxis_krb_principal (str):
                Kerberos principal to use for Pyxis authentication.
            pyxis_krb_ktfile (str|None):
                Path to Kerberos keytab file. Optional
            exclude_by_claims ([dict]|None):
                List of claim messages whose existing signature matches will not be removed.
            remove_archs ([str]|None):
                If specified and the reference is a multiarch image, only signatures of given
                architectures will be eligible for removal.
        """
        if "@" in reference:
            raise ValueError("Image, whose signatures are being removed must be specified by tag.")

        full_repo, tag = reference.split(":", 1)
        external_repo = get_external_container_repo_name(full_repo.split("/")[-1])
        image_digests = []

        repo_tags = self.quay_client.get_repository_tags(full_repo.split("/", 1)[-1])
        # if specified tag doesn't exist in a repo, no-op
        if tag not in repo_tags["tags"]:
            return

        manifest = self.quay_client.get_manifest(reference)
        # V2S2 image, we need only manifest digest
        if manifest["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json":
            image_digests.append(self.quay_client.get_manifest_digest(reference))
        # V2S2 image, we need digests of arch images
        else:
            for arch_manifest in manifest["manifests"]:
                if (
                    remove_archs is None
                    or arch_manifest["platform"]["architecture"] in remove_archs
                ):
                    image_digests.append(arch_manifest["digest"])

        new_claims_signatures = (
            list(set([(c["manifest_digest"], c["docker_reference"]) for c in exclude_by_claims]))
            if isinstance(exclude_by_claims, list)
            else []
        )

        remove_signature_ids = []
        for sig in self.get_signatures_from_pyxis(
            image_digests, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile
        ):
            # if signature corresponds to to-be-removed digest+reference and isn't among new sigs
            if (
                sig["manifest_digest"] in image_digests
                and sig["repository"] == external_repo
                and sig["reference"].split(":")[-1] == tag
                and (sig["manifest_digest"], sig["reference"]) not in new_claims_signatures
            ):
                remove_signature_ids.append(sig["_id"])

        if len(remove_signature_ids) > 0:
            LOG.info("{0} signatures will be removed".format(len(remove_signature_ids)))

            self.remove_signatures_from_pyxis(
                remove_signature_ids, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile
            )
        else:
            LOG.info("No signatures need to be removed")

    def get_index_image_signatures(
        self, image, claim_messages, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile=None
    ):
        """
        Get existing signatures of an index image.

        NOTE: Image is expected to be in an internal format.

        Args:
            image (str):
                Image, whose signatures should be gathered.
            claim_messages (str):
                Newly constructed claim messages used for excluding matching signatures. Although,
                digests should never match for a new index image, it's added just in case.
            pyxis_server (str):
                URL of the Pyxis service.
            pyxis_krb_principal (str):
                Kerberos principal to use for Pyxis authentication.
            pyxis_krb_ktfile (str|None):
                Path to Kerberos keytab file. Optional
        Returns ([dict]):
            Existing signatures of the index image.
        """
        if "@" in image:
            raise ValueError("Please specify the index image via tag")

        # We'll assume manifest list, since it's an index image
        try:
            manifest = self.quay_client.get_manifest(image, manifest_list=True)
        except requests.exceptions.HTTPError as e:
            # Perhaps destination index image doesn't exist, tolerate 404
            if e.response.status_code == 404 or e.response.status_code == 401:
                return []
            else:
                raise

        digests = [m["digest"] for m in manifest["manifests"]]
        matched_signatures = []
        repo, tag = image.split(":", 1)
        external_repo = get_external_container_repo_name(repo.split("/")[-1])
        claims_by_key = [
            (c["manifest_digest"], c["repo"], c["docker_reference"].split(":", 1)[-1])
            for c in claim_messages
        ]

        for signature in self.get_signatures_from_pyxis(
            digests, pyxis_server, pyxis_krb_principal, pyxis_krb_ktfile
        ):
            # if signature matches the old index image and isn't among new claims, it can be removed
            if (
                signature["manifest_digest"] in digests
                and signature["reference"].split(":", 1)[-1] == tag
                and signature["repository"] == external_repo
                and (
                    signature["manifest_digest"],
                    signature["repository"],
                    signature["reference"].split(":", 1)[-1],
                )
                not in claims_by_key
            ):
                matched_signatures.append(signature)

        return matched_signatures
