import abc
from contextlib import contextmanager
import logging
import pkg_resources
import tempfile
import json

from typing import Optional, List, Dict, Any, Tuple

from marshmallow import Schema, fields, EXCLUDE

from .utils.misc import (
    run_entrypoint,
    get_pyxis_ssl_paths,
)


LOG = logging.getLogger("pubtools.quay")


class SigningError(Exception):
    """Error raised when signing fails."""


class NoSchema(Schema):
    """Schema that does not validate anything."""


class SignerWrapper:
    """Wrapper providing functionality to sign containers with a generic signer."""

    SCHEMA = NoSchema
    entry_point_conf = ["signer", "group", "signer"]

    def __init__(self, config_file: Optional[str] = None, settings: Dict[str, Any] = None):
        """Initialize SignerWrapper."""
        self.config_file = config_file
        self.settings = settings
        self._ep = None
        self.validate_settings()

    @property
    def entry_point(self):
        """Load and return entry point for pubtools-sign project."""
        if self._ep is None:
            self._ep = pkg_resources.load_entry_point(*self.entry_point_conf)
        return self._ep

    def remove_signatures(self, signatures: List[str], _exclude: bool = None):
        """Remove signatures from a sigstore."""
        LOG.debug("Removing signatures %s", signatures)
        self._remove_signatures(signatures)

    @abc.abstractmethod
    def _run_remove_signatures(self, signatures_to_remove: List[str]):
        pass  # pragma: no cover

    def _remove_signatures(self, signatures_to_remove: List[str]):
        """Remove signatures from sigstore.

        This is helper to make testing easier.
        Args:
            signatures_to_remove (list): Signatures to remove.
        """
        self._run_remove_signatures(signatures_to_remove)

    @abc.abstractmethod
    def _run_store_signed(self, signatures: List[Dict[str, Any]]):
        pass  # pragma: no cover

    def _store_signed(self, signatures: List[Dict[str, Any]]):
        """Store signatures in sigstore.

        This is helper to make testing easier.
        Args:
            signatures (list): Signatures to store.
        """
        LOG.debug("Storing signatures %s", signatures)
        self._run_store_signed(signatures)

    def sign_container(
        self,
        reference: str,
        digest: str,
        signing_key: str,
        repo: Optional[str] = None,
        task_id: Optional[str] = None,
    ):
        """Sign a specific reference and digest with given signing key.

        Args:
            reference (str): Reference to container image to sign.
            digest (str): Digest of container image to sign.
            signing_key (str): Signing key to use.
            repo (str): Repository name of container image to sign.
            task_id (str): Task ID to identify the signing task if needed.
        """
        LOG.debug("Signing container %s %s %s", reference, digest, signing_key)
        opt_args = {k: v for k, v in [("task_id", task_id), ("repo", repo)] if v is not None}
        signed = self.entry_point(
            config_file=self.config_file,
            signing_key=signing_key,
            reference=reference,
            digest=digest,
            **opt_args,
        )
        if signed["signer_result"]["status"] != "ok":
            raise SigningError(signed["signer_result"]["error_message"])
        self._store_signed(signed)

    def validate_settings(self, settings: Dict[str, Any] = None):
        """Validate provided settings for the SignerWrapper."""
        settings = settings or self.settings
        if settings is None:
            raise ValueError("Settings must be provided")
        schema = self.SCHEMA(unknown=EXCLUDE)
        schema.load(settings)


class MsgSignerSettingsSchema(Schema):
    """Validation schema for messaging signer settings."""

    pyxis_server = fields.String(required=True)
    pyxis_ssl_crtfile = fields.String(required=True)
    pyxis_ssl_keyfile = fields.String(required=True)
    num_thread_pyxis = fields.Integer(required=False, default=7)


class MsgSignerWrapper(SignerWrapper):
    """Wrapper for messaging signer functionality."""

    label = "msg_signer"
    entry_point_conf = ["pubtools-sign", "modules", "pubtools-sign-msg-container-sign"]

    MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST = 50
    SCHEMA = MsgSignerSettingsSchema

    @contextmanager
    def _save_signatures_file(self, signatures: List[Dict[str, Any]]):
        """Save signatures to a temporary file and yield the file."""
        with tempfile.NamedTemporaryFile(
            mode="w", prefix="pubtools_quay_upload_signatures_"
        ) as signature_file:
            json.dump(signatures, signature_file)
            signature_file.flush()
            yield signature_file

    def _fetch_signatures(self, manifest_digests: List[str]):
        """Fetch signatures from sigstore.

        Args:
            manifest_digests (list): Manifest digests to fetch signatures for.
        Returns:
            List[Dict[str, Any]]: List of fetched signatures.
        """
        cert, key = get_pyxis_ssl_paths(self.settings)
        chunk_size = self.MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST
        manifest_digests = sorted(list(set(manifest_digests)))

        args = ["--pyxis-server", self.settings["pyxis_server"]]
        args += ["--pyxis-ssl-crtfile", cert]
        args += ["--pyxis-ssl-keyfile", key]
        args += ["--request-threads", str(self.settings.get("num_thread_pyxis", 7))]

        for chunk_start in range(0, len(manifest_digests), chunk_size):
            chunk = manifest_digests[chunk_start : chunk_start + chunk_size]  # noqa: E203

            args = ["--pyxis-server", self.settings["pyxis_server"]]
            args += ["--pyxis-ssl-crtfile", cert]
            args += ["--pyxis-ssl-keyfile", key]

            with tempfile.NamedTemporaryFile(
                mode="w", prefix="pubtools_quay_get_signatures_"
            ) as signature_fetch_file:
                if manifest_digests:
                    json.dump(chunk, signature_fetch_file)
                    signature_fetch_file.flush()
                    args += ["--manifest-digest", "@{0}".format(signature_fetch_file.name)]

                env_vars = {}
                chunk_results = run_entrypoint(
                    ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-signatures"),
                    "pubtools-pyxis-get-signatures",
                    args,
                    env_vars,
                )

            for result in chunk_results:
                yield result

    def _run_store_signed(self, signed_results: List[Dict[str, Any]]):
        """
        Upload signatures to Pyxis by using a pubtools-pyxis entrypoint.

        Data required for a Pyxis POST request:
        - manifest_digest
        - reference
        - repository
        - sig_key_id
        - signature_data

        Signatures are uploaded in batches.

        Args:
            claim_messages ([dict]):
                Signature claim messages constructed for the RADAS service.
            signature_messages ([dict]):
                Messages from RADAS containing image signatures.
        """
        LOG.info("Sending new signatures to Pyxis")

        signatures: List[Dict[str, Any]] = []
        for reference, op_res in zip(
            signed_results["operation"]["references"], signed_results["operation_results"]
        ):
            signatures.append(
                {
                    "manifest_digest": op_res[0]["msg"]["manifest_digest"],
                    "reference": reference,
                    "repository": op_res[0]["msg"]["repo"],
                    "sig_key_id": signed_results["signing_key"],
                    "signature_data": op_res[0]["msg"]["signed_claim"],
                }
            )

        for sig in signatures:
            LOG.debug(
                f"Uploading new signature. Reference: {sig['reference']}, "
                f"Repository: {sig['repository']}, "
                f"Digest: {sig['manifest_digest']}, "
                f"Key: {sig['sig_key_id']}"
            )

        cert, key = get_pyxis_ssl_paths(self.settings)

        args = ["--pyxis-server", self.settings["pyxis_server"]]
        args += ["--pyxis-ssl-crtfile", cert]
        args += ["--pyxis-ssl-keyfile", key]
        args += ["--request-threads", str(self.settings.get("num_thread_pyxis", 7))]

        with self._save_signatures_file(signatures) as signature_file:
            args += ["--signatures", "@{0}".format(signature_file.name)]
            LOG.info("Uploading {0} new signatures".format(len(signatures)))
            env_vars = {}
            run_entrypoint(
                ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-upload-signatures"),
                "pubtools-pyxis-upload-signature",
                args,
                env_vars,
            )

    def _run_remove_signatures(self, signatures_to_remove: List[str]):
        """Remove signatures from the sigstore.

        Args:
            signatures_to_remove (List[str]): List of signatures to remove.
        """
        cert, key = get_pyxis_ssl_paths(self.settings)
        args = []
        args = ["--pyxis-server", self.settings["pyxis_server"]]
        args += ["--pyxis-ssl-crtfile", cert]
        args += ["--pyxis-ssl-keyfile", key]
        args += ["--request-threads", str(self.settings.get("num_thread_pyxis", 7))]

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

    def _filter_to_remove(
        self,
        signatures: List[Tuple[str, str, str]],
        _exclude: Optional[List[Tuple[str, str, str]]] = None,
    ) -> List[str]:
        """Filter signatures to remove.

        Args:
            signatures (List[Tuple[str, str, str]]): List of (digest, tag, repository)
            tuples of signautres to remove.
            _exclude (Optional[List[Tuple[str, str, str]]]): List of  (digest, tag, repository)
            tuples of signautres to keep.
        """
        exclude = _exclude or []
        signatures_to_remove = list(self._fetch_signatures([x[0] for x in signatures]))
        sig_ids_to_remove = []
        for existing_signature in signatures_to_remove:
            if (
                existing_signature["manifest_digest"],
                existing_signature["reference"].split(":")[-1],
                existing_signature["repository"],
            ) in signatures and (
                existing_signature["manifest_digest"],
                existing_signature["reference"],
                existing_signature["repository"],
            ) not in exclude:
                sig_ids_to_remove.append(existing_signature["_id"])
                LOG.debug(
                    f"Removing signature. Reference: {existing_signature['reference']}, "
                    f"Repository: {existing_signature['repository']}, "
                    f"Digest: {existing_signature['manifest_digest']}, "
                    f"Key: {existing_signature['sig_key_id']}"
                )
        return sig_ids_to_remove

    def remove_signatures(
        self,
        signatures: List[Tuple[str, str, str]],
        _exclude: Optional[List[Tuple[str, str, str]]] = None,
    ):
        """Remove signatures from sigstore.

        Args:
            signatures (list): List of tuples containing (digest, reference, repository) of
            signatures to remove.
            exclude (Optional[List[Tuple[str, str, str]]]): List of  (digest, tag, repository)
            tuples of signautres to keep.
        """
        _signatures = list(signatures)
        to_remove = self._filter_to_remove(_signatures, _exclude=_exclude)
        self._remove_signatures(to_remove)


SIGNER_BY_LABEL = {
    wrapper.label: wrapper
    for name, wrapper in locals().items()
    if type(wrapper) is type and issubclass(wrapper, SignerWrapper) and wrapper != SignerWrapper
}