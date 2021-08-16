import base64
from datetime import datetime
import json
import logging
import uuid
import tempfile

import proton

from .exceptions import SigningError
from .utils.misc import run_entrypoint, log_step
from .quay_client import QuayClient
from .manifest_claims_handler import ManifestClaimsHandler

LOG = logging.getLogger("pubtools.quay")


class SignatureHandler:
    """Base class implementing operations common for container and operator signing."""

    MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST = 50
    DEFAULT_MAX_ITEMS_PER_UPLOAD_BATCH = 100

    def __init__(self, hub, task_id, target_settings, target_name):
        """
        Initialize.

        Args:
            hub (HubProxy):
                Instance of XMLRPC pub-hub proxy.
            task_id (str):
                ID of the pub task
            target_settings (dict):
                Target settings.
            target_name (str):
                Name of the target.
        """
        self.hub = hub
        self.task_id = task_id
        self.target_settings = target_settings
        self.target_name = target_name

        # Which URL hostnames will the destination images be accessible by to customers
        self.dest_registries = target_settings["docker_settings"]["docker_reference_registry"]
        self.dest_registries = (
            self.dest_registries
            if isinstance(self.dest_registries, list)
            else [self.dest_registries]
        )

        self.quay_host = self.target_settings.get("quay_host", "quay.io").rstrip("/")
        self._src_quay_client = None

    @property
    def src_quay_client(self):
        """Create and access QuayClient for source image."""
        if self._src_quay_client is None:
            self._src_quay_client = QuayClient(
                self.target_settings["source_quay_user"],
                self.target_settings["source_quay_password"],
                self.quay_host,
            )
        return self._src_quay_client

    @classmethod
    def create_manifest_claim_message(
        cls, destination_repo, signature_key, manifest_digest, docker_reference, image_name, task_id
    ):
        """
        Construct a manifest claim (image signature) as well as a message to send to RADAS.

        Constructed signature adheres to the following standard:
        https://github.com/containers/image/blob/master/docs/containers-signature.5.md

        Args:
            destination_repo (str):
                Internal destination repository to send to RADAS.
            signature_key (str):
                Signature key that will be sent to RADAS.
            manifest_digest (str):
                Digest referencing the signed image. Mandatory part of the image signature.
            docker_reference (str):
                Image reference which will be used by customers to pull the image. Mandatory part of
                the image signature.
            image_name (str):
                Name of the image to send to RADAS.
            task_id (str):
                ID of the pub task.
        """
        # container image signature
        manifest_claim = {
            "critical": {
                "type": "atomic container signature",
                "image": {"docker-manifest-digest": manifest_digest},
                "identity": {"docker-reference": docker_reference},
            },
            # NOTE: pub version is no longer written here. I hope that's OK
            "optional": {"creator": "Red Hat RCM Pub"},
        }

        message = {
            "sig_key_id": signature_key,
            # Python 2.6/3 compatibility workaround
            "claim_file": base64.b64encode(json.dumps(manifest_claim).encode("latin1")).decode(
                "latin1"
            ),
            "pub_task_id": task_id,
            "request_id": str(uuid.uuid4()),
            "manifest_digest": manifest_digest,
            "repo": destination_repo,
            "image_name": image_name,
            "docker_reference": docker_reference,
            "created": datetime.utcnow().isoformat() + "Z",
        }
        return message

    def get_tagged_image_digests(self, image_ref):
        """
        Get all digests referenced by a tagged image.

        There will only be one digest in case of single-arch image (source image), or multiple
        digests for a multi-arch image.

        Args:
            image_ref (str):
                Image reference URL. Must be specified via tag.

        Returns ([str]):
            List of manifest digests referenced by the tag.
        """
        digests = []

        manifest = self.src_quay_client.get_manifest(image_ref)
        # If V2S2 manifest, we only want its digest
        if manifest["mediaType"] == "application/vnd.docker.distribution.manifest.v2+json":
            digests.append(self.src_quay_client.get_manifest_digest(image_ref))
        # If manifest list, we want digests of all its arch images
        else:
            for arch_manifest in manifest["manifests"]:
                digests.append(arch_manifest["digest"])

        return digests

    def get_signatures_from_pyxis(self, manifest_digests=None):
        """
        Get existing signatures from Pyxis based on the specified criteria (currently only digests).

        NOTE: In the current implementation, only manifest digests are being used to search for
        existing signatures. Also, the search is performed in chunks, their size being limited by
        MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST.

        Args:
            manifest_digests ([str]|None):
                Digests for which to return signatures.

            Yields (dict):
                Existing signatures as returned by Pyxis based on specified criteria. The returned
                sturcture is an iterator to reduce memory requirements.
        """
        chunk_size = self.MAX_MANIFEST_DIGESTS_PER_SEARCH_REQUEST

        for chunk_start in range(0, len(manifest_digests), chunk_size):
            chunk = manifest_digests[chunk_start : chunk_start + chunk_size]  # noqa: E203

            args = [
                "--pyxis-server",
                self.target_settings["pyxis_server"],
                "--pyxis-krb-principal",
                self.target_settings["iib_krb_principal"],
            ]
            if "iib_krb_ktfile" in self.target_settings:
                args += ["--pyxis-krb-ktfile", self.target_settings["iib_krb_ktfile"]]

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

    def remove_duplicate_claim_messages(self, claim_messages):
        """
        Remove claim messages which could be considered 'duplicates', containing the same data.

        Args:
            claim_messages ([dict]):
                All created claim messages.

        Returns ([dict]):
            De-duplicated claim messages.
        """
        # dictionary key is a tuple of all parameters whose combination makes the message unique
        unique_message_mapping = {}
        for message in claim_messages:
            key = (
                message["sig_key_id"],
                message["claim_file"],
                message["pub_task_id"],
                message["manifest_digest"],
                message["repo"],
                message["image_name"],
                message["docker_reference"],
            )
            if key not in unique_message_mapping:
                unique_message_mapping[key] = message

        return list(unique_message_mapping.values())

    def filter_claim_messages(self, claim_messages):
        """
        Filter out the manifest claim messages which are already in the sigstore.

        Args:
            claim_messages ([dict]):
                Messages to be sent to RADAS.

        Returns ([dict]):
            Messages which don't yet exist in Pyxis.
        """
        LOG.info("Removing claim messages which already exist in Pyxis")
        digests = [message["manifest_digest"] for message in claim_messages]
        digests = sorted(list(set(digests)))

        existing_signatures = self.get_signatures_from_pyxis(manifest_digests=digests)

        signatures_by_key = {}
        for signature in existing_signatures:
            # combination of image reference, digest, and signature key makes a signature unique
            key = (signature["reference"], signature["manifest_digest"], signature["sig_key_id"])
            signatures_by_key[key] = signature

        filtered_claim_messages = []
        for message in claim_messages:
            key = (message["docker_reference"], message["manifest_digest"], message["sig_key_id"])
            # New signatures have switched to using long (16B) keys, while old signatures may still
            # contain short (8B) keys. If claim is matched with a shorter key format, it's
            # still considered a duplicate and shouldn't be uploaded again.
            old_key = None
            if len(message["sig_key_id"]) > 8:
                old_key = (
                    message["docker_reference"],
                    message["manifest_digest"],
                    message["sig_key_id"][-8:],
                )

            if key not in signatures_by_key and old_key not in signatures_by_key:
                filtered_claim_messages.append(message)

        LOG.info(
            "{0} claim messages remain after removing duplicates".format(
                len(filtered_claim_messages)
            )
        )
        return filtered_claim_messages

    def get_signatures_from_radas(self, claim_messages):
        """
        Send signature claims to RADAS via UMB and receive signed claims.

        The messaging logic is handled by the ManifestClaimsHandler class.

        Args:
            claim_messages ([dict]):
                Signature claims to be sent to RADAS.
        Returns ([dict]):
            Response messages from RADAS.
        raises MessageHandlerTimeoutException:
            If a message from RADAS hasn't arrived in time.
        """
        LOG.info("Sending claim messages to RADAS and waiting for results")
        # messages will be sent by pub-hub via XMLRPC
        # callback will be utilized by ManifestClaimsHandler, which will decide when to send msgs
        message_sender_callback = (
            lambda messages: self.hub.worker.umb_send_manifest_claim_messages(  # noqa: E731
                self.target_name, self.task_id, messages
            )
        )

        address = (
            "queue://Consumer.msg-producer-pub"
            ".{task_id}.VirtualTopic.eng.robosignatory.container.sign".format(task_id=self.task_id)
        )

        docker_settings = self.target_settings["docker_settings"]
        claims_handler = ManifestClaimsHandler(
            umb_urls=docker_settings["umb_urls"],
            radas_address=docker_settings.get("umb_radas_address", address),
            claim_messages=claim_messages,
            pub_cert=docker_settings.get("umb_pub_cert", "/etc/pub/umb-pub-cert-key.pem"),
            ca_cert=docker_settings.get("umb_ca_cert", "/etc/pki/tls/certs/ca-bundle.crt"),
            timeout=docker_settings.get("umb_signing_timeout", 600),
            throttle=docker_settings.get("umb_signing_throttle", 100),
            retry=docker_settings.get("umb_signing_retry", 3),
            message_sender_callback=message_sender_callback,
        )
        container = proton.reactor.Container(claims_handler)
        container.run()

        return claims_handler.received_messages

    def upload_signatures_to_pyxis(self, claim_mesages, signature_messages, max_items_per_batch):
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
            max_items_per_batch (int):
                Maximum number of items Pyxis allows to upload at once.
        """
        LOG.info("Sending new signatures to Pyxis")
        signature_batches = [[]]
        claim_messages_by_id = dict((m["request_id"], m) for m in claim_mesages)
        sorted_signature_messages = sorted(signature_messages, key=lambda msg: msg["request_id"])

        for signature_message in sorted_signature_messages:
            claim_message = claim_messages_by_id[signature_message["request_id"]]

            if len(signature_batches[-1]) >= max_items_per_batch:
                signature_batches.append([])
            batch = signature_batches[-1]

            batch.append(
                {
                    "manifest_digest": signature_message["manifest_digest"],
                    "reference": claim_message["docker_reference"],
                    "repository": claim_message["image_name"],
                    "sig_key_id": claim_message["sig_key_id"],
                    "signature_data": signature_message["signed_claim"],
                }
            )
        for i, batch in enumerate(signature_batches):
            args = [
                "--pyxis-server",
                self.target_settings["pyxis_server"],
                "--pyxis-krb-principal",
                self.target_settings["iib_krb_principal"],
            ]
            if "iib_krb_ktfile" in self.target_settings:
                args += ["--pyxis-krb-ktfile", self.target_settings["iib_krb_ktfile"]]

            with tempfile.NamedTemporaryFile(
                mode="w", prefix="pubtools_quay_upload_signatures_"
            ) as signature_batch_file:
                json.dump(batch, signature_batch_file)
                signature_batch_file.flush()
                args += ["--signatures", "@{0}".format(signature_batch_file.name)]

                LOG.info("Uploading signature batch #{0}/{1}".format(i + 1, len(signature_batches)))

                env_vars = {}
                run_entrypoint(
                    ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-upload-signatures"),
                    "pubtools-pyxis-upload-signature",
                    args,
                    env_vars,
                )

    def validate_radas_messages(self, claim_messages, signature_messages):
        """
        Check if messages received from RADAS contain any errors.

        Args:
            claim_messages ([dict]):
                Messages sent to RADAS.
            signature_messages ([dict]):
                Messages received from RADAS.

        Raises:
            SigningError:
                If RADAS messages contain errors.
        """
        failed_messages = 0
        for message in signature_messages:
            if message["errors"]:
                failed = [m for m in claim_messages if m["request_id"] == message["request_id"]][0]
                LOG.error(
                    "Signing of claim message {0} failed with following errors: {1}".format(
                        failed, message["errors"]
                    )
                )
                failed_messages += 1

        if failed_messages:
            raise SigningError(
                "Signing of {0}/{1} messages has failed".format(
                    failed_messages, len(claim_messages)
                )
            )


class ContainerSignatureHandler(SignatureHandler):
    """Class for handling the signing of container images."""

    def construct_item_claim_messages(self, push_item):
        """
        Construct all the signature claim messages for RADAS for one push item.

        push_item (ContainerPushItem):
            Container push item whose claim messages will be created.
        Returns ([dict]):
            Claim messages for a given push item.
        """
        LOG.info("Constructing claim messages for push item '{0}'".format(push_item))
        claim_messages = []

        if push_item.claims_signing_key:
            digests = self.get_tagged_image_digests(push_item.metadata["pull_url"])
            # each image digest needs its own signature
            for digest in digests:
                # each destination image reference needs its own signature
                for repo, tags in sorted(push_item.metadata["tags"].items()):
                    for tag in tags:
                        claim_messages += self.construct_variant_claim_messages(
                            repo, tag, digest, [push_item.claims_signing_key]
                        )

        return claim_messages

    def construct_variant_claim_messages(self, repo, tag, digest, signing_keys):
        """
        Construct claim messages for all specified variations of a given image.

        The variations are customer visible destination registry and signing key.

        Args:
            repo (str):
                Destination external repository  of a pushed image.
            tag: (str):
                Destination tag of a pushed image
            digest (str):
                Digest of the pushed image.
            signing_keys ([str]):
                Signing keys to construct the signatures with.

        Returns ([dict]):
            Signature claim messages to send to RADAS.
        """
        claim_messages = []
        image_schema = "{host}/{repository}:{tag}"

        for registry in self.dest_registries:
            reference = image_schema.format(host=registry, repository=repo, tag=tag)

            for signing_key in signing_keys:
                claim_message = self.create_manifest_claim_message(
                    destination_repo=repo,
                    signature_key=signing_key,
                    manifest_digest=digest,
                    docker_reference=reference,
                    image_name=repo,
                    task_id=self.task_id,
                )
                claim_messages.append(claim_message)

        return claim_messages

    @log_step("Sign container images")
    def sign_container_images(self, push_items):
        """
        Perform all the steps needed to sign the images of specified push items.

        The workflow can be summarized as:
        - create manifest claim messages for all items, registries, keys, digests, repos, and tags
        - filter out requests for signatures which are already in Pyxis
        - send messages to RADAS and receive signatures (ManifestClaimsHandler class)
        - Upload new signatures to Pyxis

        Args:
            push_items (([ContainerPushItem])):
                Container push items whose images will be signed.
        """
        if not self.target_settings["docker_settings"].get(
            "docker_container_signing_enabled", False
        ):
            LOG.info("Container signing not allowed in target settings, skipping.")
            return

        claim_messages = []
        for item in push_items:
            claim_messages += self.construct_item_claim_messages(item)
        claim_messages = self.remove_duplicate_claim_messages(claim_messages)
        claim_messages = self.filter_claim_messages(claim_messages)
        if not claim_messages:
            LOG.info("No new claim messages will be uploaded")
            return

        LOG.info("{0} claim messages will be uploaded".format(len(claim_messages)))
        signature_messages = self.get_signatures_from_radas(claim_messages)
        self.validate_radas_messages(claim_messages, signature_messages)
        self.upload_signatures_to_pyxis(
            claim_messages,
            signature_messages,
            self.target_settings.get(
                "sigstore_max_upload_items", self.DEFAULT_MAX_ITEMS_PER_UPLOAD_BATCH
            ),
        )


class OperatorSignatureHandler(SignatureHandler):
    """Class for handling the signing of index images."""

    def construct_index_image_claim_messages(self, index_image, tag, signing_keys):
        """
        Construct signature claim messages for RADAS for the specified index image.

        index_image (str):
            Reference to a new index image constructed by IIB.
        tag (str):
            Tag of the newly built index image.
        signing_keys (str):
            Signing keys to be used for signing.

        Returns ([dict]):
            Structured messages to be sent to UMB.
        """
        LOG.info("Constructing claim messages for index image '{0}'".format(index_image))
        claim_messages = []
        image_schema = "{host}/{repository}:{tag}"

        # Get digests of all archs this index image was build for
        index_image_credential = self.target_settings["iib_overwrite_from_index_token"].split(":")
        index_image_quay_client = QuayClient(
            index_image_credential[0],
            index_image_credential[1],
            self.quay_host,
        )
        manifest_list = index_image_quay_client.get_manifest(index_image, manifest_list=True)
        digests = [m["digest"] for m in manifest_list["manifests"]]
        for registry in self.dest_registries:
            for signing_key in signing_keys:
                if not signing_key:
                    continue
                for digest in digests:
                    repo = self.target_settings["quay_operator_repository"]
                    reference = image_schema.format(host=registry, repository=repo, tag=tag)
                    claim_message = self.create_manifest_claim_message(
                        destination_repo=repo,
                        signature_key=signing_key,
                        manifest_digest=digest,
                        docker_reference=reference,
                        image_name=repo,
                        task_id=self.task_id,
                    )
                    claim_messages.append(claim_message)

        return claim_messages

    @log_step("Sign operator images")
    def sign_operator_images(self, iib_results):
        """
        Perform all the steps needed to sign the newly constructed index images.

        Sigstore is not checked for existing signatures, as there's no way any could exist for a
        newly constructed image.

        Args:
            iib_results ({str:dict}):
                IIB results for each version the push was performed for.
        """
        image_schema = "{host}/{namespace}/{repo}@{digest}"
        if not self.target_settings["docker_settings"].get(
            "docker_container_signing_enabled", False
        ):
            LOG.info("Container signing not allowed in target settings, skipping.")
            return

        claim_messages = []
        for version, iib_details in sorted(iib_results.items()):
            iib_result = iib_details["iib_result"]
            signing_keys = iib_details["signing_keys"]
            # Using intermediate index image to ensure that it doesn't get overwritten
            iib_namespace = iib_result.index_image_resolved.split("/")[1]
            image_digest = iib_result.index_image_resolved.split("@")[1]
            intermediate_index_image = image_schema.format(
                host=self.target_settings.get("quay_host", "quay.io").rstrip("/"),
                namespace=iib_namespace,
                repo="iib",
                digest=image_digest,
            )
            # Version acts as a tag of the index image
            claim_messages += self.construct_index_image_claim_messages(
                intermediate_index_image, version, signing_keys
            )

        if not claim_messages:
            LOG.info("No new claim messages will be uploaded")
            return

        signature_messages = self.get_signatures_from_radas(claim_messages)
        self.validate_radas_messages(claim_messages, signature_messages)

        self.upload_signatures_to_pyxis(
            claim_messages,
            signature_messages,
            self.target_settings.get(
                "sigstore_max_upload_items", self.DEFAULT_MAX_ITEMS_PER_UPLOAD_BATCH
            ),
        )
        return claim_messages

    def sign_task_index_image(self, signing_keys, index_image, tag):
        """
        Perform an alternatve signing workflow used by IIB methods in pub.

        This workflow is used by methods 'PushAddIIBBundles', 'PushRemoveIIBOperators',
        'PushIIBBuildFromScratch'.

        Args:
            signing_keys ([str]):
                Signing key to be used.
            index_image (str):
                Index image pointing to the new manifest list.
            tag (str):
                Tag of the result index image.
        Returns ([dict]):
            Constructed claim messages.
        """
        claim_messages = self.construct_index_image_claim_messages(index_image, tag, signing_keys)
        if not claim_messages:
            LOG.info("No new claim messages will be uploaded")
            return

        signature_messages = self.get_signatures_from_radas(claim_messages)
        self.validate_radas_messages(claim_messages, signature_messages)

        self.upload_signatures_to_pyxis(
            claim_messages,
            signature_messages,
            self.target_settings.get(
                "sigstore_max_upload_items", self.DEFAULT_MAX_ITEMS_PER_UPLOAD_BATCH
            ),
        )

        return claim_messages


class BasicSignatureHandler(SignatureHandler):
    """Class that handles signing claims which were constructed by user."""

    def __init__(self, hub, target_settings, target_name):
        """
        Initialize.

        NOTE: "task_id" is not needed for this workflow

        Args:
            hub (HubProxy):
                Instance of XMLRPC pub-hub proxy.
            target_settings (dict):
                Target settings.
            target_name (str):
                Name of the target.
        """
        SignatureHandler.__init__(self, hub, "1", target_settings, target_name)

    def sign_claim_messages(self, claim_messages, remove_duplicates=True, filter_existing=True):
        """
        Sign claim messages that were provided by the user and upload them to Pyxis.

        Args:
            claim_messages ([dict]):
                Claim messages to be signed and uploaded.
            remove_duplicates (bool):
                Whether to check if there are any duplicates among the messages and remove them.
            filter_existing (bool):
                Whether to check if the signatures already exist in Pyxis, and only upload
                those that aren't.
        """
        if not self.target_settings["docker_settings"].get(
            "docker_container_signing_enabled", False
        ):
            LOG.info("Container signing not allowed in target settings, skipping.")
            return

        if remove_duplicates:
            claim_messages = self.remove_duplicate_claim_messages(claim_messages)
        if filter_existing:
            claim_messages = self.filter_claim_messages(claim_messages)
        if not claim_messages:
            LOG.info("No new claim messages will be uploaded")
            return

        LOG.info("{0} claim messages will be uploaded".format(len(claim_messages)))
        signature_messages = self.get_signatures_from_radas(claim_messages)
        self.validate_radas_messages(claim_messages, signature_messages)
        self.upload_signatures_to_pyxis(
            claim_messages,
            signature_messages,
            self.target_settings.get(
                "sigstore_max_upload_items", self.DEFAULT_MAX_ITEMS_PER_UPLOAD_BATCH
            ),
        )
