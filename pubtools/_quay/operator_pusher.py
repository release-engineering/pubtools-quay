import logging
import re

from .utils.misc import (
    run_entrypoint,
    get_internal_container_repo_name,
    log_step,
)

LOG = logging.getLogger("PubLogger")
logging.basicConfig()
LOG.setLevel(logging.INFO)


class OperatorPusher:
    """
    Add operator bundles to index images and push them to Quay.

    No validation is performed, push items are expected to be correct.
    """

    def __init__(self, push_items, target_settings):
        """
        Initialize.

        Args:
            push_items ([ContainerPushItem]):
                List of push items.
            target_name (str):
                target name
            target_settings (dict):
                Target settings.
        """
        self.push_items = push_items
        self.target_settings = target_settings

        self.quay_host = self.target_settings.get("quay_host", "quay.io").rstrip("/")

    @staticmethod
    def _get_immutable_tag(push_item):
        """
        Return immutable tag from operator push item production tags.

        Args:
            push_item (ContainerPushItem):
                Operator push item.

        Returns (str):
            Immutable tag
        """
        # NOTE: while this was copied from pub, '[0]' had to be added here to work properly
        if push_item.metadata["v_r"] in list(push_item.metadata["tags"].values())[0]:
            return push_item.metadata["v_r"]
        # if v_r tag is not in destination tags, return tag with the most numbers in it
        # This code is usually trigerred when push is not initiated from ET but manually
        # by user
        tags = []
        for tag in list(push_item.metadata["tags"].values())[0]:
            tags.append((len(re.split(r"\d+", tag)), tag))

        return sorted(tags)[-1][1]

    def public_bundle_ref(self, push_item):
        """
        Get public reference of a bundle image.

        It will be used by IIB to access the bundle image.

        Args:
            push_item (ContainerPushItem):
                Operator push item.

        Returns (str):
            Customer-visible bundle reference.
        """
        repository = list(push_item.metadata["tags"].keys())[0]
        # tags are the same for each destination repo, so any combination should work
        return "{0}/{1}:{2}".format(
            self.target_settings["docker_settings"]["docker_reference_registry"][0],
            repository,
            self._get_immutable_tag(push_item),
        )

    def pyxis_get_ocp_versions(self, push_item):
        """
        Get a list of supported ocp versions from Pyxis.

        Args:
            push_item: (ContainerPushItem)
                Push item for which the OCP version range will be found out.

        Returns ([str]):
            Supported OCP versions as returned by Pyxis.
        """
        ocp_versions = push_item.metadata["com.redhat.openshift.versions"]
        LOG.info("Getting OCP versions of '{0}' from Pyxis.".format(ocp_versions))

        args = ["--pyxis-server", self.target_settings["pyxis_server"]]
        args += ["--pyxis-krb-principal", self.target_settings["iib_krb_principal"]]
        args += ["--organization", self.target_settings["iib_organization"]]
        args += ["--ocp-versions-range", ocp_versions]
        if "iib_krb_ktfile" in self.target_settings:
            args += ["--pyxis-krb-ktfile", self.target_settings["iib_krb_ktfile"]]
        env_vars = {}

        data = run_entrypoint(
            ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-operator-indices"),
            "pubtools-pyxis-get-operator-indices",
            args,
            env_vars,
        )

        if not data:
            msg = "Pyxis has returned no OCP versions for '{0}' specified in build {1}.".format(
                ocp_versions, push_item.metadata["build"]["build_id"]
            )
            raise ValueError(msg)

        # Versions returned by Pyxis don't contain 'v' at the front (4.5 -> v4.5)
        return ["v{0}".format(item["ocp_version"]) for item in data]

    def generate_version_items_mapping(self):
        """
        Generate mapping of OCP version -> push_items.

        The mapping describes which operator bundles should be added to which index images.

        Returns ({str: [ContainerPushItem]})
            Mapping of OCP version -> Push items
        """
        version_items_mapping = {}
        ocp_versions_resolved = {}

        for item in self.push_items:
            ocp_versions = item.metadata["com.redhat.openshift.versions"]
            # we haven't yet encountered this pattern, contact Pyxis for resolution
            if ocp_versions not in ocp_versions_resolved:
                ocp_versions_resolved[ocp_versions] = self.pyxis_get_ocp_versions(item)

            for version in ocp_versions_resolved[ocp_versions]:
                version_items_mapping.setdefault(version, []).append(item)

        return version_items_mapping

    def iib_add_bundles(self, bundles, archs, ocp_version):
        """
        Construct and execute pubtools-iib command to add bundles to index image and push to Quay.

        Args:
            bundles ([str]):
                External URLs to bundle images to be added to the index image.
            archs ([str]):
                Architectures to build for.
            ocp_version (str):
                OCP version to add the bundles to. It acts as a tag of the index image.
        """
        LOG.info(
            "Requesting IIB to add bundles '{0}' to index image version '{1}'".format(
                bundles, ocp_version
            )
        )
        args = ["--skip-pulp"]

        image_schema = "{host}/{namespace}/{repo}"
        index_image_repo = image_schema.format(
            host=self.quay_host,
            namespace=self.target_settings["quay_namespace"],
            repo=get_internal_container_repo_name(self.target_settings["quay_operator_repository"]),
        )
        args += ["--quay-dest-repo", index_image_repo]

        args += ["--iib-server", self.target_settings["iib_server"]]
        args += ["--iib-krb-principal", self.target_settings["iib_krb_principal"]]
        args += ["--quay-user", self.target_settings["quay_user"]]
        args += ["--quay-send-umb-msg"]
        for umb_url in self.target_settings["docker_settings"]["umb_urls"]:
            args += ["--quay-umb-url", umb_url]
        args += [
            "--quay-umb-cert",
            self.target_settings["docker_settings"].get(
                "umb_pub_cert", "/etc/pub/umb-pub-cert-key.pem"
            ),
        ]
        args += [
            "--quay-umb-client-key",
            self.target_settings["docker_settings"].get(
                "umb_pub_cert", "/etc/pub/umb-pub-cert-key.pem"
            ),
        ]
        args += [
            "--quay-umb-ca-cert",
            self.target_settings["docker_settings"].get(
                "umb_ca_cert", "/etc/pki/tls/certs/ca-bundle.crt"
            ),
        ]
        if "iib_overwrite_from_index" in self.target_settings:
            args += ["--overwrite-from-index"]
        if "iib_krb_ktfile" in self.target_settings:
            args += ["--iib-krb-ktfile", self.target_settings["iib_krb_ktfile"]]

        index_image = "{image_repo}:{tag}".format(
            image_repo=self.target_settings["iib_index_image"], tag=ocp_version
        )
        args += ["--index-image", index_image]
        for bundle in bundles:
            args += ["--bundle", bundle]
        for arch in archs:
            args += ["--arch", arch]

        env_vars = {}
        env_vars["QUAY_PASSWORD"] = self.target_settings["quay_password"]
        if "iib_overwrite_from_index_token" in self.target_settings:
            env_vars["OVERWRITE_FROM_INDEX_TOKEN"] = self.target_settings[
                "iib_overwrite_from_index_token"
            ]

        run_entrypoint(
            ("pubtools-iib", "console_scripts", "pubtools-iib-add-bundles"),
            "pubtools-iib-add-bundles",
            args,
            env_vars,
        )

    @log_step("Push operators to Quay")
    def push_operators(self):
        """
        Perform the full workflow of pushing operators.

        The workflow can be summarized as:
        - Use Pyxis to parse 'com.redhat.openshift.versions'
        - Create mapping of which bundles should be pushed to which index image versions
        - Contact IIB to add the bundles to the index images
        - Push the newly constructed index image to Quay
        (last two steps performed by pubtools-iib)

        Returns ({str:dict}):
            Dictionary containing IIB results for all OPM versions. Data will be used in operator
            signing.
        """
        version_items_mapping = self.generate_version_items_mapping()
        iib_results = {}

        for version, items in sorted(version_items_mapping.items()):
            bundles = [self.public_bundle_ref(i) for i in items]
            all_archs = [
                i.metadata["arch"] if i.metadata["arch"] != "x86_64" else "amd64" for i in items
            ]
            archs = sorted(list(set(all_archs)))
            iib_results[version] = self.iib_add_bundles(bundles, archs, version)

        return iib_results
