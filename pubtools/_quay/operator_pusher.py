import logging
import re
import yaml

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from .container_image_pusher import ContainerImagePusher
from .utils.misc import run_entrypoint, get_internal_container_repo_name, log_step

LOG = logging.getLogger("pubtools.quay")


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
            target_settings (dict):
                Target settings.
        """
        self.push_items = push_items
        self.target_settings = target_settings

        self.quay_host = self.target_settings.get("quay_host", "quay.io").rstrip("/")
        self._version_items_mapping = {}

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

    @property
    def version_items_mapping(self):
        """
        Generate mapping of OCP version -> push_items.

        The mapping describes which operator bundles should be added to which index images.

        Returns ({str: [ContainerPushItem]})
            Mapping of OCP version -> Push items
        """
        if not self._version_items_mapping:
            ocp_versions_resolved = {}

            for item in self.push_items:
                ocp_versions = item.metadata["com.redhat.openshift.versions"]
                # we haven't yet encountered this pattern, contact Pyxis for resolution
                if ocp_versions not in ocp_versions_resolved:
                    ocp_versions_resolved[ocp_versions] = self.pyxis_get_ocp_versions(item)

                for version in ocp_versions_resolved[ocp_versions]:
                    self._version_items_mapping.setdefault(version, []).append(item)

        return self._version_items_mapping

    def get_deprecation_list(self, version):
        """
        Get bundles to be deprecated in the index image.

        Args:
            version: (str)
                version for which deprecation list will be fetched.

        Returns:
            list(str): list of bundles to be deprecated in the index image.
        """

        def _get_requests_session():
            session = requests.Session()
            retry = Retry(
                total=6,
                read=6,
                connect=6,
                backoff_factor=0.8,
                status_forcelist=(500, 502, 503, 504),
            )
            adapter = HTTPAdapter(max_retries=retry)
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            return session

        deprecation_list = []
        deprecation_list_url = "{0}/{1}.yml/raw?ref=master".format(
            self.target_settings["iib_deprecation_list_url"].rstrip("/"), version.replace(".", "_")
        )
        registry_url = self.target_settings["docker_settings"]["docker_reference_registry"][0]

        LOG.info("Getting the deprecation list for OCP version {0}".format(version))
        session = _get_requests_session()
        response = session.get(url=deprecation_list_url)
        if not response.ok:
            LOG.error(
                "Could not retrieve deprecation list after multiple attempts."
                " Status Code {0}".format(response.status_code)
            )
            response.raise_for_status()

        try:
            yaml_response = yaml.safe_load(response.text)
            if yaml_response:
                deprecation_list = [
                    "{0}/{1}".format(registry_url, bundle_path)
                    for pkg_deprecation_list in yaml_response.values()
                    for bundle_path in pkg_deprecation_list
                ]
        except Exception:
            LOG.error("Data in {0} is invalid".format(deprecation_list_url))
            raise

        LOG.info("Deprecation list retrieved successfully")
        return sorted(deprecation_list)

    @classmethod
    def pubtools_iib_get_common_args(cls, target_settings):
        """
        Create an argument list common for all pubtools-iib operations.

        Target settings are used to set the values of the arguments

        Args:
            target_settings (dict):
                Settings used for setting the value of pubtools-iib parameters.
        Returns (([str]), {str:str}):
            Tuple of arguments and environment variables to be used when calling pubtools-iib.
        """
        args = ["--skip-pulp"]

        args += ["--iib-server", target_settings["iib_server"]]
        args += ["--iib-krb-principal", target_settings["iib_krb_principal"]]

        if "iib_overwrite_from_index" in target_settings:
            args += ["--overwrite-from-index"]
        if "iib_krb_ktfile" in target_settings:
            args += ["--iib-krb-ktfile", target_settings["iib_krb_ktfile"]]

        env_vars = {}
        if "iib_overwrite_from_index_token" in target_settings:
            env_vars["OVERWRITE_FROM_INDEX_TOKEN"] = target_settings[
                "iib_overwrite_from_index_token"
            ]

        return (args, env_vars)

    @classmethod
    def iib_add_bundles(
        cls, bundles=None, archs=None, index_image=None, deprecation_list=None, target_settings={}
    ):
        """
        Construct and execute pubtools-iib command to add bundles to index image.

        Args:
            bundles ([str]):
                External URLs to bundle images to be added to the index image.
            archs ([str]):
                Architectures to build for.
            index_image (str):
                Index image to add the bundles to.
            deprecation_list ([str]|str):
                List of bundles to be deprecated. Accepts both str (csv) and a list.
            target_settings (dict):
                Settings used for setting the value of pubtools-iib parameters.

        Returns (dict):
            Build details provided by IIB.
        """
        LOG.info(
            "Requesting IIB to add bundles '{0}' to index image '{1}'".format(bundles, index_image)
        )
        args, env_vars = cls.pubtools_iib_get_common_args(target_settings)

        if index_image:
            args += ["--index-image", index_image]
        if bundles:
            for bundle in bundles:
                args += ["--bundle", bundle]
        if archs:
            for arch in archs:
                args += ["--arch", arch]
        # inconsistent way of presenting multiple arguments...
        if deprecation_list and isinstance(deprecation_list, str):
            args += ["--deprecation-list", deprecation_list]
        elif deprecation_list and isinstance(deprecation_list, list):
            args += ["--deprecation-list", ",".join(deprecation_list)]

        return run_entrypoint(
            ("pubtools-iib", "console_scripts", "pubtools-iib-add-bundles"),
            "pubtools-iib-add-bundles",
            args,
            env_vars,
        )

    @classmethod
    def iib_remove_operators(cls, operators=None, archs=None, index_image=None, target_settings={}):
        """
        Construct and execute pubtools-iib command to remove operators from index image.

        Args:
            operators ([str]):
                Operator names to be removed from the index image.
            archs ([str]):
                Architectures to build for.
            ocp_version (str):
                Index image to remove the operators from.
            target_settings (dict):
                Settings used for setting the value of pubtools-iib parameters.

        Returns (dict):
            Build details provided by IIB.
        """
        LOG.info(
            "Requesting IIB to remove operators '{0}' from index image '{1}'".format(
                operators, index_image
            )
        )
        args, env_vars = cls.pubtools_iib_get_common_args(target_settings)

        if index_image:
            args += ["--index-image", index_image]
        if operators:
            for operator in operators:
                args += ["--operator", operator]
        if archs:
            for arch in archs:
                args += ["--arch", arch]

        return run_entrypoint(
            ("pubtools-iib", "console_scripts", "pubtools-iib-remove-operators"),
            "pubtools-iib-remove-operators",
            args,
            env_vars,
        )

    def get_existing_index_images(self, quay_client):
        """
        Return existing index images for push items.

        Args:
            quay_client (QuayClient): quay_client_instance

        Returns [(digest, tag)]:
            List of tuples containing digest and tag of existing index image
        """
        image_schema = "{host}/{namespace}/{repo}"
        iib_repo = get_internal_container_repo_name(
            self.target_settings["quay_operator_repository"]
        )
        index_image_repo = image_schema.format(
            host=self.quay_host, namespace=self.target_settings["quay_namespace"], repo=iib_repo
        )
        current_index_images = []

        manifest_list = {}
        for version in sorted(self.version_items_mapping.keys()):
            image_ref = "{0}:{1}".format(index_image_repo, version)
            try:
                manifest_list = quay_client.get_manifest(image_ref, manifest_list=True)
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404 or e.response.status_code == 401:
                    continue
                else:
                    raise
            for manifest in manifest_list["manifests"]:
                current_index_images.append(
                    (manifest["digest"], version, self.target_settings["quay_operator_repository"])
                )
        return list(set(current_index_images))

    @log_step("Build index images")
    def build_index_images(self):
        """
        Perform the 'build' part of the operator workflow.

        This workflow is a part of push-docker operation.
        The workflow can be summarized as:
        - Use Pyxis to parse 'com.redhat.openshift.versions'
        - Get deprecation list for a given version (list of bundles to be deprecated)
        - Create mapping of which bundles should be pushed to which index image versions
        - Contact IIB to add the bundles to the index images

        Returns ({str:dict}):
            Dictionary containing IIB results and signing keys for all OPM versions. Data will be
            used in operator signing. Dictionary structure:
            {
                "version": {
                    "iib_result": (...) (object returned by iiblib)
                    "signing_keys": [...] (list of signing keys to be used for signing)
                }
            }

        """
        iib_results = {}

        for version, items in sorted(self.version_items_mapping.items()):
            bundles = [self.public_bundle_ref(i) for i in items]
            all_archs = [
                i.metadata["arch"] if i.metadata["arch"] != "x86_64" else "amd64" for i in items
            ]
            archs = sorted(list(set(all_archs)))
            signing_keys = sorted(list(set([item.claims_signing_key for item in items])))

            # Get deprecation list
            deprecation_list = self.get_deprecation_list(version)

            # build index image in IIB
            index_image = "{image_repo}:{tag}".format(
                image_repo=self.target_settings["iib_index_image"], tag=version
            )
            build_details = self.iib_add_bundles(
                bundles=bundles,
                archs=archs,
                index_image=index_image,
                deprecation_list=deprecation_list,
                target_settings=self.target_settings,
            )

            iib_results[version] = {"iib_result": build_details, "signing_keys": signing_keys}

        return iib_results

    @log_step("Push index images to Quay")
    def push_index_images(self, iib_results):
        """
        Push index images which were built in the previous stage to Quay.

        Args:
            iib_results (dict):
                IIB results returned by the build stage
        """
        image_schema = "{host}/{namespace}/{repo}"
        index_image_repo = image_schema.format(
            host=self.quay_host,
            namespace=self.target_settings["quay_namespace"],
            repo=get_internal_container_repo_name(self.target_settings["quay_operator_repository"]),
        )

        for version in self.version_items_mapping:
            build_details = iib_results[version]["iib_result"]

            _, tag = build_details.index_image.split(":", 1)
            dest_image = "{0}:{1}".format(index_image_repo, tag)
            ContainerImagePusher.run_tag_images(
                build_details.index_image, [dest_image], True, self.target_settings
            )
