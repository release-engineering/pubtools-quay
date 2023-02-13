import functools
import logging
import re
import yaml

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

from .container_image_pusher import ContainerImagePusher
from .utils.misc import (
    run_entrypoint,
    get_internal_container_repo_name,
    log_step,
    get_pyxis_ssl_paths,
    run_with_retries,
    get_basic_auth,
)
from .quay_client import QuayClient
from .utils.misc import parse_index_image, pyxis_get_repo_metadata

LOG = logging.getLogger("pubtools.quay")


class OperatorPusher:
    """
    Add operator bundles to index images and push them to Quay.

    No validation is performed, push items are expected to be correct.
    """

    def __init__(self, push_items, task_id, target_settings):
        """
        Initialize.

        Args:
            push_items ([ContainerPushItem]):
                List of push items.
            task_id (str):
                task id
            target_settings (dict):
                Target settings.
        """
        self.push_items = push_items
        self.target_settings = target_settings
        self.task_id = task_id

        self.quay_host = self.target_settings.get("quay_host", "quay.io").rstrip("/")
        self._version_items_mapping = {}
        self.ocp_versions_resolved = {}

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
        cert, key = get_pyxis_ssl_paths(self.target_settings)

        ocp_versions = push_item.metadata["com.redhat.openshift.versions"]
        LOG.info("Getting OCP versions of '{0}' from Pyxis.".format(ocp_versions))

        args = ["--pyxis-server", self.target_settings["pyxis_server"]]
        args += ["--pyxis-ssl-crtfile", cert]
        args += ["--pyxis-ssl-keyfile", key]
        args += ["--organization", self.target_settings["iib_organization"]]
        args += ["--ocp-versions-range", ocp_versions]
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
            for item in self.push_items:
                ocp_versions = item.metadata["com.redhat.openshift.versions"]
                # we haven't yet encountered this pattern, contact Pyxis for resolution

                if ocp_versions not in self.ocp_versions_resolved:
                    self.ocp_versions_resolved[ocp_versions] = self.pyxis_get_ocp_versions(item)

                for version in self.ocp_versions_resolved[ocp_versions]:
                    self._version_items_mapping.setdefault(version, []).append(item)

        return self._version_items_mapping

    def get_deprecation_list(self, version):
        """
        Get bundles to be deprecated in the index image.

        If deprecation list URL isn't in the target settings, None is returned.

        Args:
            version: (str)
                version for which deprecation list will be fetched.

        Returns:
            list(str)|None: list of bundles to be deprecated in the index image. or None if
                            deprecation list URL was not specified.
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

        if not self.target_settings.get("iib_deprecation_list_url"):
            return None

        deprecation_list = []
        deprecation_list_url = "{0}/{1}.yml/raw?ref=master".format(
            self.target_settings["iib_deprecation_list_url"].rstrip("/"), version.replace(".", "_")
        )
        registry_url = self.target_settings["docker_settings"]["docker_reference_registry"][0]

        LOG.info("Getting the deprecation list for OCP version {0}".format(version))
        session = _get_requests_session()
        response = session.get(url=deprecation_list_url, timeout=10)
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

        if target_settings.get("iib_overwrite_from_index", False):
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
        cls,
        bundles=None,
        archs=None,
        index_image=None,
        deprecation_list=None,
        build_tags=None,
        target_settings={},
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
            build_tags ([str]):
                Extra tags that the new index image should be tagged with.
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
        if build_tags:
            for build_tag in build_tags:
                args += ["--build-tag", build_tag]

        try:
            return run_entrypoint(
                ("pubtools-iib", "console_scripts", "pubtools-iib-add-bundles"),
                "pubtools-iib-add-bundles",
                args,
                env_vars,
            )
        except SystemExit:
            return False

    @classmethod
    def iib_remove_operators(
        cls, operators=None, archs=None, index_image=None, build_tags=None, target_settings={}
    ):
        """
        Construct and execute pubtools-iib command to remove operators from index image.

        Args:
            operators ([str]):
                Operator names to be removed from the index image.
            archs ([str]):
                Architectures to build for.
            index_image (str):
                Index image to remove the operators from.
            build_tags ([str]):
                Extra tags that the new index image should be tagged with.
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
        if build_tags:
            for build_tag in build_tags:
                args += ["--build-tag", build_tag]

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
            host=self.quay_host,
            namespace=self.target_settings.get(
                "quay_operator_namespace", self.target_settings["quay_namespace"]
            ),
            repo=iib_repo,
        )
        current_index_images = []

        manifest_list = {}
        for version in sorted(self.version_items_mapping.keys()):
            image_ref = "{0}:{1}".format(index_image_repo, version)
            try:
                manifest_list = quay_client.get_manifest(
                    image_ref, media_type=QuayClient.MANIFEST_LIST_TYPE
                )
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

    @log_step("Verify bundles presence")
    def ensure_bundles_present(self):
        """
        Make sure bundles are present in Quay.

        Wait until pushed images become present in Quay,
        and return False if too much time has passed.
        """
        bundles = [self.public_bundle_ref(i) for i in self.push_items]
        for bundle in bundles:
            registry = bundle.split("/", 1)[0]
            username, password = get_basic_auth(registry)
            quay_client = QuayClient(username, password, registry)
            try:
                get_manifest_partial = functools.partial(quay_client.get_manifest, bundle)
                run_with_retries(
                    get_manifest_partial,
                    "Verify bundle presence",
                    self.target_settings.get("verify_bundle_tries", 5),
                    self.target_settings.get("verify_bundle_wait_time_increase", 20),
                )
            except Exception:
                LOG.error("Bundle {0} cannot be reached".format(bundle))
                return False
            LOG.info("Bundle {0} is present".format(bundle))
        return True

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
        repos_opted_in = {}
        items_opted_in = {}
        failed_items = {}

        # We need to load pyxis resolved versions at this point

        versions_mapping = self.version_items_mapping  # noqa: F841

        for item in self.push_items:
            for repo in item.metadata["tags"]:
                if repo not in repos_opted_in:
                    repos_opted_in[repo] = pyxis_get_repo_metadata(repo, self.target_settings).get(
                        "fbc_opt_in", False
                    )
            item_fbc_opt_in = [repos_opted_in[repo] for repo in item.metadata["tags"]]
            if not (all(item_fbc_opt_in) or not any(item_fbc_opt_in)):
                failed_items[id(item)] = True
                item.add_error("NOTPUSHED", "Inconsistent fbc opt in")
                LOG.error("Inconsistent fbc opt in for item {i}".format(i=item))
                continue
            elif all(item_fbc_opt_in):
                items_opted_in[id(item)] = True
            else:
                items_opted_in[id(item)] = False

            ocp_versions = item.metadata["com.redhat.openshift.versions"]
            if (
                [
                    version
                    for version in self.ocp_versions_resolved[ocp_versions]
                    if tuple([int(x) for x in version.replace("v", "").split(".")]) < (4, 13)
                ]
                and [
                    version
                    for version in self.ocp_versions_resolved[ocp_versions]
                    if tuple([int(x) for x in version.replace("v", "").split(".")]) > (4, 12)
                ]
                and items_opted_in[id(item)]
            ):
                item.add_error(
                    "INVALIDFILE",
                    "Cannot push item to index image "
                    "as it supports both <= 4.12 and >= 4.13 and is opted in FBC: {item}".format(
                        item=item
                    ),
                )
                LOG.error(
                    "Cannot push item to index image "
                    "as it supports both <= 4.12 and >= 4.13 and is opted in FBC: {item}".format(
                        item=item
                    )
                )
                failed_items[id(item)] = True

        for version, items in sorted(self.version_items_mapping.items()):
            non_fbc_items = []
            osev_tuple = tuple([int(x) for x in version.replace("v", "").split(".")])
            for item in items:
                if id(item) in failed_items:
                    continue
                if not items_opted_in[id(item)] or (
                    items_opted_in[id(item)] and osev_tuple <= (4, 12)
                ):
                    non_fbc_items.append(item)
                elif items_opted_in[id(item)] and osev_tuple >= (4, 13):
                    LOG.warning(
                        "Skipping {i}".format(i=item)
                        + "from iib build as it's opted in for FBC and targeting OCP version >=4.13"
                    )

            is_hotfix = any([item.metadata.get("com.redhat.hotfix") for item in non_fbc_items])
            is_advisory_source = all(
                [re.match(r"^[A-Z0-9:\-]{4,40}$", item.origin) for item in non_fbc_items]
            )
            item_groups = {}
            if is_hotfix and not is_advisory_source:
                raise ValueError("Cannot push hotfixes without an advisory")
            if is_hotfix:
                for item in non_fbc_items:
                    item_groups.setdefault(item.origin, []).append(item)
            else:
                item_groups["default"] = non_fbc_items

            # Get deprecation list
            deprecation_list = self.get_deprecation_list(version)

            for group, g_items in item_groups.items():
                if not g_items:
                    continue
                tag = version
                index_image = "{image_repo}:{tag}".format(
                    image_repo=self.target_settings["iib_index_image"], tag=tag
                )

                build_tags = ["{0}-{1}".format(index_image.split(":")[1], self.task_id)]
                if is_hotfix:
                    hotfix_tag = "{0}-{1}-{2}".format(
                        version,
                        g_items[0].metadata["com.redhat.hotfix"],
                        g_items[0].origin.split("-")[1].replace(":", "-"),
                    )
                    build_tags.append(hotfix_tag)

                bundles = [self.public_bundle_ref(i) for i in g_items]
                signing_keys = sorted(list(set([item.claims_signing_key for item in g_items])))

                # build index image in IIB
                if is_hotfix:
                    target_settings = self.target_settings.copy()
                    target_settings["iib_overwrite_from_index"] = False
                    target_settings["iib_overwrite_from_index_token"] = ""
                else:
                    target_settings = self.target_settings
                build_details = self.iib_add_bundles(
                    bundles=bundles,
                    index_image=index_image,
                    deprecation_list=deprecation_list,
                    build_tags=build_tags,
                    target_settings=target_settings,
                )
                iib_results[tag] = {
                    "iib_result": build_details,
                    "signing_keys": signing_keys,
                    "is_hotfix": is_hotfix,
                    "hotfix_tag": "" if not is_hotfix else hotfix_tag,
                }

        return iib_results

    @log_step("Push index images to Quay")
    def push_index_images(self, iib_results, tag_suffix=None):
        """
        Push index images which were built in the previous stage to Quay.

        Args:
            iib_results (dict):
                IIB results returned by the build stage
            tag_suffix (str):
                extra tag suffix applied to iib version tags if specified
        """
        image_schema = "{host}/{namespace}/{repo}"
        image_schema_tag = "{host}/{namespace}/{repo}:{tag}"
        index_image_repo = image_schema.format(
            host=self.quay_host,
            namespace=self.target_settings.get(
                "quay_operator_namespace", self.target_settings["quay_namespace"]
            ),
            repo=get_internal_container_repo_name(self.target_settings["quay_operator_repository"]),
        )

        for version, results in iib_results.items():
            build_details = results.get("iib_result", None)
            if not build_details:
                continue

            _, tag = build_details.index_image.split(":", 1)
            iib_feed, iib_namespace, iib_intermediate_repo = parse_index_image(build_details)
            permanent_index_image = image_schema_tag.format(
                host=iib_feed,
                namespace=iib_namespace,
                repo=iib_intermediate_repo,
                tag=build_details.build_tags[0],
            )
            if not results["is_hotfix"]:
                dest_image = "{0}:{1}".format(index_image_repo, tag)
            else:
                dest_image = "{0}:{1}".format(index_image_repo, results["hotfix_tag"])
            # We don't use permanent index image here because we always want to overwrite
            # production tags with the latest index image (in case of parallel pushes)
            index_image_ts = self.target_settings.copy()
            index_image_ts["dest_quay_user"] = index_image_ts.get(
                "index_image_quay_user", index_image_ts["dest_quay_user"]
            )
            index_image_ts["dest_quay_password"] = index_image_ts.get(
                "index_image_quay_password", index_image_ts["dest_quay_password"]
            )

            ContainerImagePusher.run_tag_images(
                build_details.index_image, [dest_image], True, index_image_ts
            )
            if tag_suffix:
                dest_image = "{0}:{1}-{2}".format(index_image_repo, tag, tag_suffix)
                ContainerImagePusher.run_tag_images(
                    permanent_index_image, [dest_image], True, index_image_ts
                )
