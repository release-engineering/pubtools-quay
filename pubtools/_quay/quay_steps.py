from __future__ import print_function
import re
import six
import pkg_resources

from .utils.stepper import Step, StepFailedError
from .utils.logger import log_jsonl


LOG_INDENT = "  - "


class StepSanitizeContainerPushItems(Step):
    """Filter push items with error state or with empty file_path and ignore non docker items.

    Expected step args:
        ()
    Expected external resources:
        "log_debug": log debug callback or None
        "log_info": log info callback or None
        "log_warning": log warning callback or None
        "log_error": log error callback or None
        "push_items": list of push items
    Produced details:
        {"item": str "state": (ready, not-container, error, no-pull-data, ok)}
    Results:
        list of indexes of container push items in push_items list
    """

    NAME = "StepSanitizeContainerPushItems"

    def _init_details(self):
        push_items = self.external_resources["push_items"]
        self._details = []
        for item in push_items:
            self._details.append({"item": str(item), "state": "ready"})

    def _update_details(self, details):
        index, state = details
        self._details[index]["state"] = state

    @log_jsonl("SanitizeContainerPushItems")
    def _run(self, on_update=None):
        push_items = self.external_resources["push_items"]
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        log_warning = self.external_resources.get("log_warning", lambda *args, **kwargs: ())
        log_error = self.external_resources.get("log_error", lambda *args, **kwargs: ())

        container_push_items = []
        _on_update = on_update if on_update else lambda: ()
        failed = False
        for i, item in enumerate(push_items):
            log_info("Processing %s", str(item))
            item_error = False
            item_state = "ok"
            if item.file_type != "docker":
                log_warning(LOG_INDENT + "Item %s is not container, skipping" % str(item))
                self.update_details((i, "not-container"))
                _on_update()
                continue
            if item.file_path is None:
                item_state = "error"
                log_error(LOG_INDENT + "File path of %s is None" % str(item))
                self.results.errors.setdefault("item_errors", []).append(
                    (str(item), "empty file_path")
                )
                item_error = True
                failed = True
                if item.state is None:
                    item.state = "NOTPUSHED"
            if item.errors:
                item_state = "error"
                self.results.errors.setdefault("item_errors", []).append((str(item), item.errors))
                for message in item.errors.values():
                    log_error(LOG_INDENT + "Bad push item '%s': %s" % (item.file_name, message))
                item.state = "INVALIDFILE"
                item_error = True
                failed = True
            if not item.metadata.get("pull_data"):
                item_state = "no-pull-data"
                self.results.errors.setdefault("item_errors", []).append(
                    (str(item), "Cannot calculate pull data")
                )
                log_error(LOG_INDENT + "Missing pull_data for %s" % str(item))
                item_error = True
                failed = True
            if not item_error:
                log_info(LOG_INDENT + "Processing %s ok" % str(item))
            self.update_details((i, item_state))
            _on_update()

            container_push_items.append(i)
        if failed:
            raise StepFailedError()
        self.results.results = container_push_items


class StepSanitizeOperatorPushItems(Step):
    """Filter out push items which are not operators and store result.

    Expected step args:
        ()
    Expected step kw args:
        {"auto_upload_operators": <True|False>}
    Produced details:
        item -> {"item": str, "state": (ready, not-operator, unsupported-legacy,
                                        unknown-op-type, no-ocp-version, ok)}
    Expected external resources:
        "log_debug": log debug callback or None
        "log_info": log info callback or None
        "log_warning": log warning callback or None
        "log_error": log error callback or None
        "push_items": list of push items
    Results:
        list of indexes of container push items in push_items list
    """

    NAME = "StepSanitizeOperatorPushItems"

    def _init_details(self):
        push_items = self.external_resources["push_items"]
        self._details = []
        for item in push_items:
            self._details.append({"item": str(item), "state": "ready"})

    def _update_details(self, details):
        index, state = details
        self._details[index]["state"] = state

    def _pre_run(self):
        if not self.step_kwargs.get("auto_upload_operators", True):
            self.skip = True
            self.skip_reason = "Automatic uploading of operators is not enabled"

    @log_jsonl("SanitizeOperatorPushItems")
    def _run(self, on_update=None):
        push_items = self.external_resources["push_items"]
        log_debug = self.external_resources.get("log_debug", lambda *args, **kwargs: ())
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        log_error = self.external_resources.get("log_error", lambda *args, **kwargs: ())
        operator_push_items = []
        _on_update = on_update if on_update else lambda: ()
        errors = False
        for i, item in enumerate(push_items):
            log_debug("Processing %s", str(item))
            _on_update()
            if item.file_type != "operator":
                log_info(LOG_INDENT + "Item %s is not operator, skipping", str(item))
                item_state = "not-operator"
                self.update_details((i, item_state))
                on_update()
                continue

            item_state = "ok"
            op_type = item.metadata.get("op_type") or "appregistry"
            ocp_versions = item.metadata.get("com.redhat.openshift.versions")
            if op_type == "appregistry":
                item_state = "unsupported-legacy"
                log_info(
                    LOG_INDENT + "Item %s is unsupported legacy (appregistry), skipping",
                    str(item),
                )
            elif op_type != "bundle":
                item_state = "unknown-op-type"
                self.results.errors.setdefault("item_errors", []).append(
                    (str(item), "unknown operator type: %s" % op_type)
                )
                log_error(
                    LOG_INDENT + "Item %s has unknown operator type: %s",
                    op_type,
                    str(item),
                )
                errors = True
            elif not ocp_versions:
                item_state = "no-ocp-version"
                self.results.errors.setdefault("item_errors", []).append(
                    (
                        str(item),
                        "'com.redhat.openshift.versions' is not specified for build",
                    )
                )
                log_error(
                    LOG_INDENT + "Item %s is missing 'com.redhat.openshift.versions' label",
                    str(item),
                )
                errors = True
            if item_state == "ok":
                operator_push_items.append(i)
                log_debug(LOG_INDENT + "Processing %s ok", str(item))
            self.update_details((i, item_state))
            _on_update()
        if errors:
            raise StepFailedError()
        self.results.results = operator_push_items


class StepSanitizeRepositories(Step):
    """Sanitize destination repositories.

    Expected step args:
        (<key-for-container-items-indexes>,)
    Produced details:
        repository -> (ready, not-exists, depracated, ok)
    Expected external resources:
        "log_debug": log debug callback or None
        "log_info": log info callback or None
        "log_warning": log warning callback or None
        "log_error": log error callback or None
        "push_items": list of push items
    """

    NAME = "StepSanitizeRepositories"

    def _init_details(self):
        push_items = self.external_resources["push_items"]
        self._details = {}
        repositories = set()
        container_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[container_items_indexes_key].results
        for index in indexes:
            item = push_items[index]
            for repo in item.repos:
                repositories.add(repo)
        for repo in repositories:
            self._details[repo] = "ready"

    def _sanitize_repository(self, repo):
        raise NotImplementedError

    @log_jsonl("SanitizeOperatorPushItems")
    def _run(self, on_update=None):
        for repo in self._details.keys():
            self._sanitize_repository(repo)


class StepBuildBackupMapping(Step):
    """Build repo -> [backup tags] mapping repo -> [rollback tags].

    Expected step args:
        (<key-for-container-items-indexes>,)
    Produced details:
        {
            "backup_tags": { <repo>: { <tag>: <backup> }}
            "rollback_tags": { <repo>: {<tag>: <state>}}
        }
    Expected external resources:
        "log_debug": log debug callback or None
        "log_info": log info callback or None
        "log_warning": log warning callback or None
        "log_error": log error callback or None
        "push_items": list of push items
    Results:
        {
            "backup_tags": { <repo>: { <tag>: <backup> }}
            "rollback_tags": { <repo>: {<tag>: <state>}}
        }
    """

    NAME = "StepBuildBackupMapping"

    def _update_tag_backups(self, backup_tags):
        # TODO:
        # 1. get existing tags from quay and put them as backup
        # 2. put non-existing tags to rollback tags
        raise NotImplementedError

    def _init_details(self):
        push_items = self.external_resources["push_items"]
        container_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[container_items_indexes_key].results
        backup_tags = {}
        rollback_tags = {}
        self._details = {"backup_tags": backup_tags, "rollback_tags": rollback_tags}

        for index in indexes:
            item = push_items[index]
            for repo, tags in six.iteritems(item.metadata.get("tags", {})):
                for tag in tags:
                    backup_tags.setdefault(repo, {})[tag] = None
                    rollback_tags.setdefault(repo, {})[tag] = None

    def _update_details(self, details):
        backup_tags = details
        self._update_tag_backups(backup_tags)

    @log_jsonl("BuildBackupMapping")
    def _run(self, on_update=None):
        push_items = self.external_resources["push_items"]
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        container_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[container_items_indexes_key].results
        for index in indexes:
            item = push_items[index]
            for repo, tags in six.iteritems(item.metadata.get("tags", {})):
                log_info("Marking backup for %s" % str(item))
                self.update_details({"repo": repo, "tags": tags})
                on_update()
        self.results.results = self._details


class StepPushContainerImgs(Step):
    """Push Container items to destination.

    Expected step args:
        (container_items_indexes_key, target_settings)
    Expected shared results:
        <container_items_indexes_key>: [ list of indexes of container push items in push_items]
    Produced details:
        {
            "items": { <repo>: { <tag>: { "state" : <state>, "source": <source> } }}
        }
    Expected external resources:
        "log_debug": log debug callback or None
        "log_info": log info callback or None
        "log_warning": log warning callback or None
        "log_error": log error callback or None
        "push_items": list of push items
    Results:
        None
    """

    NAME = "StepPushContainerImgs"

    def _init_details(self):
        push_items = self.external_resources["push_items"]
        items = {}
        self._details = {"items": items}
        container_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[container_items_indexes_key].results
        for index in indexes:
            item = push_items[index]
            for repo, tags in six.iteritems(item.metadata.get("tags", {})):
                items[repo] = {}
                for tag in tags:
                    items[repo][tag] = {
                        "state": "ready",
                        "source": item.metadata["pull_data"],
                    }

    def _push_container_item(self, item):
        raise NotImplementedError

    @log_jsonl("PushContainers")
    def _run(self, on_update=None):
        push_items = self.external_resources["push_items"]
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        container_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[container_items_indexes_key].results

        for index in indexes:
            item = push_items[index]
            log_info("Pushing %s", str(item))
            self._push_container_item(item)


class StepSignContainers(Step):
    """Sign pushed containers.

    Expected step args:
        (container_items_indexes_key)
    Expected step kwargs:
        {"container_signing_enabled": <True|False=default>}
    Expected shared results:
        <container_items_indexes_key>: [ list of indexes of container push items in push_items]
    Produced details:
        {
            "items": { <repo>: { <tag> { "state": ready|signed, "source": <pull_url>}}}
    Results:
        None
    """

    NAME = "StepSignContainers"

    def _init_details(self):
        push_items = self.external_resources["push_items"]
        items = {}
        self._details = {"items": items}
        container_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[container_items_indexes_key].results

        for index in indexes:
            item = push_items[index]
            for repo, tags in six.iteritems(item.metadata.get("tags", {})):
                items[repo] = {}
                for tag in tags:
                    items[repo][tag] = {
                        "state": "ready",
                        "source": item.metadata["pull_data"],
                    }

    def _pre_run(self):
        if not self.step_kwargs.get("container_signing_enabled"):
            self.skip = True
            self.skip_reason = "Container signing for the target is not enabled"

    def _sign_container_items(self, sign_metadata):
        raise NotImplementedError

    @log_jsonl("SignContainers")
    def _run(self, on_update=None):
        push_items = self.external_resources["push_items"]
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        container_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[container_items_indexes_key].results

        sign_metadata = []
        for index in indexes:
            item = push_items[index]
            for repo, tags in six.iteritems(item.metadata.get("tags", {})):
                sign_metadata.append((repo, tags, item.metadata["pull_data"]))
                log_info("Signing %s %s", repo, tags)
        self._sign_container_items(sign_metadata)


class StepPushOperators(Step):
    """Push container operators.

    Expected step args:
        (operators_items_indexes_key,)
    Expected step kwargs:
        {"autoupload_operators": <True=default|False>,
         "docker_reference_registry": <str>,
         "iib_server":<str>}
    Expected shared results:
        <operator_items_indexes_key>: [ list of indexes of operator push items in push_items]
    Expected external resources:
        "log_debug": log debug callback or None
        "log_info": log info callback or None
        "log_warning": log warning callback or None
        "log_error": log error callback or None
        "hub": pubhub xmlrpcserver instance
        "task_id": task id
        "target_name": target name
    Produced details:
        {
            "items": { <bundle_ref> { "state": ready|error|pushed}}
        }
    Results:
        None
    """

    NAME = "StepPushOperators"

    @staticmethod
    def _get_immutable_tag(item):
        """Return immutable tag from operator push item production tags."""
        if item.metadata["v_r"] in list(item.metadata["tags"].values())[0]:
            return item.metadata["v_r"]
        # if v_r tag is not in destination tags, return tag with the most numbers in it
        # This code is usually trigerred when push is not initiated from ET but manually
        # by user
        tags = []
        for tag in list(item.metadata["tags"].values())[0]:
            tags.append((len(re.split(r"\d+", tag)), tag))
        return sorted(tags)[-1][1]

    def _init_details(self):
        push_items = self.external_resources["push_items"]
        items = {}
        self._details = {"items": items}
        for item in push_items:
            bundle_repo = list(item.metadata["destination"]["tags"].keys())[0]
            bundle_ref = "{0}/{1}:{2}".format(
                self.step_kwargs["docker_reference_registry"],
                bundle_repo,
                self._get_immutable_tag(item),
            )
            items[bundle_ref] = "ready"

    def _pre_run(self):
        if not self.step_kwargs.get("auto_upload_operators", True):
            self.skip = True
            self.skip_reason = "Automatic uploading of operators is not enabled"
        if not self.step_kwargs.get("iib_server"):
            self.skip = True
            self.skip_reason = "IIB server is not defined"

    def _push_operator_items(self, items, osev):
        raise NotImplementedError

    def pyxis_get_ocp_versions(self, item):
        """
        Get a list of supported ocp versions from Pyxis.

        Args:
            push_item: (_PushItem)
                Push item for which the OCP version range will be found out.

        Returns:
            list(str): list of supported OCP versions as returned by Pyxis.
        """
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        ocp_versions = item.metadata["com.redhat.openshift.versions"]
        log_info("Getting OCP versions of '{0}' from Pyxis.".format(ocp_versions))
        entry_point = (
            "pubtools-pyxis",
            "console_scripts",
            "pubtools-pyxis-get-operator-indices",
        )
        entry_point_fn = pkg_resources.load_entry_point(*entry_point)
        args = [
            "cmd",
            "--pyxis-server",
            self.step_kwargs["pyxis_server"],
            "--pyxis-krb-principal",
            self.step_kwargs["pyxis_krb_principal"],
            "--pyxis-krb-ktfile",
            self.step_kwargs["pyxis_krb_ktfile"],
            "--pyxis-ssl-crtfile",
            self.step_kwargs["pyxis_ssl_crtfile"],
            "--pyxis-ssl-keyfile",
            self.step_kwargs["pyxis_ssl_keyfile"],
            "--ocp-versions-range",
            ocp_versions,
        ]
        if self.step_kwargs.get("pyxis_insecure"):
            args += ["--pyxis-insecure"]
        data = entry_point_fn(args)
        if not data:
            msg = "Pyxis has returned no OCP versions for '{0}' specified in build {1}.".format(
                ocp_versions, item.metadata["build"]["build_id"]
            )
            raise ValueError(msg)
        # Versions returned by Pyxis don't contain 'v' at the front (4.5 -> v4.5)
        return ["v{0}".format(item["ocp_version"]) for item in data]

    @log_jsonl("PushOperators")
    def _run(self, on_update=None):
        push_items = self.external_resources["push_items"]
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        operator_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[operator_items_indexes_key].results
        iib_by_ose = {}
        ocp_versions_resolved = {}

        for index in indexes:
            item = push_items[index]
            ocp_versions = item.metadata["com.redhat.openshift.versions"]
            if ocp_versions not in ocp_versions_resolved:
                ocp_versions_resolved[ocp_versions] = self.pyxis_get_ocp_versions(item)
            for version in ocp_versions_resolved[ocp_versions]:
                iib_by_ose.setdefault(version, []).append(item)
        for osev, items in iib_by_ose.items():
            log_info("Pushing operators for %s: %s", osev, [str(x) for x in items])
            self._push_operator_items(items, osev)


class StepMergeManifestList(Step):
    """Merge manifest lists of pushed containers.

    Expected step args:
        (container_items_indexes_key, target_settings)
    Produced details:
        {
            "items": { <repo>: { <tag> { "state": ready|error|pushed,
                                         "source": <pull_url>}}}
        }
    Expected external resources:
        "log_debug": log debug callback or None
        "log_info": log info callback or None
        "log_warning": log warning callback or None
        "log_error": log error callback or None
        "hub": pubhub xmlrpcserver instance
        "task_id": task id
    Results:
        None
    """

    NAME = "StepMergeManifestList"

    def _init_details(self):
        push_items = self.external_resources["push_items"]
        items = {}
        self._details = {"items": items}
        for item in push_items:
            for repo, tags in six.iteritems(item.metadata.get("tags", {})):
                items[repo] = {}
                for tag in tags:
                    items[repo][tag] = {
                        "state": "ready",
                        "source": item.metadata["pull_data"],
                    }

    def _merge_manifest_list(self, item):
        raise NotImplementedError

    @log_jsonl("MergeManifestList")
    def _run(self, on_update=None):
        push_items = self.external_resources["push_items"]
        operator_items_indexes_key = self.step_args[0]
        indexes = self._shared_results[operator_items_indexes_key].results
        for index in indexes:
            item = push_items[index]
            self._merge_manifest_list(item)


class StepRollback(Step):
    """Rollback step to revert data if sequence fails.

    Expected step args:
        (backup_results_key,)
    Produced details:
        {
            "items": { <repo>: { <tag>: (ready,removed,replaced) }}
        }
    Expected external resources:
        "log_debug": log debug callback or None
        "log_info": log info callback or None
        "log_warning": log warning callback or None
        "log_error": log error callback or None
    Results:
        None
    """

    NAME = "StepRollback"

    def _init_details(self):
        backup_results_key = self.step_args[0]
        items = {}
        self._details = {"items": items}
        backup_results = self._shared_results[backup_results_key].results

        for repo, tags in backup_results.get("backup_tags", {}).items():
            items[repo] = {}
            for tag in tags:
                items[repo][tag] = "ready"
        for repo, tags in backup_results.get("rollback_tags", {}).items():
            items[repo] = {}
            for tag in tags:
                items[repo][tag] = "ready"

    def _update_details(self, details):
        repo, tag, state = details
        self._details["items"][repo][tag] = state

    def _rollback(self, repo, to_rollback):
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        log_info("Removing", repo, to_rollback)
        raise NotImplementedError

    def _restore(self, repo, to_restore):
        log_info = self.external_resources.get("log_info", lambda *args, **kwargs: ())
        log_info("Restoring", repo, to_restore)
        raise NotImplementedError

    @log_jsonl("Rollback")
    def _run(self, on_update=None):
        backup_results_key = self.step_args[0]
        rollback = self._shared_results[backup_results_key].results.get("rollback_tags", {})
        backup = self._shared_results[backup_results_key].results.get("backup_tags", {})
        for repo, tags in rollback.items():
            for to_rollback in tags:
                self._rollback(repo, to_rollback)
                self.update_details((repo, to_rollback, "removed"))
        for repo, tags in backup.items():
            for to_restore in tags:
                self._restore(repo, to_restore)
                self.update_details((repo, to_restore, "restored"))
