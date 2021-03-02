from io import BytesIO
import json

try:
    import mock
except ImportError:  # pragma: no cover
    from unittest import mock  # pragma: no cover

from .quay_steps import (
    StepSanitizeContainerPushItems,
    StepPushContainerImgs,
    StepMergeManifestList,
    StepSignContainers,
    StepSanitizeRepositories,
    StepPushOperators,
    StepBuildBackupMapping,
    StepSanitizeOperatorPushItems,
    StepRollback,
)

from .utils.stepper import Stepper, isodate_now
from .utils.logger import Logger


CLI_DESCRIPTION = ""


def push_docker(push_items, signing_key, hub, task_id, target_name, target_settings):
    """Run push docker sequence.

    Arguments:
        push_items (<list-of-push-items>)
            List of push items containing metadata
        signing_key (str)
            Signing key which should be used to sign pushed manifests
        hub (xmlrpc.client.ServerProxy)
            Pubhub XMLRPC proxy instance
        task_id (int)
            Pub task id
        target_name (str)
            Pub target name
        target_settings (dict)
            Target settings
    """
    shared_data = {}
    logger = Logger()
    common_external_res = {
        "push_items": push_items,
        "log_info": logger.log_info,
        "log_error": logger.log_error,
        "log_warning": logger.log_warning,
        "log_debug": logger.log_debug,
        "hub": hub,
        "task_id": task_id,
        "target_name": target_name,
    }

    stepper = Stepper(shared_data)
    stepper.add_step(
        StepSanitizeContainerPushItems(
            "1", (), {}, shared_data, external_resources=common_external_res
        )
    )
    stepper.add_step(
        StepSanitizeRepositories(
            "1",
            ("StepSanitizeContainerPushItems:1",),
            {},
            shared_data,
            external_resources=common_external_res,
        )
    )
    stepper.add_step(
        StepBuildBackupMapping(
            "1",
            ("StepSanitizeContainerPushItems:1",),
            {},
            shared_data,
            external_resources=common_external_res,
        )
    )
    stepper.add_step(
        StepPushContainerImgs(
            "1",
            ("StepSanitizeContainerPushItems:1", target_settings),
            {},
            shared_data,
            external_resources=common_external_res,
        )
    )
    stepper.add_step(
        StepMergeManifestList(
            "1",
            ("StepSanitizeContainerPushItems:1", target_settings),
            {},
            shared_data,
            external_resources=common_external_res,
        )
    )
    stepper.add_step(
        StepSignContainers(
            "1",
            ("StepSanitizeContainerPushItems:1", target_settings),
            {
                "container_signing_enabled": target_settings["docker_settings"].get(
                    "container_signing_enabled", False
                )
            },
            shared_data,
            external_resources=common_external_res,
        )
    )
    stepper.add_step(
        StepSanitizeOperatorPushItems(
            "1",
            (),
            {"auto_upload_operators": target_settings.get("auto_upload_operators")},
            shared_data,
            external_resources=common_external_res,
        )
    )
    stepper.add_step(
        StepPushOperators(
            "1",
            ("StepSanitizeOperatorPushItems:1", target_settings),
            {
                "docker_reference_registry": target_settings.get(
                    "docker_reference_registry"
                )
            },
            shared_data,
            external_resources=common_external_res,
        )
    )
    stepper.add_step(
        StepSignContainers(
            "index-image",
            ("StepSanitizeContainerPushItems:1",),
            {
                "autoupload_operators": target_settings.get("auto_upload_operators"),
                "docker_reference_registry": target_settings.get(
                    "docker_reference_registry"
                ),
                "iib_server": target_settings["iib_server"],
            },
            shared_data,
            external_resources=common_external_res,
        )
    )
    try:
        stepper.run()
    except Exception:
        stepper.add_step(
            StepRollback(
                "1",
                ("StepBuildBackupMapping:1", target_settings),
                {},
                shared_data,
                external_resources=common_external_res,
            )
        )
        stepper.run(start_from=-1)
        raise
    finally:
        results = stepper.dump()
        json_io = BytesIO(str(json.dumps(results) + "\n").encode("utf-8"))
        hub.upload_task_log(json_io, task_id, "report.json")
    return stepper.shared_results


def mod_entry_point(push_items, hub, task_id, target_name, target_settings):
    """Entry point for use in another python code."""
    return push_docker(
        push_items, "signing-key", hub, task_id, target_name, target_settings
    )


def mocked_mod_entry_point(push_items, hub, task_id, target_name, target_settings):
    """Mock entry point for use in testing in another code."""
    _isodate_now = [0]
    with mock.patch(isodate_now.__module__ + ".isodate_now") as patched_isodate_now:
        patched_isodate_now.side_effect = (
            lambda: "isodate_now_%d"
            % [_isodate_now.__setitem__(0, _isodate_now[0] + 1), _isodate_now][1][0]
        )
        return push_docker(
            push_items, "signing-key", hub, task_id, target_name, target_settings
        )
