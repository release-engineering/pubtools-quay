from io import BytesIO
import json

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

from .utils.stepper import Stepper
from .utils.logger import Logger

import pushcollector

CLI_DESCRIPTION = ""


def log_push_items(signing_key, items=None):
    """Update push items according to their state."""
    collector = pushcollector.Collector.get()
    push_items_to_log = []
    for item in items:
        for repo in item.repos or [""]:
            push_items_to_log.append(
                {
                    "filename": item.file_name,
                    "src": item.file_path,
                    "dest": repo,
                    "build": item.build,
                    "state": item.state,
                    "origin": item.origin,
                    "signing_key": signing_key.upper(),
                    "checksums": item.checksums,
                }
            )
    collector.update_push_items(push_items_to_log)


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
    log_push_items(signing_key, items=push_items)
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
            {"docker_reference_registry": target_settings.get("docker_reference_registry")},
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
                "docker_reference_registry": target_settings.get("docker_reference_registry"),
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
        log_push_items(signing_key, items=push_items)
        results = stepper.dump()
        json_io = BytesIO(str(json.dumps(results) + "\n").encode("utf-8"))
        hub.upload_task_log(json_io, task_id, "report.json")
    return stepper.shared_results


def mod_entry_point(push_items, hub, task_id, target_name, target_settings):
    """Entry point for use in another python code."""
    return push_docker(push_items, "signing-key", hub, task_id, target_name, target_settings)
