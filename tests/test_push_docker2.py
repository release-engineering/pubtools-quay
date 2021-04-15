try:
    import mock
except ImportError:
    from unittest import mock

import json
import pytest

from pubtools._quay.push_docker2 import mod_entry_point

MOCK_FILES = {}


@pytest.fixture
def fixture_update_tag_backups():
    with mock.patch(
        "pubtools._quay.quay_steps.StepBuildBackupMapping._update_tag_backups"
    ) as patched:
        yield patched


@pytest.fixture
def fixture_push_container_item():
    with mock.patch(
        "pubtools._quay.quay_steps.StepPushContainerImgs._push_container_item"
    ) as patched:
        yield patched


@pytest.fixture
def fixture_merge_manifest_list():
    with mock.patch(
        "pubtools._quay.quay_steps.StepMergeManifestList._merge_manifest_list"
    ) as patched:
        yield patched


@pytest.fixture
def fixture_merge_manifest_list_failed():
    with mock.patch(
        "pubtools._quay.quay_steps.StepMergeManifestList._merge_manifest_list"
    ) as patched:
        patched.side_effect = ValueError
        yield patched


@pytest.fixture
def fixture_to_rollback():
    with mock.patch("pubtools._quay.quay_steps.StepRollback._rollback") as patched:
        yield patched


@pytest.fixture
def fixture_to_restore():
    with mock.patch("pubtools._quay.quay_steps.StepRollback._restore") as patched:
        yield patched


class MockHub(object):
    """PubHub mock class."""

    def upload_task_log(self, io, task_id, filename, append=False):
        """Fake upload task log method."""
        if not append:
            MOCK_FILES["%s.%s" % (task_id, filename)] = io.getvalue()
        else:
            MOCK_FILES["%s.%s" % (task_id, filename)] += io.getvalue()


def test_push_docker_ok(
    container_push_item_ok,
    operator_push_item_ok,
    fixture_update_tag_backups,
    fixture_push_container_item,
    fixture_merge_manifest_list,
    fixture_test_data_dir,
    fixture_isodate_now,
):
    mod_entry_point(
        [container_push_item_ok, operator_push_item_ok],
        MockHub(),
        "mock-task-id",
        "mock-target-name",
        {
            "docker_settings": {},
            "iib_server": "mock-iib-server",
            "docker_reference_registry": "fake-reference-registry",
        },
    )
    status = json.loads(MOCK_FILES["mock-task-id.report.json"])
    assert status == json.load(open(fixture_test_data_dir + "test_push_docker_ok.json"))


def test_push_docker_failed(
    container_push_item_ok,
    operator_push_item_ok,
    fixture_update_tag_backups,
    fixture_push_container_item,
    fixture_merge_manifest_list_failed,
    fixture_to_rollback,
    fixture_to_restore,
    fixture_isodate_now,
):
    with pytest.raises(ValueError):
        mod_entry_point(
            [container_push_item_ok, operator_push_item_ok],
            MockHub(),
            "mock-task-id",
            "mock-target-name",
            {"docker_settings": {}, "iib_server": "mock-iib-server"},
        )
