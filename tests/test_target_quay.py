try:
    import mock
except ImportError:
    from unittest import mock

import pytest

from pubtools._quay.quay_steps import (
    StepSanitizeContainerPushItems,
    StepSanitizeOperatorPushItems,
    StepSanitizeRepositories,
    StepBuildBackupMapping,
    StepPushContainerImgs,
    StepSignContainers,
    StepPushOperators,
    StepMergeManifestList,
    StepRollback,
    # StepUDFlushCache,
)
from pubtools._quay.utils.logger import Logger
from pubtools._quay.utils.stepper import StepResults

from .conftest import MockContainerPushItem


@pytest.fixture
def fixture_isodate_now():
    """Return current datetime string in iso-8601 format."""
    counter = {"i": 0}
    with mock.patch("pubtools._quay.utils.stepper.isodate_now") as mocked:
        mocked.side_effect = lambda: [
            counter.__setitem__("i", counter["i"] + 1),
            "isodate_now_" + str(counter["i"]),
        ][1]
        yield mocked


@pytest.fixture
def container_push_item_ok():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos={"test_repo": []},
        build="push_item_build",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "tags": {"test-repo": ["latest-test-tag", "1.0"]},
            "v_r": "1.0",
        },
    )


@pytest.fixture
def container_push_item_no_metadata():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={},
    )


@pytest.fixture
def container_push_item_empty_file_path():
    return MockContainerPushItem(
        file_path=None,
        file_name="push_item_filename",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={},
    )


@pytest.fixture
def container_push_item_not_container():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="iso",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={},
    )


@pytest.fixture
def container_push_item_errors():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            }
        },
        errors={"fake-error1": "fake-error1 message"},
    )


@pytest.fixture
def operator_push_item_ok():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="operator",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "com.redhat.openshift.versions": "v4.5",
            "op_type": "bundle",
            "build": {"build_id": 123456},
            "destination": {"tags": {"repo": ["tag1", "tag2"]}},
            "tags": {"repo": ["latest-test-tag", "1.0"]},
            "v_r": "1.0",
        },
    )


@pytest.fixture
def operator_push_item_ok2():
    return MockContainerPushItem(
        file_path="push_item_filepath2",
        file_name="push_item_filename",
        file_type="operator",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "com.redhat.openshift.versions": "v4.5",
            "op_type": "bundle",
            "build": {"build_id": 123456},
            "destination": {"tags": {"repo": ["tag3", "tag4"]}},
            "tags": {"repo2": ["latest-test-tag", "5.0.0"]},
            "v_r": "5.0",
        },
    )


@pytest.fixture
def operator_push_item_appregistry():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="operator",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "com.redhat.openshift.versions": "v4.5",
            "op_type": "appregistry",
        },
    )


@pytest.fixture
def operator_push_item_unkwown_op_type():
    return MockContainerPushItem(
        file_path="push_item_filepath-1",
        file_name="push_item_filename",
        file_type="operator",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "com.redhat.openshift.versions": "v4.5",
            "op_type": "operators_next",
        },
    )


@pytest.fixture
def fixture_pyxis_get_ocp_versions():
    with mock.patch("pkg_resources.load_entry_point") as mocked:
        print(mocked())
        yield mocked()


@pytest.fixture
def operator_push_item_no_ocp():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="operator",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "op_type": "bundle",
        },
    )


@pytest.fixture
def common_external_resources():
    log = Logger()
    return {
        "log_info": log.log_info,
        "log_error": log.log_error,
        "log_warning": log.log_warning,
        "log_debug": log.log_debug,
    }


def test_StepSanitizeContainerPushItems_ok(
    container_push_item_ok, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources=common_external_resources
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeContainerPushItems",
        "step_args": [],
        "step_kwargs": {},
        "uid": "1",
        "details": [{"item": "push_item_filepath", "state": "ok"}],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "finished",
        },
        "results": {"results": [0], "errors": {}},
    }


def test_StepSanitizeContainerPushItems_no_pull_data(
    container_push_item_no_metadata, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_no_metadata]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources=common_external_resources
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeContainerPushItems",
        "step_args": [],
        "step_kwargs": {},
        "uid": "1",
        "details": [{"item": "push_item_filepath", "state": "no-pull-data"}],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "failed",
        },
        "results": {
            "results": {},
            "errors": {"item_errors": [("push_item_filepath", "Cannot calculate pull data")]},
        },
    }


def test_StepSanitizeContainerPushItems_empty_file_path(
    container_push_item_empty_file_path, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_empty_file_path]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources=common_external_resources
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeContainerPushItems",
        "step_args": [],
        "step_kwargs": {},
        "uid": "1",
        "details": [{"item": "push_item_filename", "state": "no-pull-data"}],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "failed",
        },
        "results": {
            "results": {},
            "errors": {
                "item_errors": [
                    ("push_item_filename", "empty file_path"),
                    ("push_item_filename", "Cannot calculate pull data"),
                ]
            },
        },
    }


def test_StepSanitizeRepositories_ok(
    container_push_item_ok, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources=common_external_resources
    )
    step.run()
    step2 = StepSanitizeRepositories(
        "1",
        ("StepSanitizeContainerPushItems:1",),
        {},
        shared_results,
        external_resources=common_external_resources,
    )
    step2.run()
    assert step2.dump() == {
        "name": "StepSanitizeRepositories",
        "step_args": ["StepSanitizeContainerPushItems:1"],
        "step_kwargs": {},
        "uid": "1",
        "details": {"test_repo": "ready"},
        "stats": {
            "started": "isodate_now_3",
            "finished": "isodate_now_4",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "finished",
        },
        "results": {"results": {}, "errors": {}},
    }


def test_StepSanitizeRepositories_not_implemented(
    container_push_item_ok, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources=common_external_resources
    )
    step.run()
    step2 = StepSanitizeRepositories(
        "1",
        ("StepSanitizeContainerPushItems:1",),
        {},
        shared_results,
        external_resources=common_external_resources,
    )
    assert step2.dump() == {
        "name": "StepSanitizeRepositories",
        "step_args": ["StepSanitizeContainerPushItems:1"],
        "step_kwargs": {},
        "uid": "1",
        "details": {"test_repo": "ready"},
        "stats": {
            "started": None,
            "finished": None,
            "skip": False,
            "skip_reason": "",
            "skipped": None,
            "state": "ready",
        },
        "results": {"results": {}, "errors": {}},
    }
    with pytest.raises(NotImplementedError):
        step2.run()


def test_StepSanitizeContainerPushItems_not_container(
    container_push_item_not_container, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_not_container]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources=common_external_resources
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeContainerPushItems",
        "step_args": [],
        "step_kwargs": {},
        "uid": "1",
        "details": [{"item": "push_item_filepath", "state": "not-container"}],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "finished",
        },
        "results": {"results": [], "errors": {}},
    }


def test_StepSanitizeContainerPushItems_item_errors(
    container_push_item_errors, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    container_push_item_errors.add_error("INVALID", "error message")
    push_items = [container_push_item_errors]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources=common_external_resources
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeContainerPushItems",
        "step_args": [],
        "step_kwargs": {},
        "uid": "1",
        "details": [{"item": "push_item_filepath", "state": "error"}],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "failed",
        },
        "results": {
            "results": {},
            "errors": {
                "item_errors": [
                    (
                        "push_item_filepath",
                        {"base": "error message", "fake-error1": "fake-error1 message"},
                    )
                ]
            },
        },
    }


def test_StepSanitizeOperatorPushItems_ok(
    operator_push_item_ok, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [operator_push_item_ok]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeOperatorPushItems(
        "1", ({},), {}, shared_results, external_resources=common_external_resources
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeOperatorPushItems",
        "step_args": [{}],
        "step_kwargs": {},
        "uid": "1",
        "details": [
            {"item": "push_item_filepath", "state": "ok"},
        ],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "finished",
        },
        "results": {"results": [0], "errors": {}},
    }


def test_StepSanitizeOperatorPushItems_not_operator(
    container_push_item_not_container, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_not_container]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeOperatorPushItems(
        "1",
        ({},),
        {},
        shared_results,
        external_resources=common_external_resources,
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeOperatorPushItems",
        "step_args": [{}],
        "step_kwargs": {},
        "uid": "1",
        "details": [{"item": "push_item_filepath", "state": "not-operator"}],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "finished",
        },
        "results": {"results": [], "errors": {}},
    }


def test_StepSanitizeOperatorPushItems_unsupported_legacy(
    operator_push_item_unkwown_op_type,
    operator_push_item_appregistry,
    fixture_isodate_now,
    common_external_resources,
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [
        operator_push_item_unkwown_op_type,
        operator_push_item_appregistry,
    ]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeOperatorPushItems(
        "1",
        ({},),
        {},
        shared_results,
        external_resources=common_external_resources,
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeOperatorPushItems",
        "step_args": [{}],
        "step_kwargs": {},
        "uid": "1",
        "details": [
            {"item": "push_item_filepath-1", "state": "unknown-op-type"},
            {"item": "push_item_filepath", "state": "unsupported-legacy"},
        ],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "failed",
        },
        "results": {
            "results": {},
            "errors": {
                "item_errors": [("push_item_filepath-1", "unknown operator type: operators_next")]
            },
        },
    }


def test_StepSanitizeOperatorPushItems_skip(
    fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = []
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeOperatorPushItems(
        "1",
        (),
        {"auto_upload_operators": False},
        shared_results,
        external_resources=common_external_resources,
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeOperatorPushItems",
        "step_args": [],
        "step_kwargs": {"auto_upload_operators": False},
        "uid": "1",
        "details": [],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": True,
            "skip_reason": "Automatic uploading of operators is not enabled",
            "skipped": True,
            "state": "finished",
        },
        "results": {"results": {}, "errors": {}},
    }


def test_StepSanitizeOperatorPushItems_no_ocp(
    operator_push_item_no_ocp, fixture_isodate_now, common_external_resources
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [operator_push_item_no_ocp]
    common_external_resources.update({"push_items": push_items})
    step = StepSanitizeOperatorPushItems(
        "1",
        ({},),
        {},
        shared_results,
        external_resources=common_external_resources,
    )
    step.run()
    assert step.dump() == {
        "name": "StepSanitizeOperatorPushItems",
        "step_args": [{}],
        "step_kwargs": {},
        "uid": "1",
        "details": [{"item": "push_item_filepath", "state": "no-ocp-version"}],
        "stats": {
            "started": "isodate_now_1",
            "finished": "isodate_now_2",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "failed",
        },
        "results": {
            "results": {},
            "errors": {
                "item_errors": [
                    (
                        "push_item_filepath",
                        "'com.redhat.openshift.versions' is not specified for build",
                    )
                ]
            },
        },
    }


def test_StepBuildBackupMapping_not_implemented(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources={"push_items": push_items}
    )
    step.run()
    step2 = StepBuildBackupMapping(
        "1",
        ("StepSanitizeContainerPushItems:1",),
        {},
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(NotImplementedError):
        step2.run()


def test_StepBuildBackupMapping_ok(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    with mock.patch("pubtools._quay.quay_steps.StepBuildBackupMapping.update_details"):
        step = StepSanitizeContainerPushItems(
            "1", (), {}, shared_results, external_resources={"push_items": push_items}
        )
        step.run()
        step2 = StepBuildBackupMapping(
            "1",
            ("StepSanitizeContainerPushItems:1",),
            {},
            shared_results,
            external_resources={"push_items": push_items},
        )
        step2.run()


def test_StepPushContainerImgs_not_implemented(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources={"push_items": push_items}
    )
    step.run()
    step2 = StepPushContainerImgs(
        "1",
        ("StepSanitizeContainerPushItems:1", {}),
        {},
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(NotImplementedError):
        step2.run()
    assert step2.dump() == {
        "name": "StepPushContainerImgs",
        "step_args": ["StepSanitizeContainerPushItems:1", {}],
        "step_kwargs": {},
        "uid": "1",
        "details": {
            "items": {
                "test-repo": {
                    "latest-test-tag": {
                        "source": {
                            "registry": "test-regitry",
                            "repo": "test-repo",
                            "tag": "test-tag",
                        },
                        "state": "ready",
                    },
                    "1.0": {
                        "source": {
                            "registry": "test-regitry",
                            "repo": "test-repo",
                            "tag": "test-tag",
                        },
                        "state": "ready",
                    },
                }
            }
        },
        "stats": {
            "started": "isodate_now_3",
            "finished": "isodate_now_4",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "error",
        },
        "results": {
            "results": {},
            "errors": {},
        },
    }


def test_StepSignContainers_not_implemented(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources={"push_items": push_items}
    )
    step.run()
    step2 = StepSignContainers(
        "1",
        ("StepSanitizeContainerPushItems:1",),
        {"container_signing_enabled": True},
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(NotImplementedError):
        step2.run()
    assert step2.dump() == {
        "name": "StepSignContainers",
        "step_args": ["StepSanitizeContainerPushItems:1"],
        "step_kwargs": {"container_signing_enabled": True},
        "uid": "1",
        "details": {
            "items": {
                "test-repo": {
                    "latest-test-tag": {
                        "source": {
                            "registry": "test-regitry",
                            "repo": "test-repo",
                            "tag": "test-tag",
                        },
                        "state": "ready",
                    },
                    "1.0": {
                        "source": {
                            "registry": "test-regitry",
                            "repo": "test-repo",
                            "tag": "test-tag",
                        },
                        "state": "ready",
                    },
                }
            }
        },
        "stats": {
            "started": "isodate_now_3",
            "finished": "isodate_now_4",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "error",
        },
        "results": {
            "results": {},
            "errors": {},
        },
    }


def test_StepSignContainers_skip(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources={"push_items": push_items}
    )
    step.run()
    step2 = StepSignContainers(
        "1",
        ("StepSanitizeContainerPushItems:1",),
        {"container_signing_enabled": False},
        shared_results,
        external_resources={"push_items": push_items},
    )
    step2.run()
    assert step2.dump() == {
        "name": "StepSignContainers",
        "step_args": ["StepSanitizeContainerPushItems:1"],
        "step_kwargs": {"container_signing_enabled": False},
        "uid": "1",
        "details": {
            "items": {
                "test-repo": {
                    "latest-test-tag": {
                        "source": {
                            "registry": "test-regitry",
                            "repo": "test-repo",
                            "tag": "test-tag",
                        },
                        "state": "ready",
                    },
                    "1.0": {
                        "source": {
                            "registry": "test-regitry",
                            "repo": "test-repo",
                            "tag": "test-tag",
                        },
                        "state": "ready",
                    },
                }
            }
        },
        "stats": {
            "started": "isodate_now_3",
            "finished": "isodate_now_4",
            "skip": True,
            "skip_reason": "Container signing for the target is not enabled",
            "skipped": True,
            "state": "finished",
        },
        "results": {
            "results": {},
            "errors": {},
        },
    }


def test_StepPushOperators_not_implemented(
    operator_push_item_ok,
    operator_push_item_ok2,
    fixture_isodate_now,
    fixture_pyxis_get_ocp_versions,
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [operator_push_item_ok, operator_push_item_ok2]
    fixture_pyxis_get_ocp_versions.return_value = [{"ocp_version": "4.5"}]
    step = StepSanitizeOperatorPushItems(
        "1",
        (),
        {"auto_upload_operators": True},
        shared_results,
        external_resources={"push_items": push_items},
    )
    step.run()
    step2 = StepPushOperators(
        "1",
        ("StepSanitizeOperatorPushItems:1",),
        {
            "auto_upload_operators": True,
            "iib_server": "test_iib_server",
            "pyxis_server": "test_pyxis_server",
            "pyxis_krb_principal": "test_pyxis_krb_principal",
            "pyxis_krb_ktfile": "test_pyxis_krb_ktfile",
            "pyxis_ssl_crtfile": "test_pyxis_ssl_crtfile",
            "pyxis_ssl_keyfile": "test_pyxis_ssl_keyfile",
            "pyxis_insecure": True,
            "docker_reference_registry": "test-reference-registry",
        },
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(NotImplementedError):
        step2.run()
    assert step2.dump() == {
        "name": "StepPushOperators",
        "step_args": ["StepSanitizeOperatorPushItems:1"],
        "step_kwargs": {
            "auto_upload_operators": True,
            "docker_reference_registry": "test-reference-registry",
            "iib_server": "test_iib_server",
            "pyxis_server": "test_pyxis_server",
            "pyxis_krb_principal": "test_pyxis_krb_principal",
            "pyxis_krb_ktfile": "test_pyxis_krb_ktfile",
            "pyxis_ssl_crtfile": "test_pyxis_ssl_crtfile",
            "pyxis_ssl_keyfile": "test_pyxis_ssl_keyfile",
            "pyxis_insecure": True,
        },
        "uid": "1",
        "details": {
            "items": {
                "test-reference-registry/repo:1.0": "ready",
                "test-reference-registry/repo:5.0.0": "ready",
            }
        },
        "stats": {
            "started": "isodate_now_3",
            "finished": "isodate_now_4",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "state": "error",
        },
        "results": {
            "results": {},
            "errors": {},
        },
    }


def test_StepPushOperators_no_pyxis_data(
    operator_push_item_ok, fixture_isodate_now, fixture_pyxis_get_ocp_versions
):  # pylint: disable=unused-argument
    fixture_pyxis_get_ocp_versions.return_value = []
    shared_results = {}
    push_items = [operator_push_item_ok]
    step = StepSanitizeOperatorPushItems(
        "1",
        (),
        {"auto_upload_operators": True},
        shared_results,
        external_resources={"push_items": push_items},
    )
    step.run()
    step2 = StepPushOperators(
        "1",
        ("StepSanitizeOperatorPushItems:1",),
        {
            "auto_upload_operators": True,
            "iib_server": "test_iib_server",
            "pyxis_server": "test_pyxis_server",
            "pyxis_krb_principal": "test_pyxis_krb_principal",
            "pyxis_krb_ktfile": "test_pyxis_krb_ktfile",
            "pyxis_ssl_crtfile": "test_pyxis_ssl_crtfile",
            "pyxis_ssl_keyfile": "test_pyxis_ssl_keyfile",
        },
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(ValueError):
        step2.run()


def test_StepPushOperators_skip(
    operator_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [operator_push_item_ok]
    step = StepSanitizeOperatorPushItems(
        "1",
        (),
        {"auto_upload_operators": False},
        shared_results,
        external_resources={"push_items": push_items},
    )
    step.run()
    step2 = StepPushOperators(
        "1",
        ("StepSanitizeOperatorPushItems:1",),
        {"auto_upload_operators": False, "iib_server": "test_iib_server"},
        shared_results,
        external_resources={"push_items": push_items},
    )
    step2.run()


def test_StepPushOperators_skip_no_iib(
    operator_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [operator_push_item_ok]
    step = StepSanitizeOperatorPushItems(
        "1",
        (),
        {"auto_upload_operators": True},
        shared_results,
        external_resources={"push_items": push_items},
    )
    step.run()
    step2 = StepPushOperators(
        "1",
        ("StepSanitizeOperatorPushItems:1",),
        {"auto_upload_operators": True},
        shared_results,
        external_resources={"push_items": push_items},
    )
    step2.run()


def test_StepMergeManifestList_not_implemented(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources={"push_items": push_items}
    )
    step.run()
    step2 = StepMergeManifestList(
        "1",
        (
            "StepSanitizeContainerPushItems:1",
            {"auto_upload_operators": False, "iib_server": "test_iib_server"},
        ),
        {},
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(NotImplementedError):
        step2.run()


def test_StepRollback_ok(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources={"push_items": push_items}
    )
    step.run()
    step2 = StepBuildBackupMapping(
        "1",
        ("StepSanitizeContainerPushItems:1",),
        {},
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(NotImplementedError):
        step2.run()
    assert step2.dump() == {
        "details": {
            "backup_tags": {"test-repo": {"latest-test-tag": None, "1.0": None}},
            "rollback_tags": {"test-repo": {"latest-test-tag": None, "1.0": None}},
        },
        "name": "StepBuildBackupMapping",
        "results": {"errors": {}, "results": {}},
        "stats": {
            "finished": "isodate_now_4",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "started": "isodate_now_3",
            "state": "error",
        },
        "step_args": ["StepSanitizeContainerPushItems:1"],
        "step_kwargs": {},
        "uid": "1",
    }
    shared_results["StepBuildBackupMapping:1"] = StepResults()
    shared_results["StepBuildBackupMapping:1"].results = {
        "backup_tags": {"repo": {"tag1": False}},
        "rollback_tags": {"repo": {"tag2": False, "source": "test-source"}},
    }

    with mock.patch("pubtools._quay.quay_steps.StepRollback._rollback"):
        with mock.patch("pubtools._quay.quay_steps.StepRollback._restore"):
            step3 = StepRollback(
                "1",
                ("StepBuildBackupMapping:1",),
                {},
                shared_results,
                external_resources={"push_items": push_items},
            )
            step3.run()
    assert step3.dump() == {
        "details": {
            "items": {"repo": {"source": "removed", "tag1": "restored", "tag2": "removed"}}
        },
        "name": "StepRollback",
        "results": {"errors": {}, "results": {}},
        "stats": {
            "finished": "isodate_now_6",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "started": "isodate_now_5",
            "state": "finished",
        },
        "step_args": ["StepBuildBackupMapping:1"],
        "step_kwargs": {},
        "uid": "1",
    }


def test_StepRollback_not_implemented(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources={"push_items": push_items}
    )
    step.run()
    step2 = StepBuildBackupMapping(
        "1",
        ("StepSanitizeContainerPushItems:1",),
        {},
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(NotImplementedError):
        step2.run()
    shared_results["StepBuildBackupMapping:1"] = StepResults()
    shared_results["StepBuildBackupMapping:1"].results = {
        "backup_tags": {"repo": {"tag1": False}},
        "rollback_tags": {"repo": {"tag2": False, "source": "test-source"}},
    }
    with mock.patch("pubtools._quay.quay_steps.StepRollback._restore"):
        step3 = StepRollback(
            "1",
            ("StepBuildBackupMapping:1",),
            {},
            shared_results,
            external_resources={"push_items": push_items},
        )
        with pytest.raises(NotImplementedError):
            step3.run()

    with mock.patch("pubtools._quay.quay_steps.StepRollback._rollback"):
        step3 = StepRollback(
            "1",
            ("StepBuildBackupMapping:1",),
            {},
            shared_results,
            external_resources={"push_items": push_items},
        )
        with pytest.raises(NotImplementedError):
            step3.run()


def test_MergeManifestList_not_implemented(
    container_push_item_ok, fixture_isodate_now
):  # pylint: disable=unused-argument
    shared_results = {}
    push_items = [container_push_item_ok]
    step = StepSanitizeContainerPushItems(
        "1", (), {}, shared_results, external_resources={"push_items": push_items}
    )
    step.run()
    step2 = StepMergeManifestList(
        "1",
        ("StepSanitizeContainerPushItems:1",),
        {},
        shared_results,
        external_resources={"push_items": push_items},
    )
    with pytest.raises(NotImplementedError):
        step2.run()
    assert step2.dump() == {
        "details": {
            "items": {
                "test-repo": {
                    "1.0": {
                        "source": {
                            "registry": "test-regitry",
                            "repo": "test-repo",
                            "tag": "test-tag",
                        },
                        "state": "ready",
                    },
                    "latest-test-tag": {
                        "source": {
                            "registry": "test-regitry",
                            "repo": "test-repo",
                            "tag": "test-tag",
                        },
                        "state": "ready",
                    },
                }
            }
        },
        "name": "StepMergeManifestList",
        "results": {"errors": {}, "results": {}},
        "stats": {
            "finished": "isodate_now_4",
            "skip": False,
            "skip_reason": "",
            "skipped": False,
            "started": "isodate_now_3",
            "state": "error",
        },
        "step_args": ["StepSanitizeContainerPushItems:1"],
        "step_kwargs": {},
        "uid": "1",
    }


# def test_UDFlushCache_ok(
#    container_push_item_ok, fixture_isodate_now
# ):  # pylint: disable=unused-argument
#    shared_results = {}
#    push_items = [container_push_item_ok]
#    step = StepSanitizeContainerPushItems(
#        "1", (), {}, shared_results, external_resources={"push_items": push_items}
#    )
#    step.run()
#    step2 = StepUDFlushCache(
#        "1",
#        ("StepSanitizeContainerPushItems:1",),
#        {
#            "ud_server": "qa",
#            "ud_username": "udusername",
#            "ud_password": "udpassword",
#        },
#        shared_results,
#        external_resources={"push_items": push_items},
#    )
#    # with mock.patch.object(UDCacheFlush,
#    #        'invalidate_unified_downloads_cache_object')  as flusher:
#    step2.run()
#    assert step2.dump() == {
#        "details": {"items": {"test-repo": "flushed"}},
#        "name": "StepFlushUDCache",
#        "results": {"errors": {}, "results": {}},
#        "stats": {
#            "finished": "isodate_now_4",
#            "skip": False,
#            "skip_reason": "",
#            "skipped": False,
#            "started": "isodate_now_3",
#            "state": "finished",
#        },
#        "step_args": ("StepSanitizeContainerPushItems:1",),
#        "step_kwargs": {
#            "ud_server": "qa",
#            "ud_username": "udusername",
#            "ud_password": "udpassword",
#        },
#        "uid": "1",
#    }


# def test_UDFlushCache_skip(
#    container_push_item_ok, fixture_isodate_now
# ):  # pylint: disable=unused-argument
#    shared_results = {}
#    push_items = [container_push_item_ok]
#    step = StepSanitizeContainerPushItems(
#        "1", (), {}, shared_results, external_resources={"push_items": push_items}
#    )
#    step.run()
#    step2 = StepUDFlushCache(
#        "1",
#        ("StepSanitizeContainerPushItems:1", {}),
#        {},
#        shared_results,
#        external_resources={"push_items": push_items},
#    )
#    step2.run()
#    assert step2.dump() == {
#        "details": {"items": {"test-repo": "ready"}},
#        "name": "StepFlushUDCache",
#        "results": {"errors": {}, "results": {}},
#        "stats": {
#            "finished": "isodate_now_4",
#            "skip": True,
#            "skip_reason": "Missing options for unified download, skipping "
#            "invalidating cache",
#            "skipped": True,
#            "started": "isodate_now_3",
#            "state": "finished",
#        },
#        "step_args": ("StepSanitizeContainerPushItems:1", {}),
#        "step_kwargs": {},
#        "uid": "1",
#    }
