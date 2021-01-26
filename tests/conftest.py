import os

try:
    import mock
except ImportError:
    from unittest import mock

import pytest

from pubtools._quay.utils.logger import Logger


class MockContainerPushItem(object):
    """ContainerPushItem used for testing."""

    def __init__(self, **kwargs):
        """Init ContainerPushItem with all args passed here."""
        self.errors = {}
        self.repos = {}
        self.state = None
        for key, val in kwargs.items():
            setattr(self, key, val)

    def add_error(self, state, message, repo=None):
        """Add error to the item."""
        if repo:
            for _repo in self.repos:
                self.repos[_repo] = state
                self.errors[_repo] = message
        else:
            self.state = state
            self.errors["base"] = message

    def __str__(self):
        """Return item string representation."""
        return "%s" % (self.file_path or self.file_name)


@pytest.fixture
def fixture_isodate_now():
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
        file_type="docker_v2",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "destination": {"tags": {"repo": ["tag1"]}},
            "tags": {"test-repo": ["latest-test-tag", "1.0"]},
            "v_r": "1.0",
        },
    )


@pytest.fixture
def container_push_item_no_metadata():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="docker_v2",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        state="NOTPUSHED",
        metadata={},
    )


@pytest.fixture
def container_push_item_empty_file_path():
    return MockContainerPushItem(
        file_path=None,
        file_name="push_item_filename",
        file_type="docker_v2",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
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
        checksums={},
        state="NOTPUSHED",
        metadata={},
    )


@pytest.fixture
def container_push_item_errors():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="docker_v2",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos=[],
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
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
        checksums={},
        state="NOTPUSHED",
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
        checksums={},
        state="NOTPUSHED",
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
        checksums={},
        state="NOTPUSHED",
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
        checksums={},
        state="NOTPUSHED",
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
        checksums={},
        state="NOTPUSHED",
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


@pytest.fixture
def fixture_test_data_dir():
    return os.path.join(os.path.dirname(__file__), "test_data") + "/"
