import os

try:
    import mock
except ImportError:
    from unittest import mock

import pytest

from pubtools._quay.utils.logger import Logger

# flake8: noqa: E501


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
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos={"test_repo": []},
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
        file_type="docker",
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
        file_type="docker",
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
        file_type="docker",
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


@pytest.fixture
def repo_api_data():
    return {
        "trust_enabled": False,
        "description": None,
        "tags": {
            "1": {
                "image_id": None,
                "last_modified": "Wed, 03 Mar 2021 11:23:11 -0000",
                "name": "1",
                "manifest_digest": "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
                "size": None,
            },
            "2": {
                "image_id": None,
                "last_modified": "Wed, 03 Mar 2021 11:22:41 -0000",
                "name": "2",
                "manifest_digest": "sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
                "size": None,
            },
            "3": {
                "image_id": "1a1d7fd200d783bd61e78e9e2fed23c8c1ffcefe54168939c53084f4af7e884e",
                "last_modified": "Wed, 03 Mar 2021 11:22:13 -0000",
                "name": "3",
                "manifest_digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
                "size": 69754778,
            },
            "4": {
                "image_id": "1a1d7fd200d783bd61e78e9e2fed23c8c1ffcefe54168939c53084f4af7e884e",
                "last_modified": "Wed, 03 Mar 2021 11:22:04 -0000",
                "name": "4",
                "manifest_digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
                "size": 69754778,
            },
        },
        "tag_expiration_s": 1209600,
        "is_public": False,
        "is_starred": False,
        "is_free_account": True,
        "kind": "image",
        "name": "repo1",
        "namespace": "name",
        "is_organization": True,
        "state": "NORMAL",
        "can_write": True,
        "status_token": "fghfghfghfghfgh",
        "can_admin": True,
    }


@pytest.fixture
def manifest_list_data():
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 949,
                "digest": "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 949,
                "digest": "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
                "platform": {"architecture": "arm64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 949,
                "digest": "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
                "platform": {"architecture": "arm", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 949,
                "digest": "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
                "platform": {"architecture": "ppc64le", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 949,
                "digest": "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
                "platform": {"architecture": "s390x", "os": "linux"},
            },
        ],
    }


@pytest.fixture
def common_tag_digest_mapping():
    return {
        u"1": [
            u"sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            u"sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            u"sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            u"sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            u"sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            u"sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        ],
        u"2": [
            u"sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            u"sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            u"sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            u"sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            u"sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            u"sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        ],
        u"3": [
            u"sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb"
        ],
        u"4": [
            u"sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd"
        ],
    }


@pytest.fixture
def common_digest_tag_mapping():
    return {
        u"sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb": [
            u"1",
            u"2",
            u"3",
        ],
        u"sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee": [
            u"1",
            u"2",
        ],
        u"sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36": [
            u"1",
            u"2",
        ],
        u"sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd": [
            u"1",
            u"2",
            u"4",
        ],
        u"sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c": [
            u"1",
            u"2",
        ],
        u"sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9": [
            u"1",
            u"2",
        ],
    }
