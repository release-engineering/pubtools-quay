import os

try:
    import mock
except ImportError:
    from unittest import mock

import pytest
from six import PY3

from pubtools._quay.utils.logger import Logger
from .utils.caplog_compat import CapturelogWrapper

# flake8: noqa: E501


@pytest.fixture
def caplog(caplog):
    # Wrapper to make caplog behave the same on py2 and py3.

    if PY3:
        # In Python 3, you just get exactly the usual pytest caplog fixture
        # with no changes.
        return caplog

    # In Python 2, we're using pytest-catchlog instead (due to no pytest version
    # compatible with python 2.6 having caplog). The API is similar but not
    # identical. In that case, wrap it to patch over some incompatibilities.
    return CapturelogWrapper(caplog)


class MockContainerPushItem(object):
    """ContainerPushItem used for testing."""

    def __init__(self, **kwargs):
        """Init ContainerPushItem with all args passed here."""
        self.errors = {}
        self.repos = {}
        self.external_repos = {}
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
        claims_signing_key="some-key",
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
def container_push_item_external_repos():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos={"test_repo": []},
        external_repos={"external/repo": []},
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
        claims_signing_key="some-key",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "destination": {"tags": {"repo": ["tag1"]}},
            "tags": {
                "test_repo": ["latest-test-tag", "1.0"],
                "external/repo": ["latest-test-tag", "1.0"],
            },
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
        claims_signing_key="some-key",
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
        claims_signing_key="some-key",
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
        claims_signing_key="some-key",
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
        claims_signing_key="some-key",
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
        claims_signing_key="some-key",
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
            "arch": "some-arch",
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
        claims_signing_key="some-key",
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
        claims_signing_key="some-key",
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
def operator_push_item_unknown_op_type():
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
        claims_signing_key="some-key",
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
        claims_signing_key="some-key",
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
def v2s2_manifest_data():
    return {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 5830,
            "digest": "sha256:5f88c70a8b703ed93f24c24a809f6c7838105642dd6fb0a19d1f873450304627",
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": 76421592,
                "digest": "sha256:eae19a56e9c600eb0a59816d9d0ad7065824a34a13be60469084304fc7170334",
            },
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": 1811,
                "digest": "sha256:be73321c79565b4e2fdf9f55ba6333e5d50a1bcf583db3b41be45a9be7d82431",
            },
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": 4280307,
                "digest": "sha256:c06d2750af3cc462e5f8e34eccb0fdd350b28d8cd3b72b86bbf4d28e4a40e6ea",
            },
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": 9608840,
                "digest": "sha256:457122c845c27bd616c9f80748f1fa19f3d69783957448b3eca30cea7ed9a0a0",
            },
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": 96318592,
                "digest": "sha256:899560bde2837f603312932d5134a4bb3621e328797895233da54e9d5336911f",
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
        u"3": [u"sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb"],
        u"4": [u"sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd"],
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


@pytest.fixture
def target_settings():
    return {
        "docker_settings": {
            "docker_container_signing_enabled": True,
            "docker_reference_registry": [
                "some-registry1.com",
                "some-registry2.com",
            ],
            "docker_reference_registry_connection_attrs": {"verify": False},
            "umb_url": "some-url",
            "umb_urls": ["some-url1", "some-url2"],
        },
        "iib_index_image": "registry.com/rh-osbs/iib-pub-pending",
        "iib_krb_ktfile": "/etc/pub/some.keytab",
        "iib_krb_principal": "some-principal@REDHAT.COM",
        "iib_organization": "redhat-operators",
        "iib_server": "iib-server.com",
        "iib_deprecation_list_url": "https://git-server.com",
        "max_concurrent": 2,
        "pyxis_server": "pyxis-url.com",
        "source_quay_api_token": "src-quay-token",
        "dest_quay_api_token": "dest-quay-token",
        "quay_namespace": "some-namespace",
        "quay_operator_repository": "operators/index-image",
        "source_quay_password": "src-quay-pass",
        "source_quay_user": "src-quay-user",
        "dest_quay_password": "dest-quay-pass",
        "dest_quay_user": "dest-quay-user",
        "semaphore_components": [[76, "quay"]],
        "semaphore_url": "semaphore-url.com",
        "ssl_validation": False,
        "quay_host": "quay.io/",
        "ssh_remote_host": "127.0.0.1",
        "ssh_user": "ssh-user",
        "ssh_password": "ssh-password",
        "iib_overwrite_from_index": True,
        "iib_overwrite_from_index_token": "some-token",
    }


@pytest.fixture
def container_source_push_item():
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
        claims_signing_key="some-key",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "destination": {"tags": {"repo": ["tag1"]}},
            "tags": {"target/repo": ["latest-test-tag", "1.0"]},
            "v_r": "1.0",
            "pull_url": "some-registry/src/repo:1",
            "build": {"extra": {"image": {"sources_for_nvr": "some-src"}}},
        },
    )


@pytest.fixture
def container_multiarch_push_item():
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
        claims_signing_key="some-key",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "destination": {"tags": {"repo": ["tag1"]}},
            "tags": {"target/repo": ["latest-test-tag"]},
            "v_r": "1.0",
            "pull_url": "some-registry/src/repo:1",
            "build": {},
        },
    )


@pytest.fixture
def operator_push_item_vr():
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
        claims_signing_key="some-key",
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
            "tags": {"repo1": ["latest-test-tag", "1.0", "1.0000000"]},
            "v_r": "1.0",
        },
    )


@pytest.fixture
def operator_push_item_no_vr():
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
        claims_signing_key="some-key",
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
            "tags": {"repo1": ["latest-test-tag", "1.0", "1.0000000"]},
            "v_r": "2.0",
        },
    )


@pytest.fixture
def operator_push_item_different_version():
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
        claims_signing_key="some-key",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "com.redhat.openshift.versions": "v4.7",
            "op_type": "bundle",
            "build": {"build_id": 123456},
            "destination": {"tags": {"repo": ["tag3", "tag4"]}},
            "tags": {"repo2": ["latest-test-tag", "5.0.0"]},
            "v_r": "5.0",
            "arch": "x86_64",
        },
    )


@pytest.fixture
def claim_messages():
    return [
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id1",
            "manifest_digest": "sha256:f4f4f4f",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id2",
            "manifest_digest": "sha256:a2a2a2a",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id3",
            "manifest_digest": "sha256:b3b3b3b",
            "repo": "some-dest-repo",
            "image_name": "image",
            "docker_reference": "registry.com/image:2",
            "created": "2021-03-19T14:45:23.128632Z",
        },
    ]


@pytest.fixture
def existing_signatures():
    return [
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id1",
            "manifest_digest": "sha256:f4f4f4f",
            "repo": "some-dest-repo",
            "image_name": "image",
            "reference": "registry.com/image:1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id2",
            "manifest_digest": "sha256:a2a2a2a",
            "repo": "some-dest-repo",
            "image_name": "image",
            "reference": "registry.com/image:1",
            "created": "2021-03-19T14:45:23.128632Z",
        },
        {
            "sig_key_id": "key1",
            "claim_file": "some-encode",
            "pub_task_id": "1",
            "request_id": "id3",
            "manifest_digest": "sha256:c4c4c4c4",
            "repo": "some-dest-repo",
            "image_name": "image",
            "reference": "registry.com/image:2",
            "created": "2021-03-19T14:45:23.128632Z",
        },
    ]


@pytest.fixture
def signed_messages():
    return [
        {
            "errors": [],
            "manifest_digest": "sha256:f4f4f4f",
            "pub_task_id": 1,
            "repo": "some-dest-repo",
            "request_id": "id1",
            "request_received_time": "2021-03-19T15:25:37.545759",
            "requested_by": "amcnamar",
            "sig_key_id": "key1",
            "sig_keyname": "some-keyname",
            "signed_claim": "binary-data1",
            "signing_server_requested": "2021-03-19T15:25:37.756325",
            "signing_server_responded": "2021-03-19T15:25:38.135038",
            "signing_status": "success",
        },
        {
            "errors": [],
            "manifest_digest": "sha256:a2a2a2a",
            "pub_task_id": 1,
            "repo": "some-dest-repo",
            "request_id": "id2",
            "request_received_time": "2021-03-19T15:25:37.545759",
            "requested_by": "amcnamar",
            "sig_key_id": "key1",
            "sig_keyname": "some-keyname",
            "signed_claim": "binary-data2",
            "signing_server_requested": "2021-03-19T15:25:37.756325",
            "signing_server_responded": "2021-03-19T15:25:38.135038",
            "signing_status": "success",
        },
        {
            "errors": [],
            "manifest_digest": "sha256:b3b3b3b",
            "pub_task_id": 1,
            "repo": "some-dest-repo",
            "request_id": "id3",
            "request_received_time": "2021-03-19T15:25:37.545759",
            "requested_by": "amcnamar",
            "sig_key_id": "key1",
            "sig_keyname": "some-keyname",
            "signed_claim": "binary-data3",
            "signing_server_requested": "2021-03-19T15:25:37.756325",
            "signing_server_responded": "2021-03-19T15:25:38.135038",
            "signing_status": "success",
        },
    ]


@pytest.fixture
def error_signed_messages():
    return [
        {
            "errors": ["some_error1"],
            "manifest_digest": "sha256:f4f4f4f",
            "pub_task_id": 1,
            "repo": "some-dest-repo",
            "request_id": "id1",
            "request_received_time": "2021-03-19T15:25:37.545759",
            "requested_by": "amcnamar",
            "sig_key_id": "key1",
            "sig_keyname": "some-keyname",
            "signed_claim": "binary-data1",
            "signing_server_requested": "2021-03-19T15:25:37.756325",
            "signing_server_responded": "2021-03-19T15:25:38.135038",
            "signing_status": "success",
        },
        {
            "errors": ["some_error2"],
            "manifest_digest": "sha256:a2a2a2a",
            "pub_task_id": 1,
            "repo": "some-dest-repo",
            "request_id": "id2",
            "request_received_time": "2021-03-19T15:25:37.545759",
            "requested_by": "amcnamar",
            "sig_key_id": "key1",
            "sig_keyname": "some-keyname",
            "signed_claim": "binary-data2",
            "signing_server_requested": "2021-03-19T15:25:37.756325",
            "signing_server_responded": "2021-03-19T15:25:38.135038",
            "signing_status": "success",
        },
        {
            "errors": [],
            "manifest_digest": "sha256:b3b3b3b",
            "pub_task_id": 1,
            "repo": "some-dest-repo",
            "request_id": "id3",
            "request_received_time": "2021-03-19T15:25:37.545759",
            "requested_by": "amcnamar",
            "sig_key_id": "key1",
            "sig_keyname": "some-keyname",
            "signed_claim": "binary-data3",
            "signing_server_requested": "2021-03-19T15:25:37.756325",
            "signing_server_responded": "2021-03-19T15:25:38.135038",
            "signing_status": "success",
        },
    ]


@pytest.fixture
def container_signing_push_item():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos={"namespace/repo1": [], "namespace/repo2": []},
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
        claims_signing_key="some-key",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "destination": {"tags": {"repo": ["tag1"]}},
            "tags": {"target/repo1": ["tag1", "tag2"], "target/repo2": ["tag3"]},
            "v_r": "1.0",
            "pull_url": "some-registry/src/repo:1",
            "build": {},
        },
    )


@pytest.fixture
def operator_signing_push_item():
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
        claims_signing_key="some-key",
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
            "tags": {"repo1": ["latest-test-tag", "1.0"], "repo2": ["tag2"]},
            "pull_url": "some-registry/src/repo:1",
            "v_r": "1.0",
        },
    )


@pytest.fixture
def signing_manifest_list_data():
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
        ],
    }


@pytest.fixture
def operator_push_item_errors():
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
        claims_signing_key="some-key",
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
            "arch": "some-arch",
        },
        errors={"fake-error1": "fake-error1 message"},
    )


@pytest.fixture
def operator_push_item_no_op_type():
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
        claims_signing_key="some-key",
        metadata={
            "pull_data": {
                "registry": "test-regitry",
                "repo": "test-repo",
                "tag": "test-tag",
            },
            "com.redhat.openshift.versions": "v4.5",
            "build": {"build_id": 123456},
            "destination": {"tags": {"repo": ["tag1", "tag2"]}},
            "tags": {"repo": ["latest-test-tag", "1.0"]},
            "v_r": "1.0",
            "arch": "some-arch",
        },
    )


@pytest.fixture
def container_push_item_correct_repos():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="push_item_filename",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="push_item_origin",
        repos={"namespace/repo1": []},
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
        claims_signing_key="some-key",
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
def tag_docker_push_item_add():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="v1.5",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="metadata",
        repos={"namespace/test_repo": ["v1.6", "v1.7"]},
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
        claims_signing_key="some-key",
        metadata={
            "destination": {"tags": ["v1.6", "v1.7"]},
            "tag_source": "v1.5",
            "add_tags": ["v1.6", "v1.7"],
            "remove_tags": [],
            "archs": ["arch1", "arch2"],
            "exclude_archs": False,
            "new_method": True,
        },
    )


@pytest.fixture
def tag_docker_push_item_remove_no_src():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="v1.8,v1.9",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="metadata",
        repos={"namespace/test_repo2": []},
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
        claims_signing_key="some-key",
        metadata={
            "destination": {"tags": []},
            "tag_source": "",
            "add_tags": [],
            "remove_tags": ["v1.8", "v1.9"],
            "archs": ["arch1", "arch2"],
            "exclude_archs": False,
            "new_method": True,
        },
    )


@pytest.fixture
def tag_docker_push_item_remove_src():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="v1.8,v1.9",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="metadata",
        repos={"namespace/test_repo2": []},
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
        claims_signing_key="some-key",
        metadata={
            "destination": {"tags": []},
            "tag_source": "v1.5",
            "add_tags": [],
            "remove_tags": ["v1.8", "v1.9"],
            "archs": ["arch1", "arch2"],
            "exclude_archs": False,
            "new_method": True,
        },
    )


@pytest.fixture
def tag_docker_push_item_mixed():
    return MockContainerPushItem(
        file_path="push_item_filepath",
        file_name="v1.5",
        file_type="docker",
        file_size=0,
        file_info=None,
        origin="metadata",
        repos={"namespace/test_repo3": []},
        build="push_item_build",
        checksums={},
        state="NOTPUSHED",
        claims_signing_key="some-key",
        metadata={
            "destination": {"tags": ["v1.6", "v1.7"]},
            "tag_source": "v1.5",
            "add_tags": ["v1.6", "v1.7"],
            "remove_tags": ["v1.8", "v1.9"],
            "archs": ["arch1", "arch2"],
            "exclude_archs": False,
            "new_method": True,
        },
    )
