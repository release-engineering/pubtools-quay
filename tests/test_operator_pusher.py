import logging
import mock
import pytest
import requests_mock
import requests

from pubtools._quay import exceptions
from pubtools._quay import quay_client
from pubtools._quay import operator_pusher
from .utils.misc import sort_dictionary_sortable_values, compare_logs

# flake8: noqa: E501


def test_init(target_settings, operator_push_item_ok):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)

    assert pusher.push_items == [operator_push_item_ok]
    assert pusher.target_settings == target_settings
    assert pusher.quay_host == "quay.io"


def test_get_immutable_tag_vr(target_settings, operator_push_item_vr):
    pusher = operator_pusher.OperatorPusher([operator_push_item_vr], target_settings)

    tag = pusher._get_immutable_tag(operator_push_item_vr)
    assert tag == "1.0"


def test_get_immutable_tag_no_vr(target_settings, operator_push_item_no_vr):
    pusher = operator_pusher.OperatorPusher([operator_push_item_no_vr], target_settings)

    tag = pusher._get_immutable_tag(operator_push_item_no_vr)
    assert tag == "1.0000000"


def test_public_bundle_ref(target_settings, operator_push_item_no_vr):
    pusher = operator_pusher.OperatorPusher([operator_push_item_no_vr], target_settings)

    ref = pusher.public_bundle_ref(operator_push_item_no_vr)
    assert ref == "some-registry1.com/repo1:1.0000000"


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_pyxis_get_ocp_versions(
    mock_run_entrypoint,
    target_settings,
    operator_push_item_ok,
):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)

    mock_run_entrypoint.return_value = [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}]
    versions = pusher.pyxis_get_ocp_versions(operator_push_item_ok)

    mock_run_entrypoint.assert_called_once_with(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-operator-indices"),
        "pubtools-pyxis-get-operator-indices",
        [
            "--pyxis-server",
            "pyxis-url.com",
            "--pyxis-krb-principal",
            "some-principal@REDHAT.COM",
            "--organization",
            "redhat-operators",
            "--ocp-versions-range",
            "v4.5",
            "--pyxis-krb-ktfile",
            "/etc/pub/some.keytab",
        ],
        {},
    )
    assert versions == ["v4.5", "v4.6"]


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_pyxis_get_ocp_versions_no_data(
    mock_run_entrypoint,
    target_settings,
    operator_push_item_ok,
):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)

    mock_run_entrypoint.return_value = []
    with pytest.raises(ValueError, match="Pyxis has returned no OCP.*"):
        versions = pusher.pyxis_get_ocp_versions(operator_push_item_ok)


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_pyxis_generate_mapping(
    mock_run_entrypoint,
    target_settings,
    operator_push_item_ok,
    operator_push_item_different_version,
):

    mock_run_entrypoint.side_effect = [
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}, {"ocp_version": "4.7"}],
        [{"ocp_version": "4.7"}],
    ]
    pusher = operator_pusher.OperatorPusher(
        [operator_push_item_ok, operator_push_item_different_version], target_settings
    )

    mapping = pusher.generate_version_items_mapping()
    assert mock_run_entrypoint.call_count == 2
    assert len(mapping["v4.5"]) == 1
    assert len(mapping["v4.6"]) == 1
    assert len(mapping["v4.7"]) == 2


def test_get_deprecation_list(target_settings, operator_push_item_ok):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)
    with open("tests/test_data/deprecation_list_data.yaml", "r") as f:
        deprecate_data = f.read()

    with requests_mock.Mocker() as m:
        m.get("https://git-server.com/4_7.yml/raw?ref=master", text=deprecate_data)
        deprecation_list = pusher.get_deprecation_list("4.7")

    assert deprecation_list == [
        "some-registry1.com/bundle/path@sha256:a1a1a1",
        "some-registry1.com/bundle/path@sha256:b2b2b2",
    ]


def test_get_deprecation_list_server_error(target_settings, operator_push_item_ok, caplog):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)

    with requests_mock.Mocker() as m:
        m.get("https://git-server.com/4_7.yml/raw?ref=master", status_code=500)
        with pytest.raises(requests.exceptions.HTTPError, match=".*500.*"):
            deprecation_list = pusher.get_deprecation_list("4.7")


def test_get_deprecation_list_invalid_data(target_settings, operator_push_item_ok):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)

    with requests_mock.Mocker() as m:
        m.get("https://git-server.com/4_7.yml/raw?ref=master", text="{some-invalid-data}")
        with pytest.raises(TypeError, match=".*not iterable.*"):
            deprecation_list = pusher.get_deprecation_list("4.7")


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_iib_add_bundles_str_deprecation_list(
    mock_run_entrypoint,
    target_settings,
    operator_push_item_ok,
):
    mock_run_entrypoint.return_value = "some-data"
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)
    result = pusher.iib_add_bundles(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "registry.com/rh-osbs/iib-pub-pending:v4.5",
        "bundle3,bundle4",
        pusher.target_settings,
    )

    assert result == "some-data"
    mock_run_entrypoint.assert_called_once_with(
        ("pubtools-iib", "console_scripts", "pubtools-iib-add-bundles"),
        "pubtools-iib-add-bundles",
        [
            "--skip-pulp",
            "--iib-server",
            "iib-server.com",
            "--iib-krb-principal",
            "some-principal@REDHAT.COM",
            "--overwrite-from-index",
            "--iib-krb-ktfile",
            "/etc/pub/some.keytab",
            "--index-image",
            "registry.com/rh-osbs/iib-pub-pending:v4.5",
            "--bundle",
            "bundle1",
            "--bundle",
            "bundle2",
            "--arch",
            "arch1",
            "--arch",
            "arch2",
            "--deprecation-list",
            "bundle3,bundle4",
        ],
        {"OVERWRITE_FROM_INDEX_TOKEN": "some-token"},
    )


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_iib_add_bundles_list_deprecation_list(
    mock_run_entrypoint,
    target_settings,
    operator_push_item_ok,
):
    mock_run_entrypoint.return_value = "some-data"
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)
    result = pusher.iib_add_bundles(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "registry.com/rh-osbs/iib-pub-pending:v4.5",
        ["bundle3", "bundle4"],
        pusher.target_settings,
    )

    assert result == "some-data"
    mock_run_entrypoint.assert_called_once_with(
        ("pubtools-iib", "console_scripts", "pubtools-iib-add-bundles"),
        "pubtools-iib-add-bundles",
        [
            "--skip-pulp",
            "--iib-server",
            "iib-server.com",
            "--iib-krb-principal",
            "some-principal@REDHAT.COM",
            "--overwrite-from-index",
            "--iib-krb-ktfile",
            "/etc/pub/some.keytab",
            "--index-image",
            "registry.com/rh-osbs/iib-pub-pending:v4.5",
            "--bundle",
            "bundle1",
            "--bundle",
            "bundle2",
            "--arch",
            "arch1",
            "--arch",
            "arch2",
            "--deprecation-list",
            "bundle3,bundle4",
        ],
        {"OVERWRITE_FROM_INDEX_TOKEN": "some-token"},
    )


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_iib_remove_operators(
    mock_run_entrypoint,
    target_settings,
    operator_push_item_ok,
):
    mock_run_entrypoint.return_value = "some-data"
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)
    result = pusher.iib_remove_operators(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "registry.com/rh-osbs/iib-pub-pending:v4.5",
        pusher.target_settings,
    )

    assert result == "some-data"
    mock_run_entrypoint.assert_called_once_with(
        ("pubtools-iib", "console_scripts", "pubtools-iib-remove-operators"),
        "pubtools-iib-remove-operators",
        [
            "--skip-pulp",
            "--iib-server",
            "iib-server.com",
            "--iib-krb-principal",
            "some-principal@REDHAT.COM",
            "--overwrite-from-index",
            "--iib-krb-ktfile",
            "/etc/pub/some.keytab",
            "--index-image",
            "registry.com/rh-osbs/iib-pub-pending:v4.5",
            "--operator",
            "operator1",
            "--operator",
            "operator2",
            "--arch",
            "arch1",
            "--arch",
            "arch2",
        ],
        {"OVERWRITE_FROM_INDEX_TOKEN": "some-token"},
    )


@mock.patch("pubtools._quay.operator_pusher.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.operator_pusher.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
@mock.patch("pubtools._quay.operator_pusher.OperatorPusher.get_deprecation_list")
def test_push_operators(
    mock_get_deprecation_list,
    mock_run_entrypoint,
    mock_add_bundles,
    mock_run_tag_images,
    target_settings,
    operator_push_item_ok,
    operator_push_item_different_version,
):
    class IIBRes:
        def __init__(self, index_image):
            self.index_image = index_image

    mock_get_deprecation_list.side_effect = [["bundle1", "bundle2"], ["bundle3"], []]

    mock_run_entrypoint.side_effect = [
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}, {"ocp_version": "4.7"}],
        [{"ocp_version": "4.7"}],
    ]
    iib_results = [
        IIBRes("some-registry.com/index-image:5"),
        IIBRes("some-registry.com/index-image:6"),
        IIBRes("some-registry.com/index-image:7"),
    ]
    mock_add_bundles.side_effect = iib_results
    pusher = operator_pusher.OperatorPusher(
        [operator_push_item_ok, operator_push_item_different_version], target_settings
    )

    results = pusher.build_index_images()

    assert mock_get_deprecation_list.call_count == 3
    assert mock_get_deprecation_list.call_args_list[0] == mock.call("v4.5")
    assert mock_get_deprecation_list.call_args_list[1] == mock.call("v4.6")
    assert mock_get_deprecation_list.call_args_list[2] == mock.call("v4.7")

    assert results == {
        "v4.5": {"iib_result": iib_results[0], "signing_keys": ["some-key"]},
        "v4.6": {"iib_result": iib_results[1], "signing_keys": ["some-key"]},
        "v4.7": {"iib_result": iib_results[2], "signing_keys": ["some-key"]},
    }
    assert mock_add_bundles.call_count == 3
    assert mock_add_bundles.call_args_list[0] == mock.call(
        bundles=["some-registry1.com/repo:1.0"],
        archs=["some-arch"],
        index_image="registry.com/rh-osbs/iib-pub-pending:v4.5",
        deprecation_list=["bundle1", "bundle2"],
        target_settings=target_settings,
    )
    assert mock_add_bundles.call_args_list[1] == mock.call(
        bundles=["some-registry1.com/repo:1.0"],
        archs=["some-arch"],
        index_image="registry.com/rh-osbs/iib-pub-pending:v4.6",
        deprecation_list=["bundle3"],
        target_settings=target_settings,
    )
    assert mock_add_bundles.call_args_list[2] == mock.call(
        bundles=["some-registry1.com/repo:1.0", "some-registry1.com/repo2:5.0.0"],
        archs=["amd64", "some-arch"],
        index_image="registry.com/rh-osbs/iib-pub-pending:v4.7",
        deprecation_list=[],
        target_settings=target_settings,
    )

    pusher.push_index_images(results)

    assert mock_run_tag_images.call_count == 3
    assert mock_run_tag_images.call_args_list[0] == mock.call(
        "some-registry.com/index-image:5",
        ["quay.io/some-namespace/operators----index-image:5"],
        True,
        target_settings,
    )
    assert mock_run_tag_images.call_args_list[1] == mock.call(
        "some-registry.com/index-image:6",
        ["quay.io/some-namespace/operators----index-image:6"],
        True,
        target_settings,
    )
    assert mock_run_tag_images.call_args_list[2] == mock.call(
        "some-registry.com/index-image:7",
        ["quay.io/some-namespace/operators----index-image:7"],
        True,
        target_settings,
    )
