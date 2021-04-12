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


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_iib_add_bundles(
    mock_run_entrypoint,
    target_settings,
    operator_push_item_ok,
):
    mock_run_entrypoint.return_value = "some-data"
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], target_settings)
    result = pusher.iib_add_bundles(["bundle1", "bundle2"], ["arch1", "arch2"], "v4.5")

    assert result == "some-data"
    mock_run_entrypoint.assert_called_once_with(
        ("pubtools-iib", "console_scripts", "pubtools-iib-add-bundles"),
        "pubtools-iib-add-bundles",
        [
            "--skip-pulp",
            "--quay-dest-repo",
            "quay.io/some-namespace/operators----index-image",
            "--iib-server",
            "iib-server.com",
            "--iib-krb-principal",
            "some-principal@REDHAT.COM",
            "--quay-user",
            "quay-user",
            "--quay-remote-exec",
            "--quay-ssh-remote-host",
            "127.0.0.1",
            "--quay-ssh-username",
            "ssh-user",
            "--quay-send-umb-msg",
            "--quay-umb-url",
            "some-url1",
            "--quay-umb-url",
            "some-url2",
            "--quay-umb-cert",
            "/etc/pub/umb-pub-cert-key.pem",
            "--quay-umb-client-key",
            "/etc/pub/umb-pub-cert-key.pem",
            "--quay-umb-ca-cert",
            "/etc/pki/tls/certs/ca-bundle.crt",
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
        ],
        {
            "OVERWRITE_FROM_INDEX_TOKEN": "some-token",
            "QUAY_PASSWORD": "quay-pass",
            "SSH_PASSWORD": "ssh-password",
        },
    )


@mock.patch("pubtools._quay.operator_pusher.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_push_operators(
    mock_run_entrypoint,
    mock_add_bundles,
    target_settings,
    operator_push_item_ok,
    operator_push_item_different_version,
):

    mock_run_entrypoint.side_effect = [
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}, {"ocp_version": "4.7"}],
        [{"ocp_version": "4.7"}],
    ]
    mock_add_bundles.side_effect = [
        {"results": "results1"},
        {"results": "results2"},
        {"results": "results3"},
    ]
    pusher = operator_pusher.OperatorPusher(
        [operator_push_item_ok, operator_push_item_different_version], target_settings
    )

    results = pusher.push_operators()

    assert results == {
        "v4.5": {"iib_result": {"results": "results1"}, "signing_keys": ["some-key"]},
        "v4.6": {"iib_result": {"results": "results2"}, "signing_keys": ["some-key"]},
        "v4.7": {"iib_result": {"results": "results3"}, "signing_keys": ["some-key"]},
    }
    assert mock_add_bundles.call_count == 3
    assert mock_add_bundles.call_args_list[0] == mock.call(
        ["some-registry1.com/repo:1.0"], ["some-arch"], "v4.5"
    )
    assert mock_add_bundles.call_args_list[1] == mock.call(
        ["some-registry1.com/repo:1.0"], ["some-arch"], "v4.6"
    )
    assert mock_add_bundles.call_args_list[2] == mock.call(
        ["some-registry1.com/repo:1.0", "some-registry1.com/repo2:5.0.0"],
        ["amd64", "some-arch"],
        "v4.7",
    )
