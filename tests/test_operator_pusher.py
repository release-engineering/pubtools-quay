import logging
import mock
import pytest
import requests_mock
import requests

from pubtools._quay import exceptions
from pubtools._quay import quay_client
from pubtools._quay import operator_pusher
from .utils.misc import sort_dictionary_sortable_values, compare_logs, IIBRes

# flake8: noqa: E501


def test_init(target_settings, operator_push_item_ok):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)

    assert pusher.push_items == [operator_push_item_ok]
    assert pusher.task_id == "3"
    assert pusher.target_settings == target_settings
    assert pusher.quay_host == "quay.io"


def test_get_immutable_tag_vr(target_settings, operator_push_item_vr):
    pusher = operator_pusher.OperatorPusher([operator_push_item_vr], "3", target_settings)

    tag = pusher._get_immutable_tag(operator_push_item_vr)
    assert tag == "1.0"


def test_get_immutable_tag_no_vr(target_settings, operator_push_item_no_vr):
    pusher = operator_pusher.OperatorPusher([operator_push_item_no_vr], "3", target_settings)

    tag = pusher._get_immutable_tag(operator_push_item_no_vr)
    assert tag == "1.0000000"


def test_public_bundle_ref(target_settings, operator_push_item_no_vr):
    pusher = operator_pusher.OperatorPusher([operator_push_item_no_vr], "3", target_settings)

    ref = pusher.public_bundle_ref(operator_push_item_no_vr)
    assert ref == "some-registry1.com/repo1:1.0000000"


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_pyxis_get_ocp_versions(
    mock_run_entrypoint, target_settings, operator_push_item_ok, fake_cert_key_paths
):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)

    mock_run_entrypoint.return_value = [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}]
    versions = pusher.pyxis_get_ocp_versions(operator_push_item_ok)

    mock_run_entrypoint.assert_called_once_with(
        ("pubtools-pyxis", "console_scripts", "pubtools-pyxis-get-operator-indices"),
        "pubtools-pyxis-get-operator-indices",
        [
            "--pyxis-server",
            "pyxis-url.com",
            "--pyxis-ssl-crtfile",
            "/path/to/file.crt",
            "--pyxis-ssl-keyfile",
            "/path/to/file.key",
            "--organization",
            "redhat-operators",
            "--ocp-versions-range",
            "v4.5",
        ],
        {},
    )
    assert versions == ["v4.5", "v4.6"]


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_pyxis_get_ocp_versions_no_data(
    mock_run_entrypoint, target_settings, operator_push_item_ok, fake_cert_key_paths
):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)

    mock_run_entrypoint.return_value = []
    with pytest.raises(ValueError, match="Pyxis has returned no OCP.*"):
        versions = pusher.pyxis_get_ocp_versions(operator_push_item_ok)


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_pyxis_generate_mapping(
    mock_run_entrypoint,
    target_settings,
    operator_push_item_ok,
    operator_push_item_different_version,
    fake_cert_key_paths,
):

    mock_run_entrypoint.side_effect = [
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}, {"ocp_version": "4.7"}],
        [{"ocp_version": "4.7"}],
    ]
    pusher = operator_pusher.OperatorPusher(
        [operator_push_item_ok, operator_push_item_different_version], "3", target_settings
    )

    mapping = pusher.version_items_mapping
    assert mock_run_entrypoint.call_count == 2
    assert len(mapping["v4.5"]) == 1
    assert len(mapping["v4.6"]) == 1
    assert len(mapping["v4.7"]) == 2


def test_get_deprecation_list(target_settings, operator_push_item_ok):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)
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
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)

    with requests_mock.Mocker() as m:
        m.get("https://git-server.com/4_7.yml/raw?ref=master", status_code=500)
        with pytest.raises(requests.exceptions.HTTPError, match=".*500.*"):
            deprecation_list = pusher.get_deprecation_list("4.7")


def test_get_deprecation_list_invalid_data(target_settings, operator_push_item_ok):
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)

    with requests_mock.Mocker() as m:
        m.get("https://git-server.com/4_7.yml/raw?ref=master", text="{some-invalid-data}")
        with pytest.raises(TypeError, match=".*not iterable.*"):
            deprecation_list = pusher.get_deprecation_list("4.7")


def test_get_deprecation_list_no_url(target_settings, operator_push_item_ok):
    target_settings["iib_deprecation_list_url"] = None
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)

    deprecation_list = pusher.get_deprecation_list("4.7")

    assert deprecation_list == None


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_iib_add_bundles_str_deprecation_list(
    mock_run_entrypoint, target_settings, operator_push_item_ok
):
    mock_run_entrypoint.return_value = "some-data"
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)
    result = pusher.iib_add_bundles(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "registry.com/rh-osbs/iib-pub-pending:v4.5",
        "bundle3,bundle4",
        ["tag1", "tag2"],
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
            "--build-tag",
            "tag1",
            "--build-tag",
            "tag2",
        ],
        {"OVERWRITE_FROM_INDEX_TOKEN": "some-user:some-pass"},
    )


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_iib_add_bundles_error(mock_run_entrypoint, target_settings, operator_push_item_ok):
    mock_run_entrypoint.side_effect = SystemExit(1)
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)
    result = pusher.iib_add_bundles(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "registry.com/rh-osbs/iib-pub-pending:v4.5",
        "bundle3,bundle4",
        ["tag1", "tag2"],
        pusher.target_settings,
    )

    assert result == False


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_iib_add_bundles_list_deprecation_list(
    mock_run_entrypoint, target_settings, operator_push_item_ok
):
    mock_run_entrypoint.return_value = "some-data"
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)
    result = pusher.iib_add_bundles(
        ["bundle1", "bundle2"],
        ["arch1", "arch2"],
        "registry.com/rh-osbs/iib-pub-pending:v4.5",
        ["bundle3", "bundle4"],
        None,
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
        {"OVERWRITE_FROM_INDEX_TOKEN": "some-user:some-pass"},
    )


@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_iib_remove_operators(mock_run_entrypoint, target_settings, operator_push_item_ok):
    mock_run_entrypoint.return_value = "some-data"
    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)
    result = pusher.iib_remove_operators(
        ["operator1", "operator2"],
        ["arch1", "arch2"],
        "registry.com/rh-osbs/iib-pub-pending:v4.5",
        ["tag1", "tag2"],
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
            "--build-tag",
            "tag1",
            "--build-tag",
            "tag2",
        ],
        {"OVERWRITE_FROM_INDEX_TOKEN": "some-user:some-pass"},
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
    fake_cert_key_paths,
):
    mock_get_deprecation_list.side_effect = [["bundle1", "bundle2"], ["bundle3"], []]

    mock_run_entrypoint.side_effect = [
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}, {"ocp_version": "4.7"}],
        [{"ocp_version": "4.7"}],
    ]
    iib_results = [
        IIBRes(
            "some-registry.com/index-image:5",
            "some-registry.com/index-image@sha256:a1a1",
            ["v4.5-3"],
        ),
        IIBRes(
            "some-registry.com/index-image:6",
            "some-registry.com/index-image@sha256:b2b2",
            ["v4.6-3"],
        ),
        IIBRes(
            "some-registry.com/index-image:7",
            "some-registry.com/index-image@sha256:c3c3",
            ["v4.7-3"],
        ),
    ]
    mock_add_bundles.side_effect = iib_results
    pusher = operator_pusher.OperatorPusher(
        [operator_push_item_ok, operator_push_item_different_version], "3", target_settings
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
        build_tags=["v4.5-3"],
        target_settings=target_settings,
    )
    assert mock_add_bundles.call_args_list[1] == mock.call(
        bundles=["some-registry1.com/repo:1.0"],
        archs=["some-arch"],
        index_image="registry.com/rh-osbs/iib-pub-pending:v4.6",
        deprecation_list=["bundle3"],
        build_tags=["v4.6-3"],
        target_settings=target_settings,
    )
    assert mock_add_bundles.call_args_list[2] == mock.call(
        bundles=["some-registry1.com/repo:1.0", "some-registry1.com/repo2:5.0.0"],
        archs=["amd64", "some-arch"],
        index_image="registry.com/rh-osbs/iib-pub-pending:v4.7",
        deprecation_list=[],
        build_tags=["v4.7-3"],
        target_settings=target_settings,
    )

    pusher.push_index_images(results)

    assert mock_run_tag_images.call_count == 3
    mock_run_tag_images.assert_has_calls(
        [
            mock.call(
                "some-registry.com/index-image:5",
                ["quay.io/some-namespace/operators----index-image:5"],
                True,
                target_settings,
            )
        ]
    )
    mock_run_tag_images.assert_has_calls(
        [
            mock.call(
                "some-registry.com/index-image:6",
                ["quay.io/some-namespace/operators----index-image:6"],
                True,
                target_settings,
            )
        ]
    )
    mock_run_tag_images.assert_has_calls(
        [
            mock.call(
                "some-registry.com/index-image:7",
                ["quay.io/some-namespace/operators----index-image:7"],
                True,
                target_settings,
            )
        ]
    )


@mock.patch("pubtools._quay.operator_pusher.ContainerImagePusher.run_tag_images")
@mock.patch("pubtools._quay.operator_pusher.OperatorPusher.iib_add_bundles")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
@mock.patch("pubtools._quay.operator_pusher.OperatorPusher.get_deprecation_list")
def test_push_operators_not_all_successful(
    mock_get_deprecation_list,
    mock_run_entrypoint,
    mock_add_bundles,
    mock_run_tag_images,
    target_settings,
    operator_push_item_ok,
    operator_push_item_different_version,
    fake_cert_key_paths,
):
    mock_get_deprecation_list.side_effect = [["bundle1", "bundle2"], ["bundle3"], []]

    mock_run_entrypoint.side_effect = [
        [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}, {"ocp_version": "4.7"}],
        [{"ocp_version": "4.7"}],
    ]
    iib_results = [
        IIBRes(
            "some-registry.com/index-image:5",
            "some-registry.com/index-image@sha256:a1a1",
            ["v4.5-3"],
        ),
        None,
        IIBRes(
            "some-registry.com/index-image:7",
            "some-registry.com/index-image@sha256:c3c3",
            ["v4.7-3"],
        ),
    ]
    mock_add_bundles.side_effect = iib_results
    pusher = operator_pusher.OperatorPusher(
        [operator_push_item_ok, operator_push_item_different_version], "3", target_settings
    )

    results = pusher.build_index_images()

    assert mock_get_deprecation_list.call_count == 3
    assert mock_get_deprecation_list.call_args_list[0] == mock.call("v4.5")
    assert mock_get_deprecation_list.call_args_list[1] == mock.call("v4.6")
    assert mock_get_deprecation_list.call_args_list[2] == mock.call("v4.7")

    assert results == {
        "v4.5": {"iib_result": iib_results[0], "signing_keys": ["some-key"]},
        "v4.6": {"iib_result": None, "signing_keys": ["some-key"]},
        "v4.7": {"iib_result": iib_results[2], "signing_keys": ["some-key"]},
    }
    assert mock_add_bundles.call_count == 3
    assert mock_add_bundles.call_args_list[0] == mock.call(
        bundles=["some-registry1.com/repo:1.0"],
        archs=["some-arch"],
        index_image="registry.com/rh-osbs/iib-pub-pending:v4.5",
        deprecation_list=["bundle1", "bundle2"],
        build_tags=["v4.5-3"],
        target_settings=target_settings,
    )
    assert mock_add_bundles.call_args_list[1] == mock.call(
        bundles=["some-registry1.com/repo:1.0"],
        archs=["some-arch"],
        index_image="registry.com/rh-osbs/iib-pub-pending:v4.6",
        deprecation_list=["bundle3"],
        build_tags=["v4.6-3"],
        target_settings=target_settings,
    )
    assert mock_add_bundles.call_args_list[2] == mock.call(
        bundles=["some-registry1.com/repo:1.0", "some-registry1.com/repo2:5.0.0"],
        archs=["amd64", "some-arch"],
        index_image="registry.com/rh-osbs/iib-pub-pending:v4.7",
        deprecation_list=[],
        build_tags=["v4.7-3"],
        target_settings=target_settings,
    )

    pusher.push_index_images(results)

    assert mock_run_tag_images.call_count == 2
    mock_run_tag_images.assert_has_calls(
        [
            mock.call(
                "some-registry.com/index-image:5",
                ["quay.io/some-namespace/operators----index-image:5"],
                True,
                target_settings,
            )
        ]
    )
    mock_run_tag_images.assert_has_calls(
        [
            mock.call(
                "some-registry.com/index-image:7",
                ["quay.io/some-namespace/operators----index-image:7"],
                True,
                target_settings,
            )
        ]
    )


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_get_existing_index_images(
    mock_run_entrypoint,
    mock_quay_client,
    mock_quay_api,
    target_settings,
    operator_push_item_ok,
    manifest_list_data,
    fake_cert_key_paths,
):
    mock_run_entrypoint.return_value = [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}]
    mock_quay_client.get_manifest.return_value = manifest_list_data

    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)
    existing_index_images = pusher.get_existing_index_images(mock_quay_client)
    mock_quay_client.get_manifest.assert_has_calls(
        [mock.call("quay.io/some-namespace/operators----index-image:v4.5", manifest_list=True)]
    )
    mock_quay_client.get_manifest.assert_has_calls(
        [mock.call("quay.io/some-namespace/operators----index-image:v4.6", manifest_list=True)]
    )
    assert sorted(existing_index_images) == [
        (
            "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "v4.5",
            "operators/index-image",
        ),
        (
            "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "v4.6",
            "operators/index-image",
        ),
        (
            "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "v4.5",
            "operators/index-image",
        ),
        (
            "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "v4.6",
            "operators/index-image",
        ),
        (
            "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "v4.5",
            "operators/index-image",
        ),
        (
            "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "v4.6",
            "operators/index-image",
        ),
        (
            "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "v4.5",
            "operators/index-image",
        ),
        (
            "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "v4.6",
            "operators/index-image",
        ),
        (
            "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
            "v4.5",
            "operators/index-image",
        ),
        (
            "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
            "v4.6",
            "operators/index-image",
        ),
    ]


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_get_existing_index_images_raises_401(
    mock_run_entrypoint,
    mock_quay_client,
    mock_quay_api,
    target_settings,
    operator_push_item_ok,
    manifest_list_data,
    fake_cert_key_paths,
):
    mock_run_entrypoint.return_value = [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}]
    mock_quay_client.get_manifest.side_effect = [
        requests.exceptions.HTTPError(response=mock.Mock(status_code=401)),
        manifest_list_data,
    ]

    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)
    existing_index_images = pusher.get_existing_index_images(mock_quay_client)
    mock_quay_client.get_manifest.assert_has_calls(
        [mock.call("quay.io/some-namespace/operators----index-image:v4.5", manifest_list=True)]
    )
    mock_quay_client.get_manifest.assert_has_calls(
        [mock.call("quay.io/some-namespace/operators----index-image:v4.6", manifest_list=True)]
    )
    assert sorted(existing_index_images) == [
        (
            "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "v4.6",
            "operators/index-image",
        ),
        (
            "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "v4.6",
            "operators/index-image",
        ),
        (
            "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "v4.6",
            "operators/index-image",
        ),
        (
            "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "v4.6",
            "operators/index-image",
        ),
        (
            "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
            "v4.6",
            "operators/index-image",
        ),
    ]


@mock.patch("pubtools._quay.push_docker.QuayClient")
@mock.patch("pubtools._quay.push_docker.QuayApiClient")
@mock.patch("pubtools._quay.operator_pusher.run_entrypoint")
def test_get_existing_index_images_raises_500(
    mock_run_entrypoint,
    mock_quay_client,
    mock_quay_api,
    target_settings,
    operator_push_item_ok,
    manifest_list_data,
    fake_cert_key_paths,
):
    mock_run_entrypoint.return_value = [{"ocp_version": "4.5"}, {"ocp_version": "4.6"}]
    mock_quay_client.get_manifest.side_effect = [
        requests.exceptions.HTTPError("500", response=mock.Mock(status_code=500)),
        manifest_list_data,
    ]

    pusher = operator_pusher.OperatorPusher([operator_push_item_ok], "3", target_settings)
    with pytest.raises(requests.exceptions.HTTPError, match=".*500.*"):
        existing_index_images = pusher.get_existing_index_images(mock_quay_client)
