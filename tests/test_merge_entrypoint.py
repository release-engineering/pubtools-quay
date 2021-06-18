import mock
import pytest
import requests_mock

from pubtools._quay import merge_manifest_list
from .test_ml_merger import old_ml, new_ml, merged_ml


@mock.patch("pubtools._quay.merge_manifest_list.add_args_env_variables")
@mock.patch("pubtools._quay.manifest_list_merger.ManifestListMerger")
@mock.patch("pubtools._quay.manifest_list_merger.ManifestListMerger.merge_manifest_lists")
def test_arg_parser_required_args(mock_merge_manifest_lists, mock_list_merger, mock_set_env_vars):
    required_args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--source-quay-user",
        "src-user",
        "--source-quay-password",
        "src-token",
        "--dest-quay-user",
        "dest-user",
        "--dest-quay-password",
        "dest-token",
    ]
    merge_manifest_list.merge_manifest_list_main(required_args)
    called_args, _ = mock_set_env_vars.call_args

    assert called_args[0].source_ref == "quay.io/repo/souce-image:1"
    assert called_args[0].dest_ref == "quay.io/repo/target-image:1"
    assert called_args[0].source_quay_user == "src-user"
    assert called_args[0].source_quay_password == "src-token"
    assert called_args[0].dest_quay_user == "dest-user"
    assert called_args[0].dest_quay_password == "dest-token"


@mock.patch("pubtools._quay.merge_manifest_list.add_args_env_variables")
@mock.patch("pubtools._quay.manifest_list_merger.ManifestListMerger")
@mock.patch("pubtools._quay.manifest_list_merger.ManifestListMerger.merge_manifest_lists")
def test_arg_parser_missing_required(
    mock_merge_manifest_lists, mock_list_merger, mock_set_env_vars
):
    missing_args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--source-quay-user",
        "src-user",
        "--source-quay-password",
        "src-token",
    ]

    with pytest.raises(SystemExit) as system_error:
        merge_manifest_list.merge_manifest_list_main(missing_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_merge_manifest_lists.assert_not_called()


@mock.patch("pubtools._quay.manifest_list_merger.ManifestListMerger")
@mock.patch("pubtools._quay.manifest_list_merger.ManifestListMerger.merge_manifest_lists")
def test_arg_parser_dest_digest(mock_merge_manifest_lists, mock_list_merger):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image@sha256:dfg5dfgd6f5g6",
        "--source-quay-user",
        "src-user",
        "--source-quay-password",
        "src-token",
        "--dest-quay-user",
        "dest-user",
        "--dest-quay-password",
        "dest-token",
    ]

    with pytest.raises(ValueError, match="Destination must be specified via tag, not digest"):
        merge_manifest_list.merge_manifest_list_main(args)

    mock_merge_manifest_lists.assert_not_called()


@mock.patch("pubtools._quay.manifest_list_merger.ManifestListMerger")
@mock.patch("pubtools._quay.manifest_list_merger.ManifestListMerger.merge_manifest_lists")
def test_arg_parser_missing_password(mock_merge_manifest_lists, mock_list_merger):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--source-quay-user",
        "src-user",
        "--dest-quay-user",
        "dest-user",
    ]

    with pytest.raises(
        ValueError, match="Quay password must be set for both source and dest images"
    ):
        merge_manifest_list.merge_manifest_list_main(args)

    mock_merge_manifest_lists.assert_not_called()


def test_merge_manifest_list_full():
    args = [
        "dummy",
        "--source-ref",
        "quay.io/src/image:1",
        "--dest-ref",
        "quay.io/dest/image:1",
        "--source-quay-user",
        "src-user",
        "--source-quay-password",
        "src-token",
        "--dest-quay-user",
        "dest-user",
        "--dest-quay-password",
        "dest-token",
    ]
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/src/image/manifests/1",
            json=new_ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/dest/image/manifests/1",
            json=old_ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.put("https://quay.io/v2/dest/image/manifests/1", status_code=200)

        merge_manifest_list.merge_manifest_list_main(args)
        assert m.call_count == 3
        sent_ml = m.request_history[-1].json()
        sent_ml["manifests"].sort(key=lambda manifest: manifest["digest"])
        merged_ml["manifests"].sort(key=lambda manifest: manifest["digest"])

        assert sent_ml == merged_ml
