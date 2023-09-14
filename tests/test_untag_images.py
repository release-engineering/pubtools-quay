import json
import logging
import mock
import pytest
import requests_mock
import requests

from pubtools._quay import untag_images
from .utils.misc import compare_logs

# flake8: noqa: E501


@mock.patch("pubtools._quay.untag_images.untag_images")
def test_arg_constructor_required_args(mock_untag_images):
    required_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--quay-api-token",
        "some-token",
    ]
    untag_images.untag_images_main(required_args)
    _, called_args = mock_untag_images.call_args

    assert called_args["references"] == ["quay.io/repo/some-image:1"]
    assert called_args["quay_api_token"] == "some-token"


@mock.patch.dict("os.environ", {"QUAY_PASSWORD": "robot_token", "QUAY_API_TOKEN": "api_token"})
@mock.patch("pubtools._quay.untag_images.untag_images")
def test_arg_constructor_all_args(mock_untag_images):
    all_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--remove-last",
        "--quay-user",
        "some_user",
    ]
    untag_images.untag_images_main(all_args)
    _, called_args = mock_untag_images.call_args

    assert called_args["references"] == ["quay.io/repo/some-image:1"]
    assert called_args["remove_last"] == True
    assert called_args["quay_user"] == "some_user"
    assert called_args["quay_password"] == "robot_token"
    assert called_args["quay_api_token"] == "api_token"


@mock.patch("pubtools._quay.untag_images.untag_images")
def test_args_missing_reference(mock_untag_images):
    wrong_args = [
        "dummy",
        "--quay-api-token",
        "some-token",
    ]

    with pytest.raises(SystemExit) as system_error:
        untag_images.untag_images_main(wrong_args)

    assert system_error.type == SystemExit
    assert system_error.value.code == 2
    mock_untag_images.assert_not_called()


@mock.patch("pubtools._quay.untag_images.untag_images")
def test_args_missing_api_token(mock_untag_images):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
    ]

    with pytest.raises(ValueError, match="--quay-api-token must be specified"):
        untag_images.untag_images_main(wrong_args)

    mock_untag_images.assert_not_called()


@mock.patch("pubtools._quay.untag_images.ImageUntagger")
def test_args_incorrect_digest_reference(mock_image_untagger):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image@sha256:s5df6sd5f",
        "--quay-api-token",
        "some-token",
    ]

    with pytest.raises(ValueError, match="All references must be specified via tag, not digest"):
        untag_images.untag_images_main(wrong_args)

    mock_image_untagger.assert_not_called()


@mock.patch("pubtools._quay.untag_images.ImageUntagger")
def test_args_missing_quay_credential(mock_image_untagger):
    wrong_args = [
        "dummy",
        "--reference",
        "quay.io/repo/some-image:1",
        "--quay-api-token",
        "some-token",
        "--quay-user",
        "some_user",
    ]

    with pytest.raises(ValueError, match="Both user and password must be.*"):
        untag_images.untag_images_main(wrong_args)

    mock_image_untagger.assert_not_called()


@mock.patch("pubtools._quay.image_untagger.SecurityManifestPusher.cosign_triangulate_image")
def test_full_run_remove_last(
    mock_triangulate, manifest_list_data, v2s2_manifest_data, caplog, hookspy
):
    args = [
        "dummy",
        "--reference",
        "quay.io/name/repo1:1",
        "--reference",
        "quay.io/name/repo1:2",
        "--quay-api-token",
        "some-token",
        "--remove-last",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
    ]
    caplog.set_level(logging.INFO)
    repo_tags = {"name": "repo1", "tags": ["1", "2", "3", "4"]}

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/name/repo1/tags/list",
            json=repo_tags,
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/1",
            text=json.dumps(manifest_list_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/2",
            text=json.dumps(manifest_list_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/3",
            text=json.dumps(v2s2_manifest_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/4",
            text=json.dumps(v2s2_manifest_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.delete("https://quay.io/api/v1/repository/name/repo1/tag/1")
        m.delete("https://quay.io/api/v1/repository/name/repo1/tag/2")
        untag_images.untag_images_main(args)

        expected_lost_images = [
            "quay.io/name/repo1@sha256:836b8281def8a913eb3f1aeb4d12d372d77e11fb4bc5ebffe46a55552af5fc1f",
            "quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
            "quay.io/name/repo1@sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
            "quay.io/name/repo1@sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        ]

        assert m.call_count == 16

        expected_logs = [
            "Started untagging operation with the following references: .*quay.io/name/repo1:1.*quay.io/name/repo1:2.*",
            "Gathering tags and digests of repository 'name/repo1'",
            "Getting cosign images of 6 images",
            "0 cosign images were found for the 6 images",
            "Getting cosign images of 0 images",
            "Following images won't be referencable by tag: "
            ".*quay.io/name/repo1@sha256:836b8281def8a913eb3f1aeb4d12d372d77e11fb4bc5ebffe46a55552af5fc1f.*"
            ".*quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee.*"
            ".*quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9.*"
            ".*quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c.*"
            ".*quay.io/name/repo1@sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb.*"
            ".*quay.io/name/repo1@sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd.*",
            "Removing tag '1' from repository 'name/repo1'",
            "Removing tag '2' from repository 'name/repo1'",
            "Untagging operation succeeded",
        ]
        compare_logs(caplog, expected_logs)

    assert hookspy == [
        ("task_start", {}),
        (
            "quay_images_untagged",
            {
                "lost_refs": [
                    "quay.io/name/repo1@sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
                    "quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
                    "quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
                    "quay.io/name/repo1@sha256:836b8281def8a913eb3f1aeb4d12d372d77e11fb4bc5ebffe46a55552af5fc1f",
                    "quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
                    "quay.io/name/repo1@sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
                ],
                "untag_refs": ["quay.io/name/repo1:1", "quay.io/name/repo1:2"],
            },
        ),
        ("task_stop", {"failed": False}),
    ]


def test_full_run_no_lost_digests(manifest_list_data, v2s2_manifest_data, caplog):
    args = [
        "dummy",
        "--reference",
        "quay.io/name/repo1:1",
        "--quay-api-token",
        "some-token",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
    ]
    caplog.set_level(logging.INFO)
    repo_tags = {"name": "repo1", "tags": ["1", "2", "3", "4", "5"]}

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/name/repo1/tags/list",
            json=repo_tags,
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/1",
            text=json.dumps(manifest_list_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/2",
            text=json.dumps(manifest_list_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/3",
            text=json.dumps(v2s2_manifest_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/4",
            text=json.dumps(v2s2_manifest_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        response = mock.MagicMock()
        response.status_code = 404
        m.register_uri(
            "GET",
            "https://quay.io/v2/name/repo1/manifests/5",
            exc=requests.exceptions.HTTPError("not found", response=response),
        )
        m.delete("https://quay.io/api/v1/repository/name/repo1/tag/1")
        untag_images.untag_images_main(args)

        assert m.call_count == 15

        expected_logs = [
            "Started untagging operation with the following references: .*quay.io/name/repo1:1.*",
            "Gathering tags and digests of repository 'name/repo1'",
            "No images will be lost by this untagging operation",
            "Removing tag '1' from repository 'name/repo1'",
            "Untagging operation succeeded",
        ]
        compare_logs(caplog, expected_logs)


@mock.patch("pubtools._quay.image_untagger.SecurityManifestPusher.cosign_triangulate_image")
def test_full_run_last_error(mock_triangulate, manifest_list_data, v2s2_manifest_data, caplog):
    args = [
        "dummy",
        "--reference",
        "quay.io/name/repo1:1",
        "--reference",
        "quay.io/name/repo1:2",
        "--quay-api-token",
        "some-token",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
    ]
    caplog.set_level(logging.INFO)
    repo_tags = {"name": "repo1", "tags": ["1", "2", "3", "4"]}

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/name/repo1/tags/list",
            json=repo_tags,
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/1",
            text=json.dumps(manifest_list_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/2",
            text=json.dumps(manifest_list_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/3",
            text=json.dumps(v2s2_manifest_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )
        m.get(
            "https://quay.io/v2/name/repo1/manifests/4",
            text=json.dumps(v2s2_manifest_data, sort_keys=True),
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        expected_err_msg = (
            "Following images .*"
            ".*quay.io/name/repo1@sha256:836b8281def8a913eb3f1aeb4d12d372d77e11fb4bc5ebffe46a55552af5fc1f.*"
            ".*quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee.*"
            ".*quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9.*"
            ".*quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c.*"
            ".*quay.io/name/repo1@sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb.*"
            ".*quay.io/name/repo1@sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd.*"
        )

        with pytest.raises(ValueError, match=expected_err_msg):
            untag_images.untag_images_main(args)

        assert m.call_count == 14

        expected_logs = [
            "Started untagging operation with the following references: .*quay.io/name/repo1:1.*quay.io/name/repo1:2.*",
            "Gathering tags and digests of repository 'name/repo1'",
            "Getting cosign images of 6 images",
            "0 cosign images were found for the 6 images",
            "Getting cosign images of 0 images",
        ]
        compare_logs(caplog, expected_logs)


def test_full_run_get_manifest_error():
    args = [
        "dummy",
        "--reference",
        "quay.io/name/repo1:1",
        "--quay-api-token",
        "some-token",
        "--quay-user",
        "some-user",
        "--quay-password",
        "some-password",
    ]
    repo_tags = {"name": "repo1", "tags": ["1"]}

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/name/repo1/tags/list",
            json=repo_tags,
        )
        response = mock.MagicMock()
        response.status_code = 500
        m.register_uri(
            "GET",
            "https://quay.io/v2/name/repo1/manifests/1",
            exc=requests.exceptions.HTTPError("server error", response=response),
        )
        with pytest.raises(requests.exceptions.HTTPError, match="server error"):
            untag_images.untag_images_main(args)
