import logging
import mock
import pytest
import requests_mock

from pubtools._quay import quay_client
from pubtools._quay import image_untagger
from .utils import sort_dictionary_sortable_values, compare_logs

# flake8: noqa: E501


@mock.patch("pubtools._quay.image_untagger.QuayClient")
@mock.patch("pubtools._quay.image_untagger.QuayApiClient")
def test_init_success(mock_quay_api_client, mock_quay_client):
    references = ["stage.quay.io/name/repo1:1", "stage.quay.io/name/repo2:2"]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, False, quay_user, quay_password, host
    )

    assert untagger.references == references
    assert untagger.host == host[:-1]
    assert not untagger.remove_last
    mock_quay_client.assert_called_once_with(quay_user, quay_password, host[:-1])
    mock_quay_api_client.assert_called_once_with(token, host[:-1])


@mock.patch("pubtools._quay.image_untagger.QuayClient")
@mock.patch("pubtools._quay.image_untagger.QuayApiClient")
def test_init_bad_reference(mock_quay_api_client, mock_quay_client):
    references = [
        "stage.quay.io/name/repo1:1",
        "stage.quay.io/name/repo2@sha256:dgdgdg",
    ]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    with pytest.raises(ValueError, match=".*must be specified via tag, not digest.*"):
        image_untagger.ImageUntagger(
            references, token, False, quay_user, quay_password, host
        )


@mock.patch("pubtools._quay.image_untagger.QuayClient")
@mock.patch("pubtools._quay.image_untagger.QuayApiClient")
def test_init_no_docker_client(mock_quay_api_client, mock_quay_client):
    references = ["stage.quay.io/name/repo1:1", "stage.quay.io/name/repo2:2"]
    token = "some-token"
    quay_user = "some-user"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, False, quay_user, host=host
    )

    assert untagger.references == references
    assert untagger.host == host[:-1]
    assert not untagger.remove_last
    mock_quay_client.assert_not_called()
    mock_quay_api_client.assert_called_once_with(token, host[:-1])
    assert untagger._quay_client is None

    client = quay_client.QuayClient("user", "pass")
    untagger.set_quay_client(client)
    assert client == untagger._quay_client


@mock.patch("pubtools._quay.image_untagger.QuayClient")
@mock.patch("pubtools._quay.image_untagger.QuayApiClient")
def test_repo_tag_mapping(mock_quay_api_client, mock_quay_client):
    references = [
        "stage.quay.io/name/repo1:1",
        "stage.quay.io/name/repo1:2",
        "stage.quay.io/name/repo2:2",
        "stage.quay.io/name2/repo1:1",
        "stage.quay.io/name2/repo1:3",
    ]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, False, quay_user, quay_password, host
    )

    repo_tag_mapping = untagger.get_repository_tags_mapping()
    assert repo_tag_mapping == {
        "name/repo1": ["1", "2"],
        "name/repo2": ["2"],
        "name2/repo1": ["1", "3"],
    }


def test_tag_digest_mappings(
    repo_api_data,
    manifest_list_data,
    common_tag_digest_mapping,
    common_digest_tag_mapping,
):
    references = [
        "stage.quay.io/name/repo1:1",
        "stage.quay.io/name/repo1:2",
        "stage.quay.io/name/repo1:3",
        "stage.quay.io/name/repo1:4",
    ]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, False, quay_user, quay_password, host
    )
    with requests_mock.Mocker() as m:
        m.get(
            "https://stage.quay.io/api/v1/repository/name/repo1",
            json=repo_api_data,
        )
        m.get(
            "https://stage.quay.io/v2/name/repo1/manifests/sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            json=manifest_list_data,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
            },
        )
        tag_digest_mapping, digest_tag_mapping = untagger.construct_tag_digest_mappings(
            "name/repo1"
        )
        expected_tag_digest_mapping = common_tag_digest_mapping
        expected_digest_tag_mapping = common_digest_tag_mapping

        sort_dictionary_sortable_values(tag_digest_mapping)
        sort_dictionary_sortable_values(expected_tag_digest_mapping)
        sort_dictionary_sortable_values(digest_tag_mapping)
        sort_dictionary_sortable_values(expected_digest_tag_mapping)

        assert tag_digest_mapping == expected_tag_digest_mapping
        assert digest_tag_mapping == expected_digest_tag_mapping
        assert m.call_count == 3


@mock.patch("pubtools._quay.image_untagger.QuayClient")
@mock.patch("pubtools._quay.image_untagger.QuayApiClient")
def test_get_lost_digests_none(
    mock_quay_api_client,
    mock_quay_client,
    common_tag_digest_mapping,
    common_digest_tag_mapping,
):
    references = [
        "stage.quay.io/name/repo1:1",
    ]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, False, quay_user, quay_password, host
    )

    lost_digests = untagger.get_lost_digests(
        ["1"], common_tag_digest_mapping, common_digest_tag_mapping
    )
    assert lost_digests == []


@mock.patch("pubtools._quay.image_untagger.QuayClient")
@mock.patch("pubtools._quay.image_untagger.QuayApiClient")
def test_get_lost_digests_some(
    mock_quay_api_client,
    mock_quay_client,
    common_tag_digest_mapping,
    common_digest_tag_mapping,
):
    references = [
        "stage.quay.io/name/repo1:1",
        "stage.quay.io/name/repo1:2",
    ]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, False, quay_user, quay_password, host
    )

    lost_digests = untagger.get_lost_digests(
        ["1", "2"], common_tag_digest_mapping, common_digest_tag_mapping
    )
    assert lost_digests == [
        u"sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
        u"sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
        u"sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
        u"sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
    ]


def test_untag_images_no_lost_digests(repo_api_data, manifest_list_data, caplog):
    caplog.set_level(logging.INFO)
    references = [
        "stage.quay.io/name/repo1:1",
    ]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, False, quay_user, quay_password, host
    )
    with requests_mock.Mocker() as m:
        m.get(
            "https://stage.quay.io/api/v1/repository/name/repo1",
            json=repo_api_data,
        )
        m.get(
            "https://stage.quay.io/v2/name/repo1/manifests/sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            json=manifest_list_data,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
            },
        )
        m.delete("https://stage.quay.io/api/v1/repository/name/repo1/tag/1")
        lost_images = untagger.untag_images()

        assert lost_images == []
        assert m.call_count == 4

        expected_logs = [
            "Gathering tags and digests of repository 'name/repo1'",
            "Getting manifest list of image stage.quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            "Getting manifest list of image stage.quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            "No images will be lost by this untagging operation",
            "Removing tag '1' from repository 'name/repo1'",
        ]
        compare_logs(caplog, expected_logs)


def test_untag_images_lost_digests_error(repo_api_data, manifest_list_data, caplog):
    caplog.set_level(logging.INFO)
    references = [
        "stage.quay.io/name/repo1:1",
        "stage.quay.io/name/repo1:2",
    ]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, False, quay_user, quay_password, host
    )
    with requests_mock.Mocker() as m:
        m.get(
            "https://stage.quay.io/api/v1/repository/name/repo1",
            json=repo_api_data,
        )
        m.get(
            "https://stage.quay.io/v2/name/repo1/manifests/sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            json=manifest_list_data,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
            },
        )
        m.delete("https://stage.quay.io/api/v1/repository/name/repo1/tag/1")

        expected_err_msg = (
            "Following images .*"
            ".*stage.quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36.*"
            ".*stage.quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee.*"
            ".*stage.quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9.*"
            ".*stage.quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c.*"
        )

        with pytest.raises(ValueError, match=expected_err_msg):
            untagger.untag_images()


def test_untag_images_lost_digests_remove_anyway(
    repo_api_data, manifest_list_data, caplog
):
    caplog.set_level(logging.INFO)
    references = [
        "stage.quay.io/name/repo1:1",
        "stage.quay.io/name/repo1:2",
    ]
    token = "some-token"
    quay_user = "some-user"
    quay_password = "some-password"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, True, quay_user, quay_password, host
    )
    with requests_mock.Mocker() as m:
        m.get(
            "https://stage.quay.io/api/v1/repository/name/repo1",
            json=repo_api_data,
        )
        m.get(
            "https://stage.quay.io/v2/name/repo1/manifests/sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            json=manifest_list_data,
            headers={
                "Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"
            },
        )
        m.delete("https://stage.quay.io/api/v1/repository/name/repo1/tag/1")
        m.delete("https://stage.quay.io/api/v1/repository/name/repo1/tag/2")
        lost_images = untagger.untag_images()

        expected_lost_images = [
            "stage.quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            "stage.quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
            "stage.quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
            "stage.quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
        ]

        assert lost_images == expected_lost_images
        assert m.call_count == 5

        expected_logs = [
            "Gathering tags and digests of repository 'name/repo1'",
            "Getting manifest list of image stage.quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            "Getting manifest list of image stage.quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36",
            "Following images won't be referencable by tag: "
            ".*stage.quay.io/name/repo1@sha256:8a3a33cad0bd33650ba7287a7ec94327d8e47ddf7845c569c80b5c4b20d49d36.*"
            ".*stage.quay.io/name/repo1@sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee.*"
            ".*stage.quay.io/name/repo1@sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9.*"
            ".*stage.quay.io/name/repo1@sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c.*",
            "Removing tag '1' from repository 'name/repo1'",
            "Removing tag '2' from repository 'name/repo1'",
        ]
        compare_logs(caplog, expected_logs)


def test_untag_images_missing_client(repo_api_data, manifest_list_data, caplog):
    caplog.set_level(logging.INFO)
    references = [
        "stage.quay.io/name/repo1:1",
        "stage.quay.io/name/repo1:2",
    ]
    token = "some-token"
    quay_user = "some-user"
    host = "stage.quay.io/"
    untagger = image_untagger.ImageUntagger(
        references, token, True, quay_user, host=host
    )
    with pytest.raises(RuntimeError, match="QuayClient instance must be set"):
        untagger.untag_images()
