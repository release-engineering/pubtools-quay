import mock
import pytest

from requests.exceptions import HTTPError

from pubtools._quay.item_processor import (
    ItemProcesor,
    ReferenceProcessorNOP,
    ContentExtractor,
    ReferenceProcessorInternal,
)


def test_generate_existing_tags_tolerate_missing(operator_signing_push_item):
    rp = ReferenceProcessorNOP()
    mock_client = mock.MagicMock()
    mock_client.get_repository_tags.side_effect = HTTPError(
        response=mock.MagicMock(status_code=404)
    )
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client),
    )
    tags = list(ip.generate_existing_tags(operator_signing_push_item))
    assert tags == [("test-registry.io", "repo1", None), ("test-registry.io", "repo2", None)]


def test_generate_existing_tags_no_tolerate_missing(operator_signing_push_item):
    rp = ReferenceProcessorNOP()
    mock_client = mock.MagicMock()
    mock_client.get_repository_tags.side_effect = HTTPError(
        response=mock.MagicMock(status_code=404)
    )
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client),
    )
    with pytest.raises(HTTPError):
        list(ip.generate_existing_tags(operator_signing_push_item, tolerate_missing=False))


def test_generate_existing_tags_server_error(operator_signing_push_item):
    rp = ReferenceProcessorNOP()
    mock_client = mock.MagicMock()
    mock_client.get_repository_tags.side_effect = HTTPError(
        response=mock.MagicMock(status_code=500)
    )
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client),
    )
    with pytest.raises(HTTPError):
        list(ip.generate_existing_tags(operator_signing_push_item, tolerate_missing=False))


def test_generate_existing_tags_server_error_tolerate_missing(operator_signing_push_item):
    rp = ReferenceProcessorNOP()
    mock_client = mock.MagicMock()
    mock_client.get_repository_tags.side_effect = HTTPError(
        response=mock.MagicMock(status_code=500)
    )
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client),
    )
    with pytest.raises(HTTPError):
        list(ip.generate_existing_tags(operator_signing_push_item, tolerate_missing=True))


def test_reference_processor_internal():
    assert ReferenceProcessorInternal(quay_namespace="ns")("registry", "namespace/repo", None) == (
        "ns/namespace----repo",
        "registry/ns/namespace----repo",
    )


def test_reference_processor_internal_no_slash():
    assert ReferenceProcessorInternal(quay_namespace="ns")("registry", "noslash-repo", None) == (
        "ns/noslash-repo",
        "registry/ns/noslash-repo",
    )


def test_reference_processor_internal_no_slash_tag():
    assert ReferenceProcessorInternal(quay_namespace="ns")("registry", "noslash-repo", "tag") == (
        "ns/noslash-repo",
        "registry/ns/noslash-repo:tag",
    )


def test_reference_processor_internal_invalid_repo():
    with pytest.raises(ValueError):
        assert ReferenceProcessorInternal(quay_namespace="ns")(
            "registry", "namespace/ns/repo", None
        )


def test_reference_processor_internal_tag():
    assert ReferenceProcessorInternal(quay_namespace="ns")("registry", "namespace/repo", "tag") == (
        "ns/namespace----repo",
        "registry/ns/namespace----repo:tag",
    )


def test_reference_processor_replace_repo():
    assert (
        ReferenceProcessorInternal(quay_namespace="ns").replace_repo("namespace/repo")
        == "ns/namespace----repo"
    )


def test_reference_processor_replace_repo_no_slash():
    assert (
        ReferenceProcessorInternal(quay_namespace="ns").replace_repo("namespace-repo")
        == "ns/namespace-repo"
    )


def test_reference_processor_replace_repo_error():
    with pytest.raises(ValueError):
        assert ReferenceProcessorInternal(quay_namespace="ns").replace_repo("namespace/ns/repo")
