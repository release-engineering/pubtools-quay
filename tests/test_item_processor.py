import mock
import pytest

from requests.exceptions import HTTPError

from pubtools._quay.item_processor import (
    ItemProcesor,
    ReferenceProcessorExternal,
    ContentExtractor,
    ReferenceProcessorInternal,
    VirtualPushItem,
)


def test_generate_existing_tags_tolerate_missing(operator_signing_push_item):
    rp = ReferenceProcessorExternal()
    mock_client = mock.MagicMock()
    mock_client.get_repository_tags.side_effect = HTTPError(
        response=mock.MagicMock(status_code=404)
    )
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        public_registries=[],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client),
    )
    tags = list(ip.generate_existing_tags(operator_signing_push_item))
    assert tags == [("test-registry.io", "repo1", None), ("test-registry.io", "repo2", None)]


def test_generate_existing_tags_no_tolerate_missing(operator_signing_push_item):
    rp = ReferenceProcessorExternal()
    mock_client = mock.MagicMock()
    mock_client.get_repository_tags.side_effect = HTTPError(
        response=mock.MagicMock(status_code=404)
    )
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        public_registries=[],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client),
    )
    with pytest.raises(HTTPError):
        list(ip.generate_existing_tags(operator_signing_push_item, tolerate_missing=False))


def test_generate_existing_tags_server_error(operator_signing_push_item):
    rp = ReferenceProcessorExternal()
    mock_client = mock.MagicMock()
    mock_client.get_repository_tags.side_effect = HTTPError(
        response=mock.MagicMock(status_code=500)
    )
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        public_registries=[],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client),
    )
    with pytest.raises(HTTPError):
        list(ip.generate_existing_tags(operator_signing_push_item, tolerate_missing=False))


def test_generate_existing_tags_server_error_tolerate_missing(operator_signing_push_item):
    rp = ReferenceProcessorExternal()
    mock_client = mock.MagicMock()
    mock_client.get_repository_tags.side_effect = HTTPError(
        response=mock.MagicMock(status_code=500)
    )
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        public_registries=[],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client),
    )
    with pytest.raises(HTTPError):
        list(ip.generate_existing_tags(operator_signing_push_item, tolerate_missing=True))


def test_reference_processor_internal():
    assert (
        ReferenceProcessorInternal(quay_namespace="ns").full_reference(
            "registry", "namespace/repo", None
        )
        == "registry/ns/namespace----repo"
    )


def test_reference_processor_internal_no_slash():
    assert (
        ReferenceProcessorInternal(quay_namespace="ns").full_reference(
            "registry", "noslash-repo", None
        )
        == "registry/ns/noslash-repo"
    )


def test_reference_processor_internal_no_slash_tag():
    assert (
        ReferenceProcessorInternal(quay_namespace="ns").full_reference(
            "registry", "noslash-repo", "tag"
        )
        == "registry/ns/noslash-repo:tag"
    )


def test_reference_processor_internal_invalid_repo():
    with pytest.raises(ValueError):
        assert ReferenceProcessorInternal(quay_namespace="ns").full_reference(
            "registry", "namespace/ns/repo", None
        )


def test_reference_processor_internal_tag():
    assert (
        ReferenceProcessorInternal(quay_namespace="ns").full_reference(
            "registry", "namespace/repo", "tag"
        )
        == "registry/ns/namespace----repo:tag"
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


def test_invalid_virtual_push_item():
    with pytest.raises(ValueError):
        VirtualPushItem(repos=[], metadata={})


def test_reference_processor_external_tag():
    assert (
        ReferenceProcessorExternal().full_reference("registry", "namespace/repo", "tag")
        == "registry/namespace/repo:tag"
    )


def test_reference_processor_external_repo():
    assert (
        ReferenceProcessorExternal().full_reference("registry", "namespace/repo", None)
        == "registry/namespace/repo"
    )


def test_generate_existing_manifest_map_tolerate_429(operator_signing_push_item):
    rp = ReferenceProcessorExternal()
    mock_client = mock.MagicMock()
    mock_client.get_manifest.side_effect = HTTPError(response=mock.MagicMock(status_code=429))
    ip = ItemProcesor(
        source_registry="test-registry.io",
        reference_registries=["dest-registry.io"],
        public_registries=[],
        reference_processor=rp,
        extractor=ContentExtractor(quay_client=mock_client, sleep_time=0),
    )
    assert ip.generate_existing_manifests_map(operator_signing_push_item) == {
        "test-registry.io": {
            "repo1": {"latest-test-tag": None, "1.0": None},
            "repo2": {"tag2": None},
        }
    }
