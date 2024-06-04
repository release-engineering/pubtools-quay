import logging
import mock
import pytest
import os
import json
import subprocess

from pubtools._quay import security_manifest_pusher
from pubtools._quay.exceptions import ManifestTypeError

TEST_DATA_PATH = os.path.join(os.path.dirname(__file__), "test_data")


@mock.patch("pubtools._quay.security_manifest_pusher.QuayApiClient")
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_init(
    mock_quay_client, mock_quay_api_client, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )

    assert pusher.push_items == [container_multiarch_push_item]
    assert pusher.target_settings == target_settings
    assert pusher.quay_host == "quay.io"
    mock_quay_client.assert_not_called()
    mock_quay_api_client.assert_not_called()

    assert pusher.src_quay_client == mock_quay_client.return_value
    mock_quay_client.assert_called_once_with("src-quay-user", "src-quay-pass", "quay.io")
    assert pusher.dest_quay_api_client == mock_quay_api_client.return_value
    mock_quay_api_client.assert_called_once_with("dest-quay-token", "quay.io")


@mock.patch("subprocess.run")
def test_cosign_get_security_manifest(mock_run, target_settings, container_multiarch_push_item):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0

    res = pusher.cosign_get_security_manifest("quay.io/org/repo@sha256:abcdef", "/temp/file.txt")
    assert res
    mock_run.assert_called_once_with(
        [
            "cosign",
            "download",
            "sbom",
            "quay.io/org/repo@sha256:abcdef",
            "--output-file",
            "/temp/file.txt",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@mock.patch("subprocess.run")
def test_cosign_get_security_manifest_normal_error(
    mock_run, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 1
    mock_run.return_value.stdout = """
    Error: no sbom attached to reference
    main.go:74: error during command execution: no sbom attached to reference
    """

    res = pusher.cosign_get_security_manifest("quay.io/org/repo@sha256:abcdef", "/temp/file.txt")
    assert not res


@mock.patch("time.sleep")
@mock.patch("subprocess.run")
def test_cosign_get_security_manifest_unusual_error(
    mock_run, mock_sleep, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 1
    mock_run.return_value.stdout = """
    Error: unusual error
    main.go:74: error during command execution: unusual error
    """

    with pytest.raises(RuntimeError, match=".*has failed with an error.*"):
        pusher.cosign_get_security_manifest("quay.io/org/repo@sha256:abcdef", "/temp/file.txt")

    assert mock_run.call_count == 4


@mock.patch("subprocess.run")
def test_cosign_get_existing_attestation(mock_run, target_settings, container_multiarch_push_item):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0

    res = pusher.cosign_get_existing_attestation("quay.io/org/repo@sha256:abcdef", "/temp/file.txt")
    assert res
    mock_run.assert_called_once_with(
        [
            "cosign",
            "verify-attestation",
            "--key",
            "path/to/key.pub",
            "quay.io/org/repo@sha256:abcdef",
            "--output-file",
            "/temp/file.txt",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@mock.patch("subprocess.run")
def test_cosign_get_existing_attestation_rekor_url(
    mock_run, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0

    res = pusher.cosign_get_existing_attestation(
        "quay.io/org/repo@sha256:abcdef", "/temp/file.txt", "https://some-rekor.com"
    )
    assert res
    mock_run.assert_called_once_with(
        [
            "cosign",
            "verify-attestation",
            "--rekor-url=https://some-rekor.com",
            "--key",
            "path/to/key.pub",
            "quay.io/org/repo@sha256:abcdef",
            "--output-file",
            "/temp/file.txt",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@mock.patch("subprocess.run")
def test_cosign_get_existing_attestation_disable_rekor(
    mock_run, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0

    res = pusher.cosign_get_existing_attestation(
        "quay.io/org/repo@sha256:abcdef", "/temp/file.txt", "https://some-rekor.com", True
    )
    assert res
    mock_run.assert_called_once_with(
        [
            "cosign",
            "verify-attestation",
            "--insecure-ignore-tlog=true",
            "--key",
            "path/to/key.pub",
            "quay.io/org/repo@sha256:abcdef",
            "--output-file",
            "/temp/file.txt",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@mock.patch("subprocess.run")
def test_cosign_get_existing_attestation_normal_error(
    mock_run, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 1
    mock_run.return_value.stdout = (
        "Error: no matching attestations: \n"
        "main.go:74: error during command execution: no matching attestations: \n"
    )

    res = pusher.cosign_get_existing_attestation("quay.io/org/repo@sha256:abcdef", "/temp/file.txt")
    assert not res


@mock.patch("time.sleep")
@mock.patch("subprocess.run")
def test_cosign_get_existing_attestation_unusual_error(
    mock_run, mock_sleep, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 1
    mock_run.return_value.stdout = """
    Error: no matching attestations: unusual error
    main.go:74: error during command execution: no matching attestations: unusual error
    """

    with pytest.raises(RuntimeError, match=".*has failed with an error.*"):
        pusher.cosign_get_existing_attestation("quay.io/org/repo@sha256:abcdef", "/temp/file.txt")

    assert mock_run.call_count == 4


@mock.patch("subprocess.run")
def test_cosign_attest_security_manifest(mock_run, target_settings, container_multiarch_push_item):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0

    pusher.cosign_attest_security_manifest("/temp/file.txt", "quay.io/org/repo@sha256:abcdef")
    mock_run.assert_called_once_with(
        [
            "cosign",
            "attest",
            "--predicate",
            "/temp/file.txt",
            "--key",
            "path/to/key.key",
            "-y",
            "quay.io/org/repo@sha256:abcdef",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@mock.patch("subprocess.run")
def test_cosign_attest_security_manifest_rekor_url(
    mock_run, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0

    pusher.cosign_attest_security_manifest(
        "/temp/file.txt", "quay.io/org/repo@sha256:abcdef", "https://some-rekor.com"
    )
    mock_run.assert_called_once_with(
        [
            "cosign",
            "attest",
            "--rekor-url=https://some-rekor.com",
            "--predicate",
            "/temp/file.txt",
            "--key",
            "path/to/key.key",
            "-y",
            "quay.io/org/repo@sha256:abcdef",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@mock.patch("subprocess.run")
def test_cosign_attest_security_manifest_disable_rekor(
    mock_run, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0

    pusher.cosign_attest_security_manifest(
        "/temp/file.txt", "quay.io/org/repo@sha256:abcdef", "https://some-rekor.com", True
    )
    mock_run.assert_called_once_with(
        [
            "cosign",
            "attest",
            "--tlog-upload=false",
            "--predicate",
            "/temp/file.txt",
            "--key",
            "path/to/key.key",
            "-y",
            "quay.io/org/repo@sha256:abcdef",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


@mock.patch("time.sleep")
@mock.patch("subprocess.run")
def test_cosign_attest_security_manifest_err(
    mock_run, mock_sleep, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 1

    with pytest.raises(RuntimeError, match="Creating attestation to image.*"):
        pusher.cosign_attest_security_manifest("/temp/file.txt", "quay.io/org/repo@sha256:abcdef")

    assert mock_run.call_count == 4


@mock.patch("uuid.uuid4")
@mock.patch("subprocess.run")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.open",
    mock.mock_open(read_data="quay.io/org/repo:sha256-abcdef.att\n"),
)
def test_cosign_triangulate_image(
    mock_run, mock_uuid, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0
    mock_uuid.return_value.hex = "abcd"

    ret = pusher.cosign_triangulate_image("quay.io/org/repo@sha256:abcdef", "/temp/")
    mock_run.assert_called_once_with(
        [
            "cosign",
            "triangulate",
            "--type=attestation",
            "quay.io/org/repo@sha256:abcdef",
            "--output-file",
            "/temp/attestation_reference_abcd.json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert ret == "quay.io/org/repo:sha256-abcdef.att"


@mock.patch("uuid.uuid4")
@mock.patch("subprocess.run")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.open",
    mock.mock_open(read_data="quay.io/org/repo:sha256-abcdef.sig\n"),
)
def test_cosign_triangulate_image_nondefault_type(
    mock_run, mock_uuid, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0
    mock_uuid.return_value.hex = "abcd"

    ret = pusher.cosign_triangulate_image("quay.io/org/repo@sha256:abcdef", "/temp/", "signature")
    mock_run.assert_called_once_with(
        [
            "cosign",
            "triangulate",
            "--type=signature",
            "quay.io/org/repo@sha256:abcdef",
            "--output-file",
            "/temp/signature_reference_abcd.json",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    assert ret == "quay.io/org/repo:sha256-abcdef.sig"


@mock.patch("uuid.uuid4")
@mock.patch("subprocess.run")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.open",
    mock.mock_open(read_data="quay.io/org/repo:sha256-abcdef.att\n"),
)
def test_cosign_triangulate_image_error(
    mock_run, mock_uuid, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 1
    mock_uuid.return_value.hex = "abcd"

    with pytest.raises(RuntimeError, match="Triangulating attestation image to image.*"):
        pusher.cosign_triangulate_image("quay.io/org/repo@sha256:abcdef", "/temp/")


@mock.patch("uuid.uuid4")
@mock.patch("subprocess.run")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.open",
    mock.mock_open(read_data="quay.io/org/repo:sha256-abcdef.att\n"),
)
def test_cosign_triangulate_image_unknown_type(
    mock_run, mock_uuid, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_run.return_value.returncode = 0
    mock_uuid.return_value.hex = "abcd"

    with pytest.raises(ValueError, match="Image type 'wrong' needs to be one of.*"):
        pusher.cosign_triangulate_image("quay.io/org/repo@sha256:abcdef", "/temp/", "wrong")


def test_get_security_manifest_from_attestation(target_settings, container_multiarch_push_item):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    with open(os.path.join(TEST_DATA_PATH, "security_manifest.json"), "r") as f:
        expected_security_manifest = json.load(f)

    security_manifest = pusher.get_security_manifest_from_attestation(
        os.path.join(TEST_DATA_PATH, "raw_attestation.json")
    )

    assert security_manifest == expected_security_manifest


def test_security_manifest_get_products(target_settings, container_multiarch_push_item):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    with open(os.path.join(TEST_DATA_PATH, "security_manifest_products.json"), "r") as f:
        security_manifest = json.load(f)

    products = pusher.security_manifest_get_products(security_manifest)
    assert products == {"product1", "product2"}


def test_get_destination_repos(target_settings, container_multiarch_push_item):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )

    dest_repos = pusher.get_destination_repos(container_multiarch_push_item)
    assert dest_repos == ["quay.io/some-namespace/target----repo"]


@mock.patch("uuid.uuid4")
@mock.patch("json.dump")
@mock.patch("json.load")
@mock.patch("pubtools._quay.security_manifest_pusher.open", mock.mock_open())
def test_security_manifest_remove_incompleteness_reasons(
    mock_load, mock_dump, mock_uuid, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_load.return_value = {"specVersion": "1.4", "incompleteness_reasons": []}
    mock_uuid.return_value.hex = "abcd"

    res = pusher.security_manifest_remove_incompleteness_reasons(__file__)
    assert res == os.path.join(os.path.dirname(__file__), "sanitized_security_manifest_abcd.json")
    mock_load.assert_called_once()
    mock_dump.assert_called_once()
    assert mock_dump.call_args_list[0][0][0] == {"specVersion": "1.4"}


@mock.patch("uuid.uuid4")
@mock.patch("json.dump")
@mock.patch("json.load")
@mock.patch("pubtools._quay.security_manifest_pusher.open", mock.mock_open())
def test_security_manifest_add_products(
    mock_load, mock_dump, mock_uuid, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_load.return_value = {}
    mock_uuid.return_value.hex = "abcd"

    res = pusher.security_manifest_add_products(__file__, {"product1", "product2"})
    assert res == os.path.join(os.path.dirname(__file__), "full_security_manifest_abcd.json")
    mock_load.assert_called_once()
    mock_dump.assert_called_once()
    mock_dump.call_args_list[0][0][0]["properties"].sort(key=lambda d: d["value"])
    assert mock_dump.call_args_list[0][0][0] == {
        "properties": [
            {"name": "product", "value": "product1"},
            {"name": "product", "value": "product2"},
        ]
    }


@mock.patch("uuid.uuid4")
@mock.patch("json.dump")
@mock.patch("pubtools._quay.security_manifest_pusher.open", mock.mock_open())
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_security_manifest_from_attestation"
)
def test_extract_security_manifest_from_attestation(
    mock_get_sec_manifest, mock_dump, mock_uuid, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_get_sec_manifest.return_value = {"specVersion": "1.4", "incompleteness_reasons": []}
    mock_uuid.return_value.hex = "abcd"

    path = pusher.extract_security_manifest_from_attestation("attestation.json")
    assert path == "extracted_security_manifest_abcd.json"

    mock_get_sec_manifest.assert_called_once_with("attestation.json")
    mock_dump.assert_called_once()


@mock.patch("pubtools._quay.security_manifest_pusher.QuayApiClient")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher." "cosign_triangulate_image"
)
def test_delete_existing_attestation(
    mock_triangulate, mock_api_client, target_settings, container_multiarch_push_item
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_triangulate.return_value = "quay.io/org/repo:sha256-abcdef.att"

    pusher.delete_existing_attestation("quay.io/org/repo@sha256:abcdef", "/temp")
    mock_triangulate.assert_called_once_with("quay.io/org/repo@sha256:abcdef", "/temp")
    mock_api_client.assert_called_once_with("dest-quay-token", "quay.io")


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.delete_existing_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_attest_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.security_manifest_add_products"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher"
    ".security_manifest_remove_incompleteness_reasons"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_security_manifest_from_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_existing_attestation"
)
@mock.patch("uuid.uuid4")
def test_merge_and_push_security_manifest(
    mock_uuid,
    mock_get_attestation,
    mock_get_manifest,
    mock_remove_incompleteness,
    mock_add_products,
    mock_attest,
    mock_delete_attestation,
    target_settings,
    container_multiarch_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    with open(os.path.join(TEST_DATA_PATH, "security_manifest_products.json"), "r") as f:
        security_manifest = json.load(f)

    digest_manifest = security_manifest_pusher.DigestSecurityManifest("abcdef", "path/to/manifest")
    mock_get_attestation.return_value = True

    mock_get_manifest.return_value = security_manifest
    mock_remove_incompleteness.return_value = "/path/to/sanitized/manifest.json"

    mock_uuid.return_value.hex = "abcd"
    mock_add_products.return_value = "/path/to/final/manifest.json"

    pusher.merge_and_push_security_manifest(
        container_multiarch_push_item, digest_manifest, ["quay.io/org/repo"], "/temp/temp_path"
    )

    mock_get_attestation.assert_called_once_with(
        "quay.io/org/repo@abcdef",
        "/temp/temp_path/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    mock_get_manifest.assert_called_once_with("/temp/temp_path/attestation_abcd.json")
    mock_remove_incompleteness.assert_called_once_with("path/to/manifest")
    mock_add_products.assert_called_once_with(
        "/path/to/sanitized/manifest.json", {"new-product", "product1", "product2"}
    )
    mock_delete_attestation.assert_called_once_with("quay.io/org/repo@abcdef", "/temp/temp_path")
    mock_attest.assert_called_once_with(
        "/path/to/final/manifest.json", "quay.io/org/repo@abcdef", "https://some-rekor.com", False
    )


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.delete_existing_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_attest_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.security_manifest_add_products"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher"
    ".security_manifest_remove_incompleteness_reasons"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_security_manifest_from_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_existing_attestation"
)
@mock.patch("uuid.uuid4")
def test_merge_and_push_security_manifest_no_existing_attestation_also_disable_rekor(
    mock_uuid,
    mock_get_attestation,
    mock_get_manifest,
    mock_remove_incompleteness,
    mock_add_products,
    mock_attest,
    mock_delete_attestation,
    target_settings,
    container_multiarch_push_item,
):
    target_settings["cosign_sbom_skip_verify_rekor"] = True
    target_settings["cosign_sbom_skip_upload_rekor"] = True
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    with open(os.path.join(TEST_DATA_PATH, "security_manifest_products.json"), "r") as f:
        security_manifest = json.load(f)

    digest_manifest = security_manifest_pusher.DigestSecurityManifest("abcdef", "path/to/manifest")
    mock_get_attestation.return_value = False

    mock_get_manifest.return_value = security_manifest
    mock_remove_incompleteness.return_value = "/path/to/sanitized/manifest.json"

    mock_uuid.return_value.hex = "abcd"
    mock_add_products.return_value = "/path/to/final/manifest.json"

    pusher.merge_and_push_security_manifest(
        container_multiarch_push_item, digest_manifest, ["quay.io/org/repo"], "/temp/temp_path"
    )

    mock_get_attestation.assert_called_once_with(
        "quay.io/org/repo@abcdef",
        "/temp/temp_path/attestation_abcd.json",
        "https://some-rekor.com",
        True,
    )
    mock_get_manifest.assert_not_called()
    mock_delete_attestation.assert_not_called()
    mock_remove_incompleteness.assert_called_once_with("path/to/manifest")
    mock_add_products.assert_called_once_with("/path/to/sanitized/manifest.json", {"new-product"})
    mock_attest.assert_called_once_with(
        "/path/to/final/manifest.json", "quay.io/org/repo@abcdef", "https://some-rekor.com", True
    )


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.delete_existing_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_attest_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.security_manifest_add_products"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher"
    ".security_manifest_remove_incompleteness_reasons"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_security_manifest_from_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_existing_attestation"
)
@mock.patch("uuid.uuid4")
def test_merge_and_push_security_manifest_already_pushed(
    mock_uuid,
    mock_get_attestation,
    mock_get_manifest,
    mock_remove_incompleteness,
    mock_add_products,
    mock_attest,
    mock_delete_attestation,
    target_settings,
    container_multiarch_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    with open(os.path.join(TEST_DATA_PATH, "security_manifest_products.json"), "r") as f:
        security_manifest = json.load(f)
    security_manifest["properties"] = [{"name": "product", "value": "new-product"}]

    digest_manifest = security_manifest_pusher.DigestSecurityManifest("abcdef", "path/to/manifest")
    mock_get_attestation.return_value = True

    mock_get_manifest.return_value = security_manifest
    mock_remove_incompleteness.return_value = "/path/to/sanitized/manifest.json"

    mock_uuid.return_value.hex = "abcd"
    mock_add_products.return_value = "/path/to/final/manifest.json"

    pusher.merge_and_push_security_manifest(
        container_multiarch_push_item, digest_manifest, ["quay.io/org/repo"], "/temp/temp_path"
    )

    mock_get_attestation.assert_called_once_with(
        "quay.io/org/repo@abcdef",
        "/temp/temp_path/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    mock_get_manifest.assert_called_once_with("/temp/temp_path/attestation_abcd.json")
    mock_delete_attestation.assert_not_called()
    mock_remove_incompleteness.assert_not_called()
    mock_add_products.assert_not_called()
    mock_attest.assert_not_called()


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.delete_existing_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_attest_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.security_manifest_add_products"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher"
    ".security_manifest_remove_incompleteness_reasons"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_security_manifest_from_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_existing_attestation"
)
@mock.patch("uuid.uuid4")
def test_merge_and_push_security_manifest_no_product_existing_attestation(
    mock_uuid,
    mock_get_attestation,
    mock_get_manifest,
    mock_remove_incompleteness,
    mock_add_products,
    mock_attest,
    mock_delete_attestation,
    target_settings,
    container_multiarch_push_item,
):
    container_multiarch_push_item.metadata.pop("product_name")
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    with open(os.path.join(TEST_DATA_PATH, "security_manifest_products.json"), "r") as f:
        security_manifest = json.load(f)

    digest_manifest = security_manifest_pusher.DigestSecurityManifest("abcdef", "path/to/manifest")
    mock_get_attestation.return_value = True
    mock_remove_incompleteness.return_value = "/path/to/sanitized/manifest.json"

    mock_get_manifest.return_value = security_manifest

    mock_uuid.return_value.hex = "abcd"
    mock_add_products.return_value = "/path/to/final/manifest.json"

    pusher.merge_and_push_security_manifest(
        container_multiarch_push_item, digest_manifest, ["quay.io/org/repo"], "/temp/temp_path"
    )

    mock_get_attestation.assert_called_once_with(
        "quay.io/org/repo@abcdef",
        "/temp/temp_path/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    mock_get_manifest.assert_called_once_with("/temp/temp_path/attestation_abcd.json")
    mock_add_products.assert_not_called()
    mock_delete_attestation.assert_not_called()
    mock_remove_incompleteness.assert_not_called()
    mock_attest.assert_not_called()


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.delete_existing_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_attest_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.security_manifest_add_products"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher"
    ".security_manifest_remove_incompleteness_reasons"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_security_manifest_from_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_existing_attestation"
)
@mock.patch("uuid.uuid4")
def test_merge_and_push_security_manifest_no_product_no_existing_attestation(
    mock_uuid,
    mock_get_attestation,
    mock_get_manifest,
    mock_remove_incompleteness,
    mock_add_products,
    mock_attest,
    mock_delete_attestation,
    target_settings,
    container_multiarch_push_item,
):
    container_multiarch_push_item.metadata.pop("product_name")
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    with open(os.path.join(TEST_DATA_PATH, "security_manifest_products.json"), "r") as f:
        security_manifest = json.load(f)

    digest_manifest = security_manifest_pusher.DigestSecurityManifest("abcdef", "path/to/manifest")
    mock_get_attestation.return_value = False

    mock_get_manifest.return_value = security_manifest
    mock_remove_incompleteness.return_value = "/path/to/sanitized/manifest.json"

    mock_uuid.return_value.hex = "abcd"
    mock_add_products.return_value = "/path/to/final/manifest.json"

    pusher.merge_and_push_security_manifest(
        container_multiarch_push_item, digest_manifest, ["quay.io/org/repo"], "/temp/temp_path"
    )

    mock_get_attestation.assert_called_once_with(
        "quay.io/org/repo@abcdef",
        "/temp/temp_path/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    mock_get_manifest.assert_not_called()
    mock_add_products.assert_not_called()
    mock_remove_incompleteness.assert_called_once_with("path/to/manifest")
    mock_delete_attestation.assert_not_called()
    mock_attest.assert_called_once_with(
        "/path/to/sanitized/manifest.json",
        "quay.io/org/repo@abcdef",
        "https://some-rekor.com",
        False,
    )


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "extract_security_manifest_from_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.delete_existing_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_attest_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_existing_attestation"
)
@mock.patch("uuid.uuid4")
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_push_manifest_list_security_manifests(
    mock_quay_client,
    mock_uuid,
    mock_get_attestation,
    mock_attest,
    mock_delete_attestation,
    mock_extract_sec_manifest,
    target_settings,
    manifest_list_data,
    container_multiarch_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_get_attestation.return_value = True
    mock_quay_client.return_value.get_manifest_digest.return_value = "sha256:abcdef"
    mock_quay_client.return_value.get_manifest.return_value = manifest_list_data
    mock_uuid.return_value.hex = "abcd"
    mock_extract_sec_manifest.return_value = "extracted_security_manifest_defg.json"

    pusher.push_manifest_list_security_manifests(
        container_multiarch_push_item,
        "/some",
    )

    mock_quay_client.return_value.get_manifest_digest.assert_called_once_with(
        "quay.io/some-namespace/target----repo:latest-test-tag",
        mock_quay_client.return_value.MANIFEST_LIST_TYPE,
    )
    mock_quay_client.return_value.get_manifest.assert_called_once_with(
        "quay.io/some-namespace/target----repo:latest-test-tag",
        media_type=mock_quay_client.return_value.MANIFEST_LIST_TYPE,
    )

    assert mock_get_attestation.call_count == 6
    assert mock_get_attestation.call_args_list[0] == mock.call(
        "quay.io/some-namespace/target----repo@"
        "sha256:2e8f38a0a8d2a450598430fa70c7f0b53aeec991e76c3e29c63add599b4ef7ee",
        "/some/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    assert mock_get_attestation.call_args_list[1] == mock.call(
        "quay.io/some-namespace/target----repo@"
        "sha256:b3f9218fb5839763e62e52ee6567fe331aa1f3c644f9b6f232ff23959257acf9",
        "/some/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    assert mock_get_attestation.call_args_list[2] == mock.call(
        "quay.io/some-namespace/target----repo@"
        "sha256:496fb0ff2057c79254c9dc6ba999608a98219c5c93142569a547277c679e532c",
        "/some/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    assert mock_get_attestation.call_args_list[3] == mock.call(
        "quay.io/some-namespace/target----repo@"
        "sha256:146ab6fa7ba3ab4d154b09c1c5522e4966ecd071bf23d1ba3df6c8b9fc33f8cb",
        "/some/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    assert mock_get_attestation.call_args_list[4] == mock.call(
        "quay.io/some-namespace/target----repo@"
        "sha256:bbef1f46572d1f33a92b53b0ba0ed5a1d09dab7ffe64be1ae3ae66e76275eabd",
        "/some/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    assert mock_get_attestation.call_args_list[5] == mock.call(
        "quay.io/some-namespace/target----repo@sha256:abcdef",
        "/some/attestation_abcd.json",
        "https://some-rekor.com",
        False,
    )
    assert mock_extract_sec_manifest.call_count == 5
    assert mock_extract_sec_manifest.call_args_list[0] == mock.call("/some/attestation_abcd.json")
    mock_delete_attestation.assert_called_once_with(
        "quay.io/some-namespace/target----repo@sha256:abcdef", "/some"
    )

    assert mock_attest.call_count == 5
    assert mock_attest.call_args_list[0] == mock.call(
        "extracted_security_manifest_defg.json",
        "quay.io/some-namespace/target----repo@sha256:abcdef",
        "https://some-rekor.com",
        False,
    )


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "extract_security_manifest_from_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.delete_existing_attestation"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_attest_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_existing_attestation"
)
@mock.patch("uuid.uuid4")
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_push_manifest_list_security_manifests_arch_att_not_exist(
    mock_quay_client,
    mock_uuid,
    mock_get_attestation,
    mock_attest,
    mock_delete_attestation,
    mock_extract_sec_manifest,
    target_settings,
    manifest_list_data,
    container_multiarch_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    mock_get_attestation.side_effect = [True, True, False, True, True, True]
    mock_quay_client.return_value.get_manifest_digest.return_value = "sha256:abcdef"
    mock_quay_client.return_value.get_manifest.return_value = manifest_list_data
    mock_uuid.return_value.hex = "abcd"
    mock_extract_sec_manifest.return_value = "extracted_security_manifest_defg.json"

    pusher.push_manifest_list_security_manifests(
        container_multiarch_push_item,
        "/some",
    )

    mock_quay_client.return_value.get_manifest_digest.assert_called_once_with(
        "quay.io/some-namespace/target----repo:latest-test-tag",
        mock_quay_client.return_value.MANIFEST_LIST_TYPE,
    )
    mock_quay_client.return_value.get_manifest.assert_called_once_with(
        "quay.io/some-namespace/target----repo:latest-test-tag",
        media_type=mock_quay_client.return_value.MANIFEST_LIST_TYPE,
    )

    assert mock_get_attestation.call_count == 6
    assert mock_extract_sec_manifest.call_count == 4
    assert mock_extract_sec_manifest.call_args_list[0] == mock.call("/some/attestation_abcd.json")
    mock_delete_attestation.assert_called_once_with(
        "quay.io/some-namespace/target----repo@sha256:abcdef", "/some"
    )
    assert mock_attest.call_count == 4


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_security_manifest"
)
@mock.patch("uuid.uuid4")
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_get_source_item_security_manifests(
    mock_quay_client,
    mock_uuid,
    mock_get_security_manifest,
    target_settings,
    container_source_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_source_push_item], target_settings
    )

    mock_quay_client.return_value.get_manifest_digest.return_value = "sha256:abcdef"
    mock_uuid.return_value.hex = "abcd"
    mock_get_security_manifest.return_value = ["abc"]

    res = pusher.get_source_item_security_manifests(container_source_push_item, "/temp")

    assert res == [
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:abcdef", "/temp/security_manifest_source_abcd.json"
        )
    ]
    mock_quay_client.return_value.get_manifest_digest.assert_called_once_with(
        "some-registry/src/repo:2"
    )
    mock_get_security_manifest.assert_called_once_with(
        "some-registry/src/repo:2", "/temp/security_manifest_source_abcd.json"
    )


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_security_manifest"
)
@mock.patch("uuid.uuid4")
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_get_source_item_security_manifests_no_manifest(
    mock_quay_client,
    mock_uuid,
    mock_get_security_manifest,
    target_settings,
    container_source_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_source_push_item], target_settings
    )

    mock_quay_client.return_value.get_manifest_digest.return_value = "sha256:abcdef"
    mock_uuid.return_value.hex = "abcd"
    mock_get_security_manifest.return_value = []

    res = pusher.get_source_item_security_manifests(container_source_push_item, "/temp")
    assert res == []


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_security_manifest"
)
@mock.patch("uuid.uuid4")
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_get_multiarch_item_security_manifests(
    mock_quay_client,
    mock_uuid,
    mock_get_manifest,
    target_settings,
    container_multiarch_push_item,
    src_manifest_list,
    caplog,
):
    caplog.set_level(logging.ERROR)
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )

    mock_quay_client.return_value.get_manifest.return_value = src_manifest_list
    mock_uuid.return_value.hex = "abcd"
    mock_get_manifest.return_value = True

    res = pusher.get_multiarch_item_security_manifests(container_multiarch_push_item, "/temp")
    assert res == [
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:1111111111", "/temp/security_manifest_arm64_abcd.json"
        ),
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:2222222222", "/temp/security_manifest_armhfp_abcd.json"
        ),
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:3333333333", "/temp/security_manifest_ppc64le_abcd.json"
        ),
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:5555555555", "/temp/security_manifest_amd64_abcd.json"
        ),
    ]
    mock_quay_client.return_value.get_manifest.assert_called_once()
    assert mock_get_manifest.call_count == 4
    assert mock_get_manifest.call_args_list[0] == mock.call(
        "some-registry/src/repo@sha256:1111111111", "/temp/security_manifest_arm64_abcd.json"
    )
    assert mock_get_manifest.call_args_list[1] == mock.call(
        "some-registry/src/repo@sha256:2222222222", "/temp/security_manifest_armhfp_abcd.json"
    )
    assert mock_get_manifest.call_args_list[2] == mock.call(
        "some-registry/src/repo@sha256:3333333333", "/temp/security_manifest_ppc64le_abcd.json"
    )
    assert mock_get_manifest.call_args_list[3] == mock.call(
        "some-registry/src/repo@sha256:5555555555", "/temp/security_manifest_amd64_abcd.json"
    )

    assert caplog.messages == []


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_security_manifest"
)
@mock.patch("uuid.uuid4")
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_get_multiarch_item_security_manifests_not_present(
    mock_quay_client,
    mock_uuid,
    mock_get_manifest,
    target_settings,
    container_multiarch_push_item,
    src_manifest_list,
    caplog,
):
    caplog.set_level(logging.ERROR)
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )

    mock_quay_client.return_value.get_manifest.return_value = src_manifest_list
    mock_uuid.return_value.hex = "abcd"
    mock_get_manifest.return_value = False

    res = pusher.get_multiarch_item_security_manifests(container_multiarch_push_item, "/temp")
    assert res == []
    mock_quay_client.return_value.get_manifest.assert_called_once()
    assert mock_get_manifest.call_count == 4
    assert caplog.messages == []


@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.cosign_get_security_manifest"
)
@mock.patch("uuid.uuid4")
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_get_multiarch_item_security_manifests_some_present(
    mock_quay_client,
    mock_uuid,
    mock_get_manifest,
    target_settings,
    container_multiarch_push_item,
    src_manifest_list,
    caplog,
):
    caplog.set_level(logging.ERROR)
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )

    mock_quay_client.return_value.get_manifest.return_value = src_manifest_list
    mock_uuid.return_value.hex = "abcd"
    mock_get_manifest.side_effect = [True, False, True, False]

    res = pusher.get_multiarch_item_security_manifests(container_multiarch_push_item, "/temp")
    assert res == [
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:1111111111", "/temp/security_manifest_arm64_abcd.json"
        ),
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:3333333333", "/temp/security_manifest_ppc64le_abcd.json"
        ),
    ]
    mock_quay_client.return_value.get_manifest.assert_called_once()
    assert mock_get_manifest.call_count == 4
    assert caplog.messages == [
        "Only some architectures of multiarch image some-registry/src/repo:1 have a "
        "security manifest"
    ]


@mock.patch("tempfile.TemporaryDirectory")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "push_manifest_list_security_manifests"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "merge_and_push_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_source_item_security_manifests"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_multiarch_item_security_manifests"
)
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_push_item_security_manifest_source_image(
    mock_quay_client,
    mock_get_multiarch,
    mock_get_source,
    mock_merge_and_push,
    mock_push_ml_security_manifests,
    mock_tmpdir,
    target_settings,
    container_source_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_source_push_item], target_settings
    )
    retval = security_manifest_pusher.DigestSecurityManifest(
        "sha256:abcdef", "/temp/security_manifest_source_abcd.json"
    )
    mock_get_source.return_value = [retval]
    mock_quay_client.return_value.get_manifest.side_effect = ManifestTypeError("not found")
    mock_tmpdir.return_value.__enter__.return_value = "tmp/path"

    pusher.push_item_security_manifests(container_source_push_item)
    mock_quay_client.return_value.get_manifest.assert_called_once()
    mock_get_source.assert_called_once_with(container_source_push_item, "tmp/path")
    mock_get_multiarch.assert_not_called()
    mock_merge_and_push.assert_called_once_with(
        container_source_push_item,
        retval,
        ["quay.io/some-namespace/target----repo"],
        mock_tmpdir.return_value.__enter__.return_value,
    )
    mock_push_ml_security_manifests.assert_not_called()


@mock.patch("tempfile.TemporaryDirectory")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "push_manifest_list_security_manifests"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "merge_and_push_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_source_item_security_manifests"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_multiarch_item_security_manifests"
)
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_push_item_security_manifest_multiarch_image(
    mock_quay_client,
    mock_get_multiarch,
    mock_get_source,
    mock_merge_and_push,
    mock_push_ml_security_manifests,
    mock_tmpdir,
    target_settings,
    container_multiarch_push_item,
    manifest_list_data,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    retval = [
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:1111111111", "/temp/security_manifest_arm64_abcd.json"
        ),
        security_manifest_pusher.DigestSecurityManifest(
            "sha256:3333333333", "/temp/security_manifest_ppc64le_abcd.json"
        ),
    ]
    mock_get_multiarch.return_value = retval
    mock_quay_client.return_value.get_manifest.return_value = manifest_list_data
    mock_tmpdir.return_value.__enter__.return_value = "tmp/path"

    pusher.push_item_security_manifests(container_multiarch_push_item)
    mock_quay_client.return_value.get_manifest.assert_called_once()
    mock_get_source.assert_not_called()
    mock_get_multiarch.assert_called_once_with(container_multiarch_push_item, "tmp/path")
    assert mock_merge_and_push.call_count == 2
    assert mock_merge_and_push.call_args_list[0] == mock.call(
        container_multiarch_push_item,
        retval[0],
        ["quay.io/some-namespace/target----repo"],
        mock_tmpdir.return_value.__enter__.return_value,
    )
    assert mock_merge_and_push.call_args_list[1] == mock.call(
        container_multiarch_push_item,
        retval[1],
        ["quay.io/some-namespace/target----repo"],
        mock_tmpdir.return_value.__enter__.return_value,
    )

    mock_push_ml_security_manifests.assert_called_once_with(
        container_multiarch_push_item,
        "tmp/path",
    )


@mock.patch("tempfile.TemporaryDirectory")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "push_manifest_list_security_manifests"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "merge_and_push_security_manifest"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_source_item_security_manifests"
)
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher."
    "get_multiarch_item_security_manifests"
)
@mock.patch("pubtools._quay.security_manifest_pusher.QuayClient")
def test_push_item_security_manifest_v2s1_image(
    mock_quay_client,
    mock_get_multiarch,
    mock_get_source,
    mock_merge_and_push,
    mock_push_ml_security_manifests,
    mock_tmpdir,
    target_settings,
    container_multiarch_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item], target_settings
    )
    retval = security_manifest_pusher.DigestSecurityManifest(
        "sha256:abcdef", "/temp/security_manifest_source_abcd.json"
    )
    mock_get_source.return_value = [retval]
    mock_quay_client.return_value.get_manifest.side_effect = ManifestTypeError("not found")
    mock_tmpdir.return_value.__enter__.return_value.name = "tmp/path"

    pusher.push_item_security_manifests(container_multiarch_push_item)
    mock_quay_client.return_value.get_manifest.assert_called_once()
    mock_get_source.assert_not_called()
    mock_get_multiarch.assert_not_called()
    mock_merge_and_push.assert_not_called()
    mock_push_ml_security_manifests.assert_not_called()


@mock.patch("pubtools._quay.security_manifest_pusher.LocalExecutor")
@mock.patch(
    "pubtools._quay.security_manifest_pusher.SecurityManifestPusher.push_item_security_manifests"
)
def test_push_security_manifests(
    mock_push_item_security_manifests,
    mock_local_executor,
    target_settings,
    container_multiarch_push_item,
    container_source_push_item,
):
    pusher = security_manifest_pusher.SecurityManifestPusher(
        [container_multiarch_push_item, container_source_push_item], target_settings
    )
    pusher.push_security_manifests()

    mock_local_executor.return_value.__enter__.return_value.skopeo_login.assert_called_once_with(
        "quay.io", "dest-quay-user", "dest-quay-pass"
    )
    assert mock_push_item_security_manifests.call_count == 2
