import mock

import requests_mock

from pubtools._quay.signer_wrapper import CosignSignerWrapper


def test_remove_signatures(cosign_signer_settings, fake_cert_key_paths, dest_manifest_list):
    with mock.patch("pubtools._quay.signer_wrapper.run_entrypoint") as mock_run_entry_point:
        with requests_mock.Mocker() as m:
            m.get(
                "https://test-quay.io/v2/testing/testing----repository/manifests/sha256:123456789",
                json=dest_manifest_list,
                headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            )
            mock_run_entry_point.return_value = (
                True,
                ["quay.io/testing/repository:sha256-123456789.sig"],
            )
            sw = CosignSignerWrapper(
                config_file="fake-config-file", settings=cosign_signer_settings
            )
            # TODO: uncomment when cosign removing signatures is enabled
            # with mock.patch(
            #     "pubtools._quay.signer_wrapper.QuayApiClient.delete_tag"
            # ) as mock_delete_tag:
            sw.remove_signatures([("sha256:123456789", "tag", "testing/repository")])
            # mock_delete_tag.assert_not_called()
            # TODO: uncomment when removing signatures is enabled
            # mock_delete_tag.assert_called_once_with(
            #    "testing/testing----repository", "sha256-123456789.sig"
            # )


def test_remove_signatures_failure(cosign_signer_settings, fake_cert_key_paths, dest_manifest_list):
    with mock.patch("pubtools._quay.signer_wrapper.run_entrypoint") as mock_run_entry_point:
        with requests_mock.Mocker() as m:
            m.get(
                "https://test-quay.io/v2/testing/testing----repository/manifests/sha256:123456789",
                json=dest_manifest_list,
                headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
            )
            mock_run_entry_point.return_value = (
                False,
                "test-error",
            )
            sw = CosignSignerWrapper(
                config_file="fake-config-file", settings=cosign_signer_settings
            )
            # TODO: uncomment when cosign removing signatures is enabled
            # with mock.patch(
            #     "pubtools._quay.signer_wrapper.QuayApiClient.delete_tag"
            # ) as mock_delete_tag:
            sw.remove_signatures([("sha256:123456789", "tag", "testing/repository")])
            # mock_delete_tag.assert_not_called()
