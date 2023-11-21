import mock

from pubtools._quay.signer_wrapper import CosignSignerWrapper


def test_remove_signatures(cosign_signer_settings, fake_cert_key_paths):
    with mock.patch("pubtools._quay.signer_wrapper.run_entrypoint") as mock_run_entry_point:
        mock_run_entry_point.return_value = (
            True,
            ["quay.io/testing/repository:sha256-123456789.sig"],
        )
        sw = CosignSignerWrapper(config_file="fake-config-file", settings=cosign_signer_settings)
        with mock.patch(
            "pubtools._quay.signer_wrapper.QuayApiClient.delete_tag"
        ) as mock_delete_tag:
            sw.remove_signatures([("sha256:123456789", "tag", "testing/repository")])
            mock_delete_tag.assert_called_once_with(
                "testing/testing----repository", "sha256-123456789.sig"
            )
