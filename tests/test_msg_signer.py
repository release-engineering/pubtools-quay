import mock

from pubtools._quay.signer_wrapper import MsgSignerWrapper


def test_remove_signatures(
    msg_signer_settings, fake_cert_key_paths, signer_wrapper_remove_signatures
):
    with mock.patch("pubtools._quay.signer_wrapper.run_entrypoint") as mock_run_entry_point:
        mock_run_entry_point.return_value = [
            {
                "_id": 1,
                "manifest_digest": "digest",
                "reference": "reference:tag",
                "repository": "repository",
                "sig_key_id": "sig-key",
            }
        ]
        sw = MsgSignerWrapper(config_file="fake-config-file", settings=msg_signer_settings)

        sw.remove_signatures([("digest", "tag", "repository")])
        signer_wrapper_remove_signatures.assert_called_once_with([1])
