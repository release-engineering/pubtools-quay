import pytest

from pubtools._quay.signer_wrapper import MsgSignerWrapper, SigningError


def test_store_error_signatures(msg_signer_settings, fake_cert_key_paths, dest_manifest_list):
    msg_signer = MsgSignerWrapper(config_file="fake-config-file", settings=msg_signer_settings)
    with pytest.raises(SigningError):
        msg_signer._store_signed(
            {
                "operation": {"references": ["fake-reference"]},
                "operation_results": [
                    (
                        {
                            "msg": {
                                "errors": ["simulated error"],
                                "manifest_digest": "fake-digest",
                                "reference": "fake-reference",
                                "repository": "fake-repo",
                            }
                        },
                        None,
                    )
                ],
            }
        )
