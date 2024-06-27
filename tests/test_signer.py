import mock
import pytest

from pubtools._quay.signer_wrapper import SignerWrapper, SigningError, SignEntry


def test_signer_wrapper_entry_point():
    with mock.patch("pkg_resources.load_entry_point") as mock_load_entry_point:
        sw = SignerWrapper(config_file="fake-config-file", settings={})
        sw.entry_point()
        mock_load_entry_point.assert_called_once_with("signer", "group", "signer")


def test_signer_remove_signatures():
    with mock.patch(
        "pubtools._quay.signer_wrapper.SignerWrapper._remove_signatures"
    ) as mock_remove:
        sw = SignerWrapper(config_file="fake-config-file", settings={})
        sw.remove_signatures(1)
        mock_remove.assert_called_once_with(
            1,
        )


def test_sign_containers_failed():
    with mock.patch("pkg_resources.load_entry_point") as mock_load_entry_point:
        sw = SignerWrapper(config_file="fake-config-file", settings={})
        sw.entry_point()
        mock_load_entry_point.return_value = {
            "signer_result": {"status": "error", "error_message": "fake-error-message"}
        }
        with pytest.raises(SigningError):
            sw._sign_containers(
                [
                    SignEntry(
                        pub_reference="",
                        reference="fake-reference",
                        digest="fake-digest",
                        signing_key="fake-signing-key",
                        arch="amd64",
                        repo="fake-repo",
                    )
                ]
            )
