import mock
import pytest

from pubtools._quay.signer_wrapper import SignerWrapper, SigningError, SignEntry, DirectSignerWrapper, EntryPointNotFoundError


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


def test_direct_signer_wrapper_success():
    import json
    import os

    settings = {
        "pyxis_server": "https://pyxis.example.com/graphql/",
        "pyxis_ssl_crtfile": "/path/to/cert",
        "pyxis_ssl_keyfile": "/path/to/key",
    }

    mock_ep = mock.MagicMock()

    # Simulate sign-container CLI behavior
    def mock_ep_side_effect():
        import sys
        args = sys.argv
        if "sign" in args:
            output_idx = args.index("--output-file") + 1
            output_path = args[output_idx]
            with open(output_path, "w") as f:
                json.dump([{"fake": "signature"}], f)
        elif "upload" in args:
            # Check inputs during upload
            input_idx = args.index("--input-file") + 1
            input_path = args[input_idx]
            assert os.path.exists(input_path)

    mock_ep.side_effect = mock_ep_side_effect

    with mock.patch("pkg_resources.load_entry_point", return_value=mock_ep), \
         mock.patch("pubtools._quay.signer_wrapper.get_pyxis_ssl_paths", return_value=("/path/to/cert", "/path/to/key")) as mock_paths:

        sw = DirectSignerWrapper(config_file="fake-config-file", settings=settings)

        sign_entries = [
            SignEntry(
                pub_reference="pub-ref",
                reference="fake-reference",
                digest="fake-digest",
                signing_key="fake-signing-key",
                arch="amd64",
                repo="fake-repo",
            )
        ]

        sw._sign_containers(sign_entries)

        assert mock_ep.call_count == 2


def test_direct_signer_wrapper_failure():
    settings = {
        "pyxis_server": "https://pyxis.example.com/graphql/",
    }

    mock_ep = mock.MagicMock()
    # Simulate non-zero CLI status exit
    mock_ep.side_effect = SystemExit(1)

    with mock.patch("pkg_resources.load_entry_point", return_value=mock_ep), \
         mock.patch("pubtools._quay.signer_wrapper.get_pyxis_ssl_paths", return_value=("/path/to/cert", "/path/to/key")):

        sw = DirectSignerWrapper(config_file="fake-config-file", settings=settings)

        sign_entries = [
            SignEntry(
                pub_reference="pub-ref",
                reference="fake-reference",
                digest="fake-digest",
                signing_key="fake-signing-key",
                arch="amd64",
                repo="fake-repo",
            )
        ]

        with pytest.raises(SigningError) as excinfo:
            sw._sign_containers(sign_entries)

        assert "sign-container failed with exit code 1" in str(excinfo.value)


def test_entry_point_not_found():
    # Simulate entry point loading failure
    with mock.patch("pkg_resources.load_entry_point", side_effect=ImportError("mocked import error")):
        sw = SignerWrapper(config_file="fake-config-file", settings={})
        with pytest.raises(EntryPointNotFoundError) as excinfo:
            _ = sw.entry_point

        assert "is not available: mocked import error" in str(excinfo.value)


def test_direct_signer_wrapper_remove_signatures():
    from pubtools._quay.signer_wrapper import DirectSignerWrapper

    settings = {
        "pyxis_server": "https://pyxis.example.com/graphql/",
    }

    mock_run_entrypoint = mock.MagicMock()

    with mock.patch("pubtools._quay.signer_wrapper.run_entrypoint_mod", mock_run_entrypoint), \
         mock.patch("pubtools._quay.signer_wrapper.get_pyxis_ssl_paths", return_value=("/path/to/cert", "/path/to/key")):

        def mock_fetch_signatures(manifest_digests):
            yield {
                "manifest_digest": "fake-digest",
                "reference": "fake-repo:fake-tag",
                "repository": "fake-repo",
                "_id": "fake-sig-id-123",
                "sig_key_id": "fake-signing-key",
            }

        sw = DirectSignerWrapper(config_file="fake-config-file", settings=settings)
        sw._fetch_signatures = mock_fetch_signatures

        # Call remove_signatures
        sw.remove_signatures([("fake-digest", "fake-tag", "fake-repo")])

        # Verify run_entrypoint_mod was called to delete the signatures with the filtered IDs
        mock_run_entrypoint.assert_called_once()
        args = mock_run_entrypoint.call_args[0]
        assert args[0] == ("pubtools-pyxis", "mod", "pubtools-pyxis-delete-signatures")
        assert args[1] == "pubtools-pyxis-delete-signatures"
        cli_args = args[2]
        assert "--pyxis-server" in cli_args
        assert "https://pyxis.example.com/graphql/" in cli_args
        assert "--ids" in cli_args


def test_direct_signer_wrapper_fetch_signatures():
    from pubtools._quay.signer_wrapper import DirectSignerWrapper

    settings = {
        "pyxis_server": "https://pyxis.example.com/graphql/",
    }

    mock_run_entrypoint = mock.MagicMock(return_value=[{"sig": "data"}])

    with mock.patch("pubtools._quay.signer_wrapper.run_entrypoint_mod", mock_run_entrypoint), \
         mock.patch("pubtools._quay.signer_wrapper.get_pyxis_ssl_paths", return_value=("/path/to/cert", "/path/to/key")):

        sw = DirectSignerWrapper(config_file="fake-config-file", settings=settings)
        sigs = list(sw._fetch_signatures(["fake-digest"]))

        assert sigs == [{"sig": "data"}]
        mock_run_entrypoint.assert_called_once()
        args = mock_run_entrypoint.call_args[0]
        assert args[0] == ("pubtools-pyxis", "mod", "pubtools-pyxis-get-signatures")



