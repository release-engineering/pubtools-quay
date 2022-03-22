import sys

import mock

from pubtools._quay import tag_images

sys.modules["rhmsg"] = mock.MagicMock()
sys.modules["rhmsg.activemq"] = mock.MagicMock()
module_mock = mock.MagicMock()
sys.modules["rhmsg.activemq.producer"] = module_mock


@mock.patch("pubtools._quay.tag_images.LocalExecutor")
def test_run_tag_entrypoint_local_success(mock_local_executor, hookspy):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
    ]
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    mock_local_executor.return_value.__enter__.return_value = mock_local_executor.return_value
    mock_tag_images = mock.MagicMock()
    mock_local_executor.return_value.tag_images = mock_tag_images

    tag_images.tag_images_main(args)

    mock_local_executor.assert_called_once_with()
    mock_skopeo_login.assert_called_once_with("quay.io", None, None)
    mock_tag_images.assert_called_once_with(
        "quay.io/repo/souce-image:1", ["quay.io/repo/target-image:1"], False
    )

    assert hookspy == [
        ("task_start", {}),
        (
            "quay_images_tagged",
            {
                "dest_refs": ["quay.io/repo/target-image:1"],
                "source_ref": "quay.io/repo/souce-image:1",
            },
        ),
        ("task_stop", {"failed": False}),
    ]


@mock.patch("pubtools._quay.tag_images.LocalExecutor")
def test_run_tag_entrypoint_local_success_all_arch(mock_local_executor):
    args = [
        "dummy",
        "--source-ref",
        "src.quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--all-arch",
        "--source-quay-host",
        "src.quay.io",
        "--source-quay-user",
        "src-user",
        "--source-quay-password",
        "src-password",
    ]
    mock_skopeo_login = mock.MagicMock()
    mock_local_executor.return_value.skopeo_login = mock_skopeo_login
    mock_local_executor.return_value.__enter__.return_value = mock_local_executor.return_value
    mock_tag_images = mock.MagicMock()
    mock_local_executor.return_value.tag_images = mock_tag_images

    tag_images.tag_images_main(args)

    mock_local_executor.assert_called_once_with()
    assert len(mock_skopeo_login.mock_calls) == 2
    assert mock_skopeo_login.call_args_list == [
        mock.call("quay.io", None, None),
        mock.call("src.quay.io", "src-user", "src-password"),
    ]
    mock_tag_images.assert_called_once_with(
        "src.quay.io/repo/souce-image:1", ["quay.io/repo/target-image:1"], True
    )


@mock.patch("pubtools._quay.tag_images.RemoteExecutor")
def test_run_tag_entrypoint_remote_success(mock_remote_executor):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--remote-exec",
        "--ssh-remote-host",
        "127.0.0.1",
        "--ssh-reject-unknown-host",
        "--ssh-username",
        "dummy",
        "--ssh-password",
        "123456",
        "--ssh-key-filename",
        "/path/to/file.key",
    ]
    mock_skopeo_login = mock.MagicMock()
    mock_remote_executor.return_value.skopeo_login = mock_skopeo_login
    mock_remote_executor.return_value.__enter__.return_value = mock_remote_executor.return_value
    mock_tag_images = mock.MagicMock()
    mock_remote_executor.return_value.tag_images = mock_tag_images

    tag_images.tag_images_main(args)

    mock_remote_executor.assert_called_once_with(
        "127.0.0.1", "dummy", "/path/to/file.key", "123456", None, False
    )
    mock_skopeo_login.assert_called_once_with("quay.io", None, None)
    mock_tag_images.assert_called_once_with(
        "quay.io/repo/souce-image:1", ["quay.io/repo/target-image:1"], False
    )


@mock.patch("pubtools._quay.tag_images.ContainerExecutor")
def test_run_tag_entrypoint_container_success(mock_container_executor):
    args = [
        "dummy",
        "--source-ref",
        "quay.io/repo/souce-image:1",
        "--dest-ref",
        "quay.io/repo/target-image:1",
        "--container-exec",
        "--container-image",
        "quay.io/some/image:1",
        "--docker-url",
        "some-url.com",
        "--docker-timeout",
        "120",
        "--docker-verify-tls",
        "--docker-cert-path",
        "/some/path",
        "--registry-username",
        "registry-user",
        "--registry-password",
        "registry-passwd",
    ]
    mock_skopeo_login = mock.MagicMock()
    mock_container_executor.return_value.skopeo_login = mock_skopeo_login
    mock_container_executor.return_value.__enter__.return_value = (
        mock_container_executor.return_value
    )
    mock_tag_images = mock.MagicMock()
    mock_container_executor.return_value.tag_images = mock_tag_images

    tag_images.tag_images_main(args)

    mock_container_executor.assert_called_once_with(
        "quay.io/some/image:1",
        "some-url.com",
        120,
        True,
        "/some/path",
        "registry-user",
        "registry-passwd",
    )
    mock_skopeo_login.assert_called_once_with("quay.io", None, None)
    mock_tag_images.assert_called_once_with(
        "quay.io/repo/souce-image:1", ["quay.io/repo/target-image:1"], False
    )
