import json
import mock
import pytest
import requests
import requests.exceptions
import requests_mock

from pubtools._quay import quay_client, exceptions
from pubtools._quay.exceptions import ManifestNotFoundError


@mock.patch("pubtools._quay.quay_client.QuaySession")
def test_init(mock_session):
    client = quay_client.QuayClient("user", "pass", "stage.quay.io")

    assert client.username == "user"
    assert client.password == "pass"
    assert client.session == mock_session.return_value
    mock_session.assert_called_once_with(api="docker", hostname="stage.quay.io")


@mock.patch("pubtools._quay.quay_client.QuaySession")
def test_parse_image(mock_session):
    client = quay_client.QuayClient("user", "pass", "stage.quay.io")

    repo, ref = client._parse_and_validate_image_url("quay.io/name/image:1")
    assert repo == "name/image"
    assert ref == "1"

    repo, ref = client._parse_and_validate_image_url("quay.io/name2/image2@sha256:dfgdfg8df5g")
    assert repo == "name2/image2"
    assert ref == "sha256:dfgdfg8df5g"

    with pytest.raises(ValueError, match="Neither tag nor digest were found in the image"):
        client._parse_and_validate_image_url("quay.io/name/image")


@mock.patch("pubtools._quay.quay_client.QuaySession")
def test_authenticate_quay_header_error(mock_session):
    client = quay_client.QuayClient("user", "pass")

    header1 = {
        "Server": "nginx/1.12.1",
        "Date": "Tue, 02 Feb 2021 13:03:35 GMT",
        "Content-Type": "application/json",
        "Content-Length": "112",
        "Connection": "close",
        "Docker-Distribution-API-Version": "registry/2.0",
    }
    with pytest.raises(exceptions.RegistryAuthError, match="'WWW-Authenticate' is not in the.*"):
        client._authenticate_quay(header1)

    header2 = {
        "Server": "nginx/1.12.1",
        "Date": "Tue, 02 Feb 2021 13:03:35 GMT",
        "Content-Type": "application/json",
        "Content-Length": "112",
        "Connection": "close",
        "Docker-Distribution-API-Version": "registry/2.0",
        "WWW-Authenticate": 'Basic realm="https://quay.io/v2/auth",service="quay.io",'
        'scope="repository:namespace/some-repo:pull"',
    }
    with pytest.raises(exceptions.RegistryAuthError, match="Different than the Bearer.*"):
        client._authenticate_quay(header2)


@mock.patch("pubtools._quay.quay_client.QuaySession")
@mock.patch("pubtools._quay.quay_client.requests.Session")
def test_authenticate_quay_success(mock_session, mock_quay_session):
    mock_response = mock.MagicMock()
    mock_response.json.return_value = {"token": "abcdef"}
    mock_get = mock.MagicMock()
    mock_get.return_value = mock_response
    mocked_session = mock.MagicMock()
    mocked_session.get = mock_get
    mock_session.return_value = mocked_session

    mocked_quay_session = mock.MagicMock()
    mock_quay_session.return_value = mocked_quay_session

    client = quay_client.QuayClient("user", "pass")
    header = {
        "Server": "nginx/1.12.1",
        "Date": "Tue, 02 Feb 2021 13:03:35 GMT",
        "Content-Type": "application/json",
        "Content-Length": "112",
        "Connection": "close",
        "Docker-Distribution-API-Version": "registry/2.0",
        "WWW-Authenticate": 'Bearer realm="https://quay.io/v2/auth",service="quay.io",'
        'scope="repository:namespace/some-repo:pull"',
    }
    client._authenticate_quay(header)

    mocked_session.get.assert_called_once_with(
        "https://quay.io/v2/auth",
        auth=("user", "pass"),
        params={"service": "quay.io", "scope": "repository:namespace/some-repo:pull"},
        timeout=10,
    )
    mocked_quay_session.set_auth_token.assert_called_once_with("abcdef")


@mock.patch("pubtools._quay.quay_client.QuaySession")
@mock.patch("pubtools._quay.quay_client.requests.Session")
def test_authenticate_quay_missing_token(mock_session, mock_quay_session):
    mock_response = mock.MagicMock()
    mock_response.json.return_value = {"bad_data": "abcdef"}
    mock_get = mock.MagicMock()
    mock_get.return_value = mock_response
    mocked_session = mock.MagicMock()
    mocked_session.get = mock_get
    mock_session.return_value = mocked_session

    mocked_quay_session = mock.MagicMock()
    mock_quay_session.return_value = mocked_quay_session

    client = quay_client.QuayClient("user", "pass")
    header = {
        "Server": "nginx/1.12.1",
        "Date": "Tue, 02 Feb 2021 13:03:35 GMT",
        "Content-Type": "application/json",
        "Content-Length": "112",
        "Connection": "close",
        "Docker-Distribution-API-Version": "registry/2.0",
        "WWW-Authenticate": 'Bearer realm="https://quay.io/v2/auth",service="quay.io",'
        'scope="repository:namespace/some-repo:pull"',
    }

    with pytest.raises(exceptions.RegistryAuthError, match="Authentication server response.*"):
        client._authenticate_quay(header)


@mock.patch("pubtools._quay.quay_client.QuayClient._authenticate_quay")
def test_request_quay_success(mock_authenticate):
    with requests_mock.Mocker() as m:
        m.get("https://quay.io/v2/get/data/1", text="data")

        client = quay_client.QuayClient("user", "pass")
        r = client._request_quay("GET", "get/data/1")

        assert r.text == "data"
        assert r.status_code == 200
        mock_authenticate.assert_not_called()


def test_request_quay_bad_status_code():
    with requests_mock.Mocker() as m:
        m.get("https://quay.io/v2/get/data/1", text="data", status_code=404)

        client = quay_client.QuayClient("user", "pass")
        with pytest.raises(requests.HTTPError, match="404 Client Error.*"):
            client._request_quay("GET", "get/data/1")


@mock.patch("pubtools._quay.quay_client.QuayClient._authenticate_quay")
def test_request_quay_authenticate_success(mock_authenticate):
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/get/data/1",
            [
                {"headers": {"some-header": "value"}, "status_code": 401},
                {"text": "data", "status_code": 200},
            ],
        )

        client = quay_client.QuayClient("user", "pass")
        r = client._request_quay("GET", "get/data/1")

        assert r.text == "data"
        assert r.status_code == 200
        mock_authenticate.assert_called_once_with({"some-header": "value"})


@mock.patch("pubtools._quay.quay_client.QuayClient._authenticate_quay")
def test_request_quay_authenticate_missing(mock_authenticate):
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/get/data/1",
            [
                {"headers": {"some-header": "value"}, "status_code": 401},
                {"text": "missing", "status_code": 404},
            ],
        )

        client = quay_client.QuayClient("user", "pass")

        with pytest.raises(requests.HTTPError, match="404 Client Error.*"):
            client._request_quay("GET", "get/data/1")
        mock_authenticate.assert_called_once_with({"some-header": "value"})


def test_get_manifest_list_success():
    ml = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 429,
                "digest": "sha256:6d5f4d65fg4d6f54g",
                "platform": {"architecture": "arm64", "os": "linux"},
            }
        ],
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            json=ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        ret_ml = client.get_manifest(
            "quay.io/namespace/image:1",
            media_type="application/vnd.docker.distribution.manifest.list.v2+json",
        )
        assert m.call_count == 1

    assert ml == ret_ml


def test_get_manifest_list_raw_success():
    ml = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 429,
                "digest": "sha256:6d5f4d65fg4d6f54g",
                "platform": {"architecture": "arm64", "os": "linux"},
            }
        ],
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            json=ml,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.list.v2+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        ret_ml = client.get_manifest(
            "quay.io/namespace/image:1",
            raw=True,
            media_type="application/vnd.docker.distribution.manifest.list.v2+json",
        )
        assert m.call_count == 1

    assert json.dumps(ml) == ret_ml


def test_get_manifest_list_wrong_type():
    manifest = {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "size": 429,
        "digest": "sha256:6d5f4d65fg4d6f54g",
        "platform": {"architecture": "arm64", "os": "linux"},
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            json=manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        with pytest.raises(exceptions.ManifestTypeError, match=".*doesn't have a .* manifest"):
            client.get_manifest(
                "quay.io/namespace/image:1",
                media_type="application/vnd.docker.distribution.manifest.list.v2+json",
            )
        assert m.call_count == 1


def test_get_manifest_success():
    manifest = {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "size": 429,
        "digest": "sha256:6d5f4d65fg4d6f54g",
        "platform": {"architecture": "arm64", "os": "linux"},
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            json=manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        ret_manifest = client.get_manifest("quay.io/namespace/image:1")
        assert m.call_count == 2

    assert manifest == ret_manifest


def test_get_manifest_v2s2_second_attempt():
    v2s1_manifest = {
        "name": "hello-world",
        "tag": "latest",
        "architecture": "amd64",
        "fsLayers": [],
        "history": [],
        "schemaVersion": 1,
        "signatures": [],
    }
    v2s2_manifest = {
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "size": 429,
        "digest": "sha256:6d5f4d65fg4d6f54g",
        "platform": {"architecture": "arm64", "os": "linux"},
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            [
                {
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.v1+json"
                    },
                    "json": v2s1_manifest,
                },
                {
                    "headers": {
                        "Content-Type": "application/vnd.docker.distribution.manifest.v2+json"
                    },
                    "json": v2s2_manifest,
                },
            ],
        )

        client = quay_client.QuayClient("user", "pass")
        ret_manifest = client.get_manifest("quay.io/namespace/image:1")
        assert m.call_count == 2

    assert v2s2_manifest == ret_manifest


def test_get_manifest_accept_any():
    v2s1_manifest = {
        "name": "hello-world",
        "tag": "latest",
        "architecture": "amd64",
        "fsLayers": [],
        "history": [],
        "schemaVersion": 1,
        "signatures": [],
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            json=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        ret_manifest = client.get_manifest("quay.io/namespace/image:1")
        assert m.call_count == 5

    assert v2s1_manifest == ret_manifest


def test_get_v2s1_manifest():
    v2s1_manifest = {
        "name": "hello-world",
        "tag": "latest",
        "architecture": "amd64",
        "fsLayers": [],
        "history": [],
        "schemaVersion": 1,
        "signatures": [],
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            json=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        ret_manifest = client.get_manifest(
            "quay.io/namespace/image:1",
            media_type="application/vnd.docker.distribution.manifest.v1+json",
        )
        assert m.call_count == 1

    assert v2s1_manifest == ret_manifest


def test_get_v2s2_manifest():
    v2s2_manifest = {
        "name": "hello-world",
        "tag": "latest",
        "architecture": "amd64",
        "fsLayers": [],
        "history": [],
        "schemaVersion": 2,
        "signatures": [],
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            json=v2s2_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        ret_manifest = client.get_manifest(
            "quay.io/namespace/image:1",
            media_type="application/vnd.docker.distribution.manifest.v2+json",
        )
        assert m.call_count == 1

    assert v2s2_manifest == ret_manifest


def test_get_v2s1_manifest_wrong_type():
    v2s2_manifest = {
        "mediaType": "application/vnd.docker.distribution.manifest.v1+json",
        "size": 429,
        "digest": "sha256:6d5f4d65fg4d6f54g",
        "platform": {"architecture": "arm64", "os": "linux"},
    }

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            json=v2s2_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        with pytest.raises(
            exceptions.ManifestTypeError,
            match=r".*doesn't have a application/vnd\."
            r"docker\.distribution\.manifest\.v2\+json manifest",
        ):
            client.get_manifest(
                "quay.io/namespace/image:1",
                media_type="application/vnd.docker.distribution.manifest.v2+json",
            )
        assert m.call_count == 1


def test_get_v2s1_manifest_raw():
    v2s1_manifest_data = {
        "name": "hello-world",
        "tag": "latest",
        "architecture": "amd64",
        "fsLayers": [],
        "history": [],
        "schemaVersion": 1,
        "signatures": [],
    }
    v2s1_manifest = json.dumps(v2s1_manifest_data, sort_keys=True, indent=4)

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            text=v2s1_manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v1+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        ret_manifest = client.get_manifest(
            "quay.io/namespace/image:1",
            media_type="application/vnd.docker.distribution.manifest.v1+json",
            raw=True,
        )
        assert m.call_count == 1

    assert v2s1_manifest == ret_manifest


def test_upload_manifest_list_success():
    ml = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 429,
                "digest": "sha256:6d5f4d65fg4d6f54g",
                "platform": {"architecture": "arm64", "os": "linux"},
            }
        ],
    }

    with requests_mock.Mocker() as m:
        m.put("https://quay.io/v2/namespace/image/manifests/1", status_code=200)

        client = quay_client.QuayClient("user", "pass")
        client.upload_manifest(ml, "quay.io/namespace/image:1")
        assert m.call_count == 1
        assert m.request_history[0].json() == ml


def test_upload_raw_manifest_success():
    ml = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 429,
                "digest": "sha256:6d5f4d65fg4d6f54g",
                "platform": {"architecture": "arm64", "os": "linux"},
            }
        ],
    }

    with requests_mock.Mocker() as m:
        m.put("https://quay.io/v2/namespace/image/manifests/1", status_code=200)

        client = quay_client.QuayClient("user", "pass")
        client.upload_manifest(json.dumps(ml), "quay.io/namespace/image:1", raw=True)
        assert m.call_count == 1
        assert m.request_history[0].json() == ml


def test_upload_manifest_list_failure():
    ml = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
        "manifests": [
            {
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "size": 429,
                "digest": "sha256:6d5f4d65fg4d6f54g",
                "platform": {"architecture": "arm64", "os": "linux"},
            }
        ],
    }

    with requests_mock.Mocker() as m:
        m.put("https://quay.io/v2/namespace/image/manifests/1", status_code=400)

        client = quay_client.QuayClient("user", "pass")
        with pytest.raises(requests.HTTPError, match="400 Client Error.*"):
            client.upload_manifest(ml, "quay.io/namespace/image:1")
        assert m.call_count == 1


def test_get_repository_tags_no_pagination():
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/tags/list",
            json={"name": "namespace/image", "tags": ["1", "2", "3"]},
        )

        client = quay_client.QuayClient("user", "pass")
        data = client.get_repository_tags("namespace/image")
        assert data == {"name": "namespace/image", "tags": ["1", "2", "3"]}
        assert m.call_count == 1


def test_get_repository_tags_raw():
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/tags/list",
            json={"name": "namespace/image", "tags": ["1", "2", "3"]},
        )

        client = quay_client.QuayClient("user", "pass")
        data = client.get_repository_tags("namespace/image", "raw")
        assert data == json.dumps({"name": "namespace/image", "tags": ["1", "2", "3"]})
        assert m.call_count == 1


def test_get_repository_tags_pagination():
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/tags/list",
            json={"name": "namespace/image", "tags": ["1", "2", "3"]},
            headers={"Link": '</v2/namespace/image/tags/list/next-page-2>; rel="next"'},
        )
        m.get(
            "https://quay.io/v2/namespace/image/tags/list/next-page-2",
            json={"name": "namespace/image", "tags": ["4", "5", "6"]},
            headers={"Link": '</v2/namespace/image/tags/list/next-page-3>; rel="next"'},
        )
        m.get(
            "https://quay.io/v2/namespace/image/tags/list/next-page-3",
            json={"name": "namespace/image", "tags": ["7", "8", "9"]},
        )

        client = quay_client.QuayClient("user", "pass")
        data = client.get_repository_tags("namespace/image")
        assert data == {
            "name": "namespace/image",
            "tags": ["1", "2", "3", "4", "5", "6", "7", "8", "9"],
        }
        assert m.call_count == 3


def test_get_repository_tags_pagination_cannot_parse_url():
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/tags/list",
            json={"name": "namespace/image", "tags": ["1", "2", "3"]},
            headers={"Link": '/v2/namespace/image/tags/list/next-page-2; rel="next"'},
        )

        client = quay_client.QuayClient("user", "pass")
        with pytest.raises(ValueError, match="Could not extract next page URL.*"):
            client.get_repository_tags("namespace/image")

        assert m.call_count == 1


def test_get_manifest_digest():
    manifest = (
        '{"mediaType": "application/vnd.docker.distribution.manifest.v2+json",'
        ' "size": 429, "digest": "sha256:6d5f4d65fg4d6f54g",'
        ' "platform": {"architecture": "arm64", "os": "linux"}}'
    )

    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            text=manifest,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        client = quay_client.QuayClient("user", "pass")
        digest = client.get_manifest_digest("quay.io/namespace/image:1")
        assert m.call_count == 2

        assert digest == "sha256:b9742c91f353022604e8ed4cf4ab1d688114fc4b133f0e11cbf7dd6272753ac8"


def test_get_manifest_digest_not_found():
    client = quay_client.QuayClient("user", "pass")
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            status_code=404,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        with pytest.raises(ManifestNotFoundError):
            client.get_manifest_digest("quay.io/namespace/image:1")


def test_get_manifest_digest_unkown_error():
    client = quay_client.QuayClient("user", "pass")
    with requests_mock.Mocker() as m:
        m.get(
            "https://quay.io/v2/namespace/image/manifests/1",
            status_code=500,
            headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
        )

        with pytest.raises(requests.exceptions.HTTPError):
            client.get_manifest_digest("quay.io/namespace/image:1")
