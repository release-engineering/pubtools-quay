import mock
import pytest
import requests
import requests_mock

from pubtools._quay import quay_api_client


@mock.patch("pubtools._quay.quay_api_client.QuaySession")
def test_init(mock_session):
    client = quay_api_client.QuayApiClient("some-token", "stage.quay.io")

    assert client.token == "some-token"
    mock_session.assert_called_once_with(hostname="stage.quay.io", api="quay")
    mock_session.return_value.set_auth_token.assert_called_once_with("some-token")


def test_delete_client():
    client = quay_api_client.QuayApiClient("some-token", "stage.quay.io")

    with requests_mock.Mocker() as m:
        m.delete(
            "https://stage.quay.io/api/v1/repository/some-repo/tag/10",
            [
                {"text": "Unauthorized", "status_code": 401},
                {"text": "Success", "status_code": 200},
                {"text": "Not found", "status_code": 404},
            ],
        )
        with pytest.raises(requests.HTTPError, match="401 Client Error.*"):
            resp = client.delete_tag("some-repo", "10")

        resp = client.delete_tag("some-repo", "10")
        assert resp.status_code == 200
        resp = client.delete_tag("some-repo", "10")
        assert resp.text == "Not found"
        assert resp.status_code == 404

        assert m.call_count == 3


def test_delete_repository():
    client = quay_api_client.QuayApiClient("some-token", "stage.quay.io")

    with requests_mock.Mocker() as m:
        m.delete(
            "https://stage.quay.io/api/v1/repository/some-namespace/some-repo",
            [
                {"text": "Server error", "status_code": 500},
                {"text": "Success", "status_code": 200},
            ],
        )
        with pytest.raises(requests.HTTPError, match="500 Server Error.*"):
            client.delete_repository("some-namespace/some-repo")

        response = client.delete_repository("some-namespace/some-repo")
        assert response.status_code == 200

        assert m.call_count == 2
