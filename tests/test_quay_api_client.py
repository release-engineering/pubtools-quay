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


def test_get_repo_data():
    client = quay_api_client.QuayApiClient("some-token", "stage.quay.io")

    with requests_mock.Mocker() as m:
        m.get(
            "https://stage.quay.io/api/v1/repository/some-repo",
            json={"some-data": "value"},
        )

        data = client.get_repository_data("some-repo")
        assert data == {"some-data": "value"}

        data = client.get_repository_data("some-repo", raw=True)
        assert data == '{"some-data": "value"}'

        assert m.call_count == 2


def test_delete_client():
    client = quay_api_client.QuayApiClient("some-token", "stage.quay.io")

    with requests_mock.Mocker() as m:
        m.delete(
            "https://stage.quay.io/api/v1/repository/some-repo/tag/10",
            [
                {"text": "Unauthorized", "status_code": 401},
                {"text": "Success", "status_code": 200},
                {"text": "Invalid repository tag 10", "status_code": 400},
            ],
        )
        with pytest.raises(requests.HTTPError, match="401 Client Error.*"):
            resp = client.delete_tag("some-repo", "10")

        resp = client.delete_tag("some-repo", "10")
        assert resp.status_code == 200
        resp = client.delete_tag("some-repo", "10")
        assert resp.text == "Invalid repository tag 10"
        assert resp.status_code == 400

        assert m.call_count == 3
