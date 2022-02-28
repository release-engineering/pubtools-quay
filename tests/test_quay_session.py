import mock
import pytest

from pubtools._quay import quay_session


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_init_docker_api(mock_session):
    mocked_session = mock.MagicMock()
    mocked_session.headers = {}
    mock_session.return_value = mocked_session

    session = quay_session.QuaySession(api="docker")

    assert session.hostname == "quay.io"
    assert session.session.verify is False
    assert session.session.headers["Host"] == "quay.io"
    assert session.api == "docker"
    assert session._api_url("some-endpoint") == "https://quay.io/v2/some-endpoint"


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_init_quay_api(mock_session):
    mocked_session = mock.MagicMock()
    mocked_session.headers = {}
    mock_session.return_value = mocked_session

    session = quay_session.QuaySession(api="quay")

    assert session.hostname == "quay.io"
    assert session.session.verify is False
    assert session.session.headers["Host"] == "quay.io"
    assert session.api == "quay"
    assert session._api_url("some-endpoint") == "https://quay.io/api/v1/some-endpoint"


def test_init_unsupported_api():
    with pytest.raises(ValueError, match="Unknown API type.*"):
        quay_session.QuaySession(api="unsupported")


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_api_url(mock_session):
    session1 = quay_session.QuaySession()
    result1 = session1._api_url("some/endpoint")
    assert result1 == "https://quay.io/v2/some/endpoint"

    session2 = quay_session.QuaySession("http://registry.com")
    result2 = session2._api_url("other/endpoint")
    assert result2 == "http://registry.com/v2/other/endpoint"


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_set_token(mock_session):
    mocked_session = mock.MagicMock()
    mocked_session.headers = {}
    mock_session.return_value = mocked_session

    session = quay_session.QuaySession()
    session.set_auth_token("some-token")

    assert session.session.headers["Authorization"] == "Bearer some-token"


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_get(mock_session):
    mocked_session = mock.MagicMock()
    mocked_session.headers = {}
    mock_session.return_value = mocked_session
    session = quay_session.QuaySession()

    kwargs = {"headers": {"Accept": "application/json"}}
    session.get("get/data/1", **kwargs)
    kwargs["timeout"] = 10
    mocked_session.get.assert_called_with("https://quay.io/v2/get/data/1", **kwargs)


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_post(mock_session):
    mocked_session = mock.MagicMock()
    mocked_session.headers = {}
    mock_session.return_value = mocked_session
    session = quay_session.QuaySession()

    kwargs = {"headers": {"Accept": "application/json"}, "data": "some data"}
    session.post("post/data/2", **kwargs)
    kwargs["timeout"] = 10
    mocked_session.post.assert_called_with("https://quay.io/v2/post/data/2", **kwargs)


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_put(mock_session):
    mocked_session = mock.MagicMock()
    mocked_session.headers = {}
    mock_session.return_value = mocked_session
    session = quay_session.QuaySession()

    kwargs = {"data": "new data"}
    session.put("put/data/3", **kwargs)
    kwargs["timeout"] = 10
    mocked_session.put.assert_called_with("https://quay.io/v2/put/data/3", **kwargs)


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_delete(mock_session):
    mocked_session = mock.MagicMock()
    mocked_session.headers = {}
    mock_session.return_value = mocked_session
    session = quay_session.QuaySession()

    kwargs = {"data": "old data"}
    session.delete("delete/data/4", **kwargs)
    kwargs["timeout"] = 10
    mocked_session.delete.assert_called_with("https://quay.io/v2/delete/data/4", **kwargs)


@mock.patch("pubtools._quay.quay_session.requests.Session")
def test_request(mock_session):
    mocked_session = mock.MagicMock()
    mocked_session.headers = {}
    mock_session.return_value = mocked_session
    session = quay_session.QuaySession()

    kwargs = {"headers": {"Accept": "application/json"}, "data": "some data"}
    session.request("POST", "post/data/2", **kwargs)
    kwargs["timeout"] = 10
    mocked_session.request.assert_called_with("POST", "https://quay.io/v2/post/data/2", **kwargs)
