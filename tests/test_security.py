import pytest
from app import app as flask_app

@pytest.fixture
def client():
    with flask_app.test_client() as client:
        yield client

def test_sql_injection(client):
    payload = "admin' OR '1'='1"
    response = client.post('/login', data={'username': payload, 'password': 'any'})
    assert b"\xd0\x92\xd1\x96\xd1\x82\xd0\xb0\xd1\x94\xd0\xbc\xd0\xbe" not in response.data

def test_xss(client):
    payload = "<script>alert(1)</script>"
    response = client.post('/login', data={'username': payload, 'password': "admin' OR '1'='1"})
    assert payload.encode() not in response.data

def test_command_injection(client):
    response = client.post('/run', data={'cmd': 'id'})
    assert b"uid=" not in response.data
