
import io
import uuid

import pytest

import app as trustvault


@pytest.fixture
def client(tmp_path):
    database_path = tmp_path / "test_trustvault.db"

    # Configure the app to use a temporary test database.
    trustvault.app.config.update(
        TESTING=True,
        SQLALCHEMY_DATABASE_URI=f"sqlite:///{database_path.as_posix()}",
    )

    # Initialize tables inside the application context.
    with trustvault.app.app_context():
        trustvault.db.session.remove()
        trustvault.db.engine.dispose()
        trustvault.db.create_all()

    # Provide a test client to each test.
    with trustvault.app.test_client() as test_client:
        yield test_client

    # Clean up the test database.
    with trustvault.app.app_context():
        trustvault.db.session.remove()
        trustvault.db.drop_all()
        trustvault.db.engine.dispose()


def register(client, username):
    unique_username = f"{username}_{uuid.uuid4().hex[:8]}"

    response = client.post(
        "/register",
        data={
            "username": unique_username,
            "password": "testpassword123",
        },
        follow_redirects=True,
    )

    return unique_username, response


def logout(client):
    return client.get("/logout", follow_redirects=True)


def test_register_account(client):
    username, response = register(client, "register_user")

    assert response.status_code == 200
    assert username.encode() in response.data


def test_login_and_logout(client):
    username, _ = register(client, "login_user")

    logout(client)

    response = client.post(
        "/login",
        data={
            "username": username,
            "password": "testpassword123",
        },
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert username.encode() in response.data


def test_upload_rejects_unsupported_file(client):
    register(client, "upload_user")

    response = client.post(
        "/upload",
        data={
            "document": (
                io.BytesIO(b"sample content"),
                "malware.exe",
            )
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"file type is not allowed" in response.data.lower()
