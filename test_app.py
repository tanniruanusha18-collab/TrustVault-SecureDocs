
import io
import uuid
import pytest
import app as trustvault


@pytest.fixture
def client():
    trustvault.app.config["TESTING"] = True

    with trustvault.app.test_client() as test_client:
        yield test_client


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


def test_other_user_cannot_download_private_document(client):
    owner_username, _ = register(client, "private_owner")

    upload_response = client.post(
        "/upload",
        data={
            "document": (
                io.BytesIO(b"private document content"),
                "private.txt",
            )
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )

    assert upload_response.status_code == 200

    with trustvault.app.app_context():
        owner = trustvault.User.query.filter_by(
            username=owner_username
        ).first()

        document = trustvault.Document.query.filter_by(
            owner_id=owner.id,
            original_name="private.txt",
        ).first()

        assert document is not None
        document_id = document.id

    logout(client)

    _, login_response = register(client, "private_viewer")
    assert login_response.status_code == 200

    response = client.get(f"/download/{document_id}")

    assert response.status_code == 403
