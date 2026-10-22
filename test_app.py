
import io
import uuid

import pytest
import app as trustvault


@pytest.fixture
def client():
    trustvault.app.config["TESTING"] = True
    trustvault.app.config["WTF_CSRF_ENABLED"] = False

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


def login(client, username):
    return client.post(
        "/login",
        data={
            "username": username,
            "password": "testpassword123",
        },
        follow_redirects=True,
    )


def upload_document(client, filename, content):
    return client.post(
        "/upload",
        data={
            "document": (io.BytesIO(content), filename),
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )


def find_document_id(username, filename):
    with trustvault.app.app_context():
        owner = trustvault.User.query.filter_by(
            username=username
        ).first()

        assert owner is not None

        document = trustvault.Document.query.filter_by(
            owner_id=owner.id,
            original_name=filename,
        ).first()

        assert document is not None
        return document.id


def test_register_account(client):
    username, response = register(client, "register_user")

    assert response.status_code == 200
    assert username.encode() in response.data


def test_login_and_logout(client):
    username, _ = register(client, "login_user")

    logout(client)
    response = login(client, username)

    assert response.status_code == 200
    assert username.encode() in response.data


def test_upload_rejects_unsupported_file(client):
    register(client, "upload_user")

    response = upload_document(
        client,
        "malware.exe",
        b"sample content",
    )

    assert response.status_code == 200
    assert b"file type is not allowed" in response.data.lower()


def test_other_user_cannot_download_private_document(client):
    owner_username, _ = register(client, "private_owner")

    upload_response = upload_document(
        client,
        "private.txt",
        b"private document content",
    )
    assert upload_response.status_code == 200

    document_id = find_document_id(owner_username, "private.txt")

    logout(client)
    _, _ = register(client, "private_viewer")

    response = client.get(f"/download/{document_id}")

    assert response.status_code == 403


def test_revoked_user_cannot_download_document(client):
    owner_username, _ = register(client, "revoke_owner")

    upload_response = upload_document(
        client,
        "confidential.txt",
        b"confidential content",
    )
    assert upload_response.status_code == 200

    document_id = find_document_id(
        owner_username,
        "confidential.txt",
    )

    logout(client)
    viewer_username, _ = register(client, "revoke_viewer")

    # The owner grants read access to the viewer.
    logout(client)
    login(client, owner_username)

    share_response = client.post(
        f"/share/{document_id}",
        data={
            "username": viewer_username,
            "can_read": "on",
        },
        follow_redirects=True,
    )
    assert share_response.status_code == 200

    # Confirm the viewer can download before revocation.
    logout(client)
    login(client, viewer_username)

    allowed_response = client.get(f"/download/{document_id}")
    assert allowed_response.status_code == 200
    assert allowed_response.data == b"confidential content"

    # The owner revokes access.
    logout(client)
    login(client, owner_username)

    revoke_response = client.post(
        f"/revoke/{document_id}",
        data={"username": viewer_username},
        follow_redirects=True,
    )
    assert revoke_response.status_code == 200

    # The viewer must be denied after revocation.
    logout(client)
    login(client, viewer_username)

    denied_response = client.get(f"/download/{document_id}")
    assert denied_response.status_code == 403


def test_csrf_rejects_post_without_token(client):
    trustvault.app.config["WTF_CSRF_ENABLED"] = True

    try:
        response = client.post(
            "/register",
            data={
                "username": "csrf_test_user",
                "password": "TestPassword123!",
            },
        )
        assert response.status_code == 400
    finally:
        trustvault.app.config["WTF_CSRF_ENABLED"] = False
