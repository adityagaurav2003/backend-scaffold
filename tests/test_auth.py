import sys
import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.auth import create_access_token, verify_token


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "FastAPI Backend is running!"

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_register_login_and_protected():
    # Register
    response = client.post("/auth/register", json={
        "username": "testuser",
        "password": "testpass",
        "email": "testuser@example.com"
    })
    assert response.status_code == 200

    # Login
    response = client.post("/auth/login", json={
        "username": "testuser",
        "password": "testpass"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data

    # Access protected route
    headers = {"Authorization": f"Bearer {data['access_token']}"}
    response = client.get("/protected", headers=headers)
    assert response.status_code == 200
    assert "Hello testuser" in response.json()["message"]

def test_jwt_token_creation_and_verification():
    data = {"sub": "sampleuser"}
    token = create_access_token(data)
    username = verify_token(token)
    assert username == "sampleuser"
