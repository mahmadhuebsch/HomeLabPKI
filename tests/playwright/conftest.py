"""Playwright test configuration."""

import os
import subprocess
import time
import pytest
from playwright.sync_api import Page

@pytest.fixture(scope="function", autouse=True)
def live_server():
    """Start a live server for each test function."""
    # Reset the config file before each test
    if os.path.exists("config.yaml"):
        os.remove("config.yaml")

    process = subprocess.Popen(["python", "main.py"])
    time.sleep(5)  # Give the server time to start
    yield
    process.terminate()
    process.wait()

@pytest.fixture
def page(page: Page, base_url: str):
    """Navigate to the base URL before each test."""
    page.goto(base_url)
    return page
