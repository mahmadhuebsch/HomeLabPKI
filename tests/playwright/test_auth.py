"""Tests for authentication UI."""

import re
import os
import pytest
from playwright.sync_api import Page, expect

@pytest.mark.ui
def test_login_and_change_password(page: Page, base_url: str):
    """
    Test the full login, password change, and logout flow.
    """
    # 1. Login with default password
    page.goto(f"{base_url}/login")
    page.wait_for_selector('input[name="password"]')
    page.locator('input[name="password"]').fill("admin")
    page.locator('button[type="submit"]').click()
    expect(page).to_have_url(re.compile(r".*/$"))
    expect(page.locator("h1")).to_have_text("Dashboard")

    # 2. Navigate to settings and change password
    page.locator('a[href="/settings"]').click()
    expect(page).to_have_url(re.compile(r".*/settings$"))
    page.locator('input[name="current_password"]').fill("admin")
    page.locator('input[name="new_password"]').fill("new_password_123!")
    page.locator('input[name="confirm_password"]').fill("new_password_123!")
    page.locator('button:has-text("Change Password")').click()

    # 3. Should be redirected to login page with a success message
    expect(page).to_have_url(re.compile(r".*/login\?message=.*"))
    expect(page.locator(".alert-success")).to_have_text("Password changed successfully")

    # 4. Login with new password
    page.locator('input[name="password"]').fill("new_password_123!")
    page.locator('button[type="submit"]').click()
    expect(page).to_have_url(re.compile(r".*/$"))
    expect(page.locator("h1")).to_have_text("Dashboard")

    # 5. Logout
    logout_button = page.locator('a:has-text("Logout")')
    expect(logout_button).to_be_visible()
    logout_button.click()

    # After logout, we should be on the login page
    expect(page).to_have_url(re.compile(r".*/login.*"))
    # The login page uses a h4 for the title
    expect(page.locator("h4")).to_contain_text("HomeLab PKI")
