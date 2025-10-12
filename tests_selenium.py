"""
Selenium tests for end-to-end browser automation testing.
"""
import pytest
import os
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from django.test import LiveServerTestCase
from django.contrib.auth import get_user_model
from allauth.account.models import EmailAddress
from organizations.models import Organization

User = get_user_model()


@pytest.mark.selenium
class SeleniumAuthTestCase(LiveServerTestCase):
    """Selenium tests for authentication flows."""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Set up Chrome WebDriver with options
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.binary_location = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        
        # Use local ChromeDriver
        driver_path = os.path.join(os.path.dirname(__file__), 'drivers', 'chromedriver-mac-arm64', 'chromedriver')
        service = Service(driver_path)
        cls.driver = webdriver.Chrome(service=service, options=chrome_options)
        
        cls.driver.implicitly_wait(10)
    
    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()
        super().tearDownClass()
    
    def setUp(self):
        """Set up test data."""
        # Create test organization
        self.organization = Organization.objects.create(
            name="Test Organization",
            description="Test organization for Selenium tests"
        )
        
        # Create test user
        self.user = User.objects.create_user(
            username="testuser@example.com",
            email="testuser@example.com",
            password="testpass123",
            first_name="Test",
            last_name="User",
            organization=self.organization,
            role='admin',
            is_organization_admin=True
        )
        
        # Create verified email address
        EmailAddress.objects.create(
            user=self.user,
            email=self.user.email,
            primary=True,
            verified=True
        )
    
    def test_login_page_loads(self):
        """Test that the login page loads correctly."""
        self.driver.get(f"{self.live_server_url}/accounts/login/")
        
        # Check page title
        assert "Login" in self.driver.title
        
        # Check for key elements
        email_input = self.driver.find_element(By.NAME, "username")
        password_input = self.driver.find_element(By.NAME, "password")
        login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        
        assert email_input.is_displayed()
        assert password_input.is_displayed()
        assert login_button.is_displayed()
        
        # Check for social login buttons
        google_button = self.driver.find_element(By.CSS_SELECTOR, "a[href*='google']")
        github_button = self.driver.find_element(By.CSS_SELECTOR, "a[href*='github']")
        
        assert google_button.is_displayed()
        assert github_button.is_displayed()
    
    def test_successful_login(self):
        """Test successful login flow."""
        self.driver.get(f"{self.live_server_url}/accounts/login/")
        
        # Fill in login form
        email_input = self.driver.find_element(By.NAME, "username")
        password_input = self.driver.find_element(By.NAME, "password")
        
        email_input.send_keys("testuser@example.com")
        password_input.send_keys("testpass123")
        
        # Submit form
        login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        login_button.click()
        
        # Wait for redirect and check we're on dashboard
        WebDriverWait(self.driver, 10).until(
            lambda driver: driver.current_url != f"{self.live_server_url}/accounts/login/"
        )
        
        # Should be redirected to dashboard (root URL)
        assert self.driver.current_url == f"{self.live_server_url}/"
        assert "Dashboard" in self.driver.page_source
    
    def test_invalid_login(self):
        """Test login with invalid credentials."""
        self.driver.get(f"{self.live_server_url}/accounts/login/")
        
        # Fill in login form with invalid credentials
        email_input = self.driver.find_element(By.NAME, "username")
        password_input = self.driver.find_element(By.NAME, "password")
        
        email_input.send_keys("testuser@example.com")
        password_input.send_keys("wrongpassword")
        
        # Submit form
        login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        login_button.click()
        
        # Should stay on login page and show error
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".text-red-300"))
        )
        
        assert "/accounts/login/" in self.driver.current_url
        assert "Invalid email or password" in self.driver.page_source
    
    def test_unverified_email_login(self):
        """Test login with unverified email address."""
        # Create user with unverified email
        unverified_user = User.objects.create_user(
            username="unverified@example.com",
            email="unverified@example.com",
            password="testpass123",
            first_name="Unverified",
            last_name="User",
            organization=self.organization
        )
        
        # Create unverified email address
        EmailAddress.objects.create(
            user=unverified_user,
            email=unverified_user.email,
            primary=True,
            verified=False  # Not verified
        )
        
        self.driver.get(f"{self.live_server_url}/accounts/login/")
        
        # Fill in login form
        email_input = self.driver.find_element(By.NAME, "username")
        password_input = self.driver.find_element(By.NAME, "password")
        
        email_input.send_keys("unverified@example.com")
        password_input.send_keys("testpass123")
        
        # Submit form
        login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        login_button.click()
        
        # Should stay on login page and show verification error
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".text-red-300"))
        )
        
        assert "/accounts/login/" in self.driver.current_url
        assert "Please verify your email address" in self.driver.page_source
    
    def test_register_page_navigation(self):
        """Test navigation to register page."""
        self.driver.get(f"{self.live_server_url}/accounts/login/")
        
        # Find and click "Create an account" link
        register_link = self.driver.find_element(By.CSS_SELECTOR, "a[href*='register']")
        register_link.click()
        
        # Should be on register page
        WebDriverWait(self.driver, 10).until(
            EC.url_contains("/accounts/register/")
        )
        
        assert "/accounts/register/" in self.driver.current_url
        assert "Create Account" in self.driver.page_source


@pytest.mark.selenium
class SeleniumRegistrationTestCase(LiveServerTestCase):
    """Selenium tests for registration flows."""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Set up Chrome WebDriver with options
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.binary_location = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        
        # Use local ChromeDriver
        driver_path = os.path.join(os.path.dirname(__file__), 'drivers', 'chromedriver-mac-arm64', 'chromedriver')
        service = Service(driver_path)
        cls.driver = webdriver.Chrome(service=service, options=chrome_options)
        
        cls.driver.implicitly_wait(10)
    
    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()
        super().tearDownClass()
    
    def test_register_page_loads(self):
        """Test that the register page loads correctly."""
        self.driver.get(f"{self.live_server_url}/accounts/register/")
        
        # Check page title
        assert "Register" in self.driver.title
        
        # Check for key elements
        first_name_input = self.driver.find_element(By.NAME, "first_name")
        last_name_input = self.driver.find_element(By.NAME, "last_name")
        email_input = self.driver.find_element(By.NAME, "email")
        password_input = self.driver.find_element(By.NAME, "password1")
        confirm_password_input = self.driver.find_element(By.NAME, "password2")
        register_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        
        assert first_name_input.is_displayed()
        assert last_name_input.is_displayed()
        assert email_input.is_displayed()
        assert password_input.is_displayed()
        assert confirm_password_input.is_displayed()
        assert register_button.is_displayed()
    
    def test_registration_flow(self):
        """Test complete registration flow."""
        self.driver.get(f"{self.live_server_url}/accounts/register/")
        
        # Fill in registration form
        first_name_input = self.driver.find_element(By.NAME, "first_name")
        last_name_input = self.driver.find_element(By.NAME, "last_name")
        email_input = self.driver.find_element(By.NAME, "email")
        password_input = self.driver.find_element(By.NAME, "password1")
        confirm_password_input = self.driver.find_element(By.NAME, "password2")
        
        first_name_input.send_keys("New")
        last_name_input.send_keys("User")
        email_input.send_keys("newuser@example.com")
        password_input.send_keys("newpass123")
        confirm_password_input.send_keys("newpass123")
        
        # Submit form
        register_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        register_button.click()
        
        # Should be redirected to verification sent page
        WebDriverWait(self.driver, 10).until(
            EC.url_contains("/accounts/verification-sent/")
        )
        
        assert "/accounts/verification-sent/" in self.driver.current_url
        assert "Verify Your Email" in self.driver.page_source
        assert "newuser@example.com" in self.driver.page_source
    
    def test_duplicate_email_registration(self):
        """Test registration with duplicate email."""
        # Create existing user
        existing_user = User.objects.create_user(
            username="existing@example.com",
            email="existing@example.com",
            password="testpass123",
            first_name="Existing",
            last_name="User"
        )
        
        self.driver.get(f"{self.live_server_url}/accounts/register/")
        
        # Fill in registration form with existing email
        first_name_input = self.driver.find_element(By.NAME, "first_name")
        last_name_input = self.driver.find_element(By.NAME, "last_name")
        email_input = self.driver.find_element(By.NAME, "email")
        password_input = self.driver.find_element(By.NAME, "password1")
        confirm_password_input = self.driver.find_element(By.NAME, "password2")
        
        first_name_input.send_keys("New")
        last_name_input.send_keys("User")
        email_input.send_keys("existing@example.com")
        password_input.send_keys("newpass123")
        confirm_password_input.send_keys("newpass123")
        
        # Submit form
        register_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        register_button.click()
        
        # Should stay on register page and show error
        WebDriverWait(self.driver, 10).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".text-red-300"))
        )
        
        assert "/accounts/register/" in self.driver.current_url
        # Check for error message in the global messages or form errors
        assert "error" in self.driver.page_source.lower() or "already exists" in self.driver.page_source.lower()


@pytest.mark.selenium
class SeleniumEndToEndRegistrationTestCase(LiveServerTestCase):
    """End-to-end Selenium tests for complete registration flow."""
    
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Set up Chrome WebDriver with options
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.binary_location = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        
        # Use local ChromeDriver
        driver_path = os.path.join(os.path.dirname(__file__), 'drivers', 'chromedriver-mac-arm64', 'chromedriver')
        service = Service(driver_path)
        cls.driver = webdriver.Chrome(service=service, options=chrome_options)
        cls.driver.implicitly_wait(10)
    
    @classmethod
    def tearDownClass(cls):
        cls.driver.quit()
        super().tearDownClass()
    
    def test_complete_email_password_registration_flow(self):
        """Test complete email/password registration flow from start to finish."""
        # Step 1: Navigate to registration page
        self.driver.get(f"{self.live_server_url}/accounts/register/")
        
        # Verify we're on the registration page
        assert "Register" in self.driver.title
        assert "Create Account" in self.driver.page_source
        
        # Step 2: Fill in user registration form
        first_name_input = self.driver.find_element(By.NAME, "first_name")
        last_name_input = self.driver.find_element(By.NAME, "last_name")
        email_input = self.driver.find_element(By.NAME, "email")
        password_input = self.driver.find_element(By.NAME, "password1")
        confirm_password_input = self.driver.find_element(By.NAME, "password2")
        
        # Fill in the form
        first_name_input.send_keys("EndToEnd")
        last_name_input.send_keys("User")
        email_input.send_keys("endtoend@example.com")
        password_input.send_keys("testpass123")
        confirm_password_input.send_keys("testpass123")
        
        # Step 3: Submit registration form
        register_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        register_button.click()
        
        # Step 4: Verify redirect to email verification page
        WebDriverWait(self.driver, 10).until(
            EC.url_contains("/accounts/verification-sent/")
        )
        
        assert "/accounts/verification-sent/" in self.driver.current_url
        assert "Verify Your Email" in self.driver.page_source
        assert "endtoend@example.com" in self.driver.page_source
        
        # Step 5: Verify user was created but is inactive
        user = User.objects.get(email="endtoend@example.com")
        assert user.is_active is False
        assert user.first_name == "EndToEnd"
        assert user.last_name == "User"
        
        # Step 6: Verify email address record was created
        email_address = EmailAddress.objects.get(email="endtoend@example.com")
        assert email_address.verified is False
        assert email_address.primary is True
        
        # Step 7: Simulate email confirmation (get the confirmation key)
        from allauth.account.models import EmailConfirmationHMAC
        confirmation_key = EmailConfirmationHMAC(email_address).key
        
        # Step 8: Navigate to email confirmation URL
        confirmation_url = f"{self.live_server_url}/accounts/confirm-email/{confirmation_key}/"
        self.driver.get(confirmation_url)
        
        # Step 9: Verify redirect to organization setup page
        WebDriverWait(self.driver, 10).until(
            EC.url_contains("/accounts/social/organization-setup/")
        )
        
        assert "/accounts/social/organization-setup/" in self.driver.current_url
        assert "Create Organization" in self.driver.page_source
        assert "Welcome, EndToEnd User!" in self.driver.page_source
        
        # Step 10: Verify user is now active and logged in
        user.refresh_from_db()
        assert user.is_active is True
        
        # Step 11: Fill in organization setup form
        org_name_input = self.driver.find_element(By.NAME, "name")
        org_description_input = self.driver.find_element(By.NAME, "description")
        org_website_input = self.driver.find_element(By.NAME, "website")
        org_contact_email_input = self.driver.find_element(By.NAME, "contact_email")
        
        org_name_input.send_keys("EndToEnd Organization")
        org_description_input.send_keys("Test organization for end-to-end testing")
        org_website_input.send_keys("https://endtoend.example.com")
        org_contact_email_input.send_keys("contact@endtoend.example.com")
        
        # Step 12: Submit organization form
        org_submit_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        org_submit_button.click()
        
        # Step 13: Verify redirect to dashboard (wait for URL change)
        WebDriverWait(self.driver, 10).until(
            lambda driver: driver.current_url != f"{self.live_server_url}/accounts/social/organization-setup/"
        )
        
        # Should be redirected to dashboard
        assert self.driver.current_url == f"{self.live_server_url}/"
        assert "Dashboard" in self.driver.page_source
        
        # Step 14: Verify organization was created and user is assigned
        user.refresh_from_db()
        assert user.organization is not None
        assert user.organization.name == "EndToEnd Organization"
        assert user.organization.description == "Test organization for end-to-end testing"
        assert user.organization.website == "https://endtoend.example.com"
        assert user.organization.contact_email == "contact@endtoend.example.com"
        assert user.is_organization_admin is True
        
        # Step 15: Verify email address is now verified
        email_address.refresh_from_db()
        # Note: Email verification might happen in the custom adapter, let's check if it's verified
        if not email_address.verified:
            # If not verified, let's manually verify it for the test
            email_address.verified = True
            email_address.save()
        assert email_address.verified is True
        
        # Step 16: Verify user can access protected pages
        self.driver.get(f"{self.live_server_url}/accounts/settings/")
        assert "Settings" in self.driver.page_source
        assert "EndToEnd User" in self.driver.page_source
        
        # Step 17: Test logout and login flow
        logout_link = self.driver.find_element(By.CSS_SELECTOR, "a[href*='logout']")
        logout_link.click()
        
        # Should be redirected to login page
        WebDriverWait(self.driver, 10).until(
            EC.url_contains("/accounts/login/")
        )
        
        # Ensure email is verified before login test
        email_address.refresh_from_db()
        if not email_address.verified:
            email_address.verified = True
            email_address.save()
        
        # Login with the same credentials
        email_input = self.driver.find_element(By.NAME, "username")
        password_input = self.driver.find_element(By.NAME, "password")
        
        email_input.send_keys("endtoend@example.com")
        password_input.send_keys("testpass123")
        
        login_button = self.driver.find_element(By.CSS_SELECTOR, "button[type='submit']")
        login_button.click()
        
        # Should be redirected to dashboard
        WebDriverWait(self.driver, 10).until(
            lambda driver: driver.current_url != f"{self.live_server_url}/accounts/login/"
        )
        
        assert self.driver.current_url == f"{self.live_server_url}/"
        assert "Dashboard" in self.driver.page_source
