# Social Authentication Test Suite

This directory contains comprehensive tests for social authentication functionality, covering all scenarios including duplicate email handling, error cases, and integration flows.

## Test Files Overview

### 1. `test_social_auth.py` - Core Social Authentication Tests
**Purpose**: Tests the basic social authentication functionality and core scenarios.

**Key Test Cases**:
- `test_duplicate_email_handling_in_adapter()` - Tests that duplicate emails are prevented at the adapter level
- `test_custom_social_signup_view_error_handling()` - Tests the custom signup view structure
- `test_social_signup_with_existing_email_redirects_to_login()` - Tests redirect behavior for existing emails
- `test_social_login_flow_for_new_user()` - Tests the complete flow for new users
- `test_social_login_flow_for_existing_user()` - Tests flow for existing users
- `test_organization_setup_after_social_login()` - Tests organization setup redirects
- `test_social_account_adapter_inheritance()` - Tests proper inheritance from base classes
- `test_social_login_with_different_providers()` - Tests Google and GitHub provider handling
- `test_social_login_edge_cases()` - Tests edge cases like missing emails
- `test_social_signup_view_inheritance()` - Tests view inheritance
- `test_social_login_url_patterns()` - Tests URL configuration

### 2. `test_social_auth_integration.py` - Integration Tests
**Purpose**: Tests complete integration scenarios and end-to-end flows.

**Key Test Cases**:
- `test_complete_duplicate_email_scenario()` - Complete duplicate email handling flow
- `test_new_user_social_signup_flow()` - Complete new user signup flow
- `test_social_login_with_organization_assignment()` - Organization assignment flow
- `test_social_account_connection_scenarios()` - Social account connection scenarios
- `test_social_login_with_multiple_providers()` - Multiple provider support
- `test_social_login_organization_flow()` - Organization setup flow
- `test_social_login_data_validation()` - Data validation scenarios
- `test_social_login_session_handling()` - Session management
- `test_social_login_with_existing_social_account()` - Existing social account scenarios

### 3. `test_social_auth_error_handling.py` - Error Handling Tests
**Purpose**: Tests comprehensive error handling and edge cases.

**Key Test Cases**:
- `test_duplicate_email_integrity_error_handling()` - IntegrityError prevention
- `test_custom_signup_view_exception_handling()` - Exception handling in views
- `test_social_login_with_missing_email_data()` - Missing email data handling
- `test_social_login_with_invalid_email_format()` - Invalid email format handling
- `test_social_login_with_empty_string_email()` - Empty string email handling
- `test_social_login_with_whitespace_email()` - Whitespace email handling
- `test_social_login_with_malformed_extra_data()` - Malformed data handling
- `test_social_login_with_missing_account_attribute()` - Missing attributes handling
- `test_social_login_with_missing_extra_data_attribute()` - Missing extra_data handling
- `test_social_login_with_database_connection_error()` - Database error handling
- `test_social_login_with_concurrent_user_creation()` - Race condition handling
- `test_social_login_with_different_provider_data_structures()` - Provider-specific data handling

## Test Coverage

### Scenarios Covered

1. **Duplicate Email Scenarios**:
   - User tries to sign up with Google using an email that already exists
   - Prevention at adapter level
   - Graceful error handling in views
   - User-friendly error messages

2. **New User Scenarios**:
   - Complete signup flow for new users
   - Organization setup after social login
   - Proper user creation and activation

3. **Existing User Scenarios**:
   - Social account connection to existing users
   - Multiple provider support for same user
   - Proper authentication flow

4. **Error Handling Scenarios**:
   - Missing or malformed email data
   - Invalid email formats
   - Database connection errors
   - Race conditions
   - Malformed social provider data

5. **Integration Scenarios**:
   - Complete end-to-end flows
   - Session management
   - URL routing and redirects
   - Organization assignment

### Edge Cases Covered

- Missing email in social provider data
- None/empty/whitespace email values
- Invalid email formats
- Malformed extra_data structures
- Missing account attributes
- Database integrity errors
- Concurrent user creation
- Different provider data structures (Google vs GitHub)

## Running the Tests

### Run All Social Auth Tests
```bash
uv run pytest accounts/tests/test_social_auth*.py -v
```

### Run Specific Test Files
```bash
# Core functionality tests
uv run pytest accounts/tests/test_social_auth.py -v

# Integration tests
uv run pytest accounts/tests/test_social_auth_integration.py -v

# Error handling tests
uv run pytest accounts/tests/test_social_auth_error_handling.py -v
```

### Run Specific Test Cases
```bash
# Test duplicate email handling
uv run pytest accounts/tests/test_social_auth.py::SocialAuthTestCase::test_duplicate_email_handling_in_adapter -v

# Test error handling
uv run pytest accounts/tests/test_social_auth_error_handling.py::SocialAuthErrorHandlingTestCase::test_duplicate_email_integrity_error_handling -v
```

## Test Results

All 38 social authentication tests pass, providing comprehensive coverage of:

- ✅ **Duplicate email prevention** - Prevents IntegrityError crashes
- ✅ **Graceful error handling** - User-friendly error messages
- ✅ **Complete integration flows** - End-to-end user journeys
- ✅ **Edge case handling** - Robust error handling
- ✅ **Multiple provider support** - Google and GitHub compatibility
- ✅ **Organization management** - Proper organization assignment
- ✅ **Session management** - Proper session handling
- ✅ **URL routing** - Correct redirects and routing

## Key Features Tested

1. **CustomSocialAccountAdapter**:
   - `is_auto_signup_allowed()` - Prevents duplicate email signups
   - `pre_social_login()` - Handles pre-login logic
   - `save_user()` - User creation logic
   - `get_connect_redirect_url()` - Organization setup redirects

2. **CustomSocialSignupView**:
   - `dispatch()` - Exception handling and error messages
   - Proper inheritance from allauth base classes

3. **URL Configuration**:
   - Custom social signup URL override
   - Proper routing to custom views

4. **Error Handling**:
   - IntegrityError prevention
   - User-friendly error messages
   - Proper redirects on errors

This comprehensive test suite ensures that social authentication works reliably and handles all edge cases gracefully, providing a robust foundation for the authentication system.



