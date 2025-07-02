# GoHighLevel User Sync

Synchronizes WordPress user details (name, email, multiple roles) to GoHighLevel CRM using the upsert API with a Private Integrations API Key and Location ID. Includes robust caching and debugging features.

## Description

The GoHighLevel User Sync plugin provides a robust and secure way to keep your WordPress user data synchronized with your GoHighLevel CRM. This plugin automates the process of sending user details, including their name, email, and all assigned WordPress roles, to GoHighLevel whenever a user is registered, updated, or their role changes.

Key Features:

* **Automatic User Synchronization:** Triggers sync on user registration, profile updates, and role changes.

* **Deferred Admin Sync:** Automatically defers synchronization for updates made in the WordPress admin area to bypass caching issues and ensure accurate role data is sent.

* **GoHighLevel Private Integrations API Key:** Securely connects to your GoHighLevel account using a Private Integrations API Key.

* **Location ID Support:** Ensures API calls are directed to the correct GoHighLevel sub-account by including the configurable Location ID.

* **Dynamic Custom Field ID Resolution:** Automatically fetches and caches the `id` of your custom role field in GoHighLevel based on its `key`, simplifying configuration.

* **Multiple Role Support:** Sends all human-readable WordPress user roles to a designated "Checkbox allowing multiple options" custom field in GoHighLevel.

* **Enhanced Security:** The Private Integrations API Key is stored securely in `wp-config.php` constants, not in the database. Includes nonce verification for CSRF protection and strict SSL certificate validation for API calls.

* **Detailed Debugging & Logging:** Provides immediate feedback on custom field resolution in settings and extensive error/debug logging to the WordPress debug log for easy troubleshooting.

This plugin ensures that your GoHighLevel contacts are always up-to-date with your WordPress user base, streamlining your CRM efforts.

## Installation

1.  **Download the plugin:** Download the plugin files (or create the plugin file as described below).

2.  **Upload via WordPress:**

    * Go to your WordPress admin dashboard.

    * Navigate to `Plugins > Add New > Upload Plugin`.

    * Choose the plugin zip file and click 'Install Now'.

    * Activate the plugin through the 'Plugins' menu in WordPress.

3.  **Manual Installation (Alternative):**

    * Create a new folder named `gohighlevel-user-sync` in your `wp-content/plugins/` directory.

    * Copy all the plugin files (including `gohighlevel-user-sync.php`) into this new folder.

    * Activate the plugin through the 'Plugins' menu in WordPress.

4.  **Configure `wp-config.php` (Crucial Security Step):**

    * Access your WordPress `wp-config.php` file (located in the root directory of your WordPress installation) via FTP, SFTP, or your hosting's file manager.

    * **Add the following line** *before* the line `/* That's all, stop editing! Happy publishing. */`:

    ```php
    define( 'GOHIGHLEVEL_PRIVATE_API_KEY', 'YOUR_PRIVATE_API_KEY_HERE' );
    ```

    * Replace `YOUR_PRIVATE_API_KEY_HERE` with the actual Private Integrations API Key from your GoHighLevel account.

5.  **Generate GoHighLevel Private Integrations API Key:**

    * Log in to your GoHighLevel account.

    * Navigate to `Settings > Private Integrations`.

    * Generate or locate your Private Integrations API Key. This key is typically a long alphanumeric string starting with `ey`.

    * **Required Scopes:** Ensure your Private Integration has "Edit Contacts" and "View Custom Fields" scopes enabled.

6.  **Configure Plugin Settings in WordPress:**

    * Go to your WordPress admin dashboard.

    * Navigate to `Settings > GoHighLevel Sync`.

    * **Role Custom Field Key:** Enter the "Key" of the custom field in GoHighLevel where the user's WordPress roles will be stored. You can find this by viewing the custom field in your GoHighLevel settings. Ensure this field in GoHighLevel is a "Checkbox allowing multiple options" type.

    * **GoHighLevel Location ID:** Enter the unique ID of your GoHighLevel sub-account (location). You can find it in your GoHighLevel sub-account under `Settings > Business Profile`.

    * Click "Save Changes."

Your plugin is now configured and ready to sync!

## Troubleshooting & Debugging

If you encounter issues, especially with roles not syncing correctly from the WordPress admin:

1.  **Enable WordPress Debugging:**
    In your `wp-config.php` file, ensure these lines are set (temporarily for debugging):

    ```php
    define( 'WP_DEBUG', true );
    define( 'WP_DEBUG_LOG', true );
    define( 'WP_DEBUG_DISPLAY', false );
    @ini_set( 'display_errors', 0 );
    ```

    This will write all plugin debug and error messages to `wp-content/debug.log`.

2.  **Check `wp-content/debug.log`:**

    * **Custom Field ID Resolution:** Look for messages like `[GoHighLevel Sync INFO]: Successfully resolved custom field ID "..." for key "..."`. If you see errors here, it indicates an issue with your API Key, Location ID, or Custom Field Key/permissions.

    * **Raw User Roles:** After updating a user, look for `[GoHighLevel Sync DEBUG]: Raw user roles from $user->roles (after cache clear): ...`. This shows the exact roles WordPress is providing. If this doesn't match the roles visible in the WP admin user list, the caching fix might not be fully effective in your environment, or another plugin is interfering.

    * **Role Processing:** Look for `[GoHighLevel Sync DEBUG]: Processing role slug: "..." -> Human-readable name: "..."` to verify how each role is being interpreted.

    * **Request Body:** Check `[GoHighLevel Sync DEBUG]: Request Body: ...` to see the exact JSON payload sent to GoHighLevel. This is crucial for verifying the `field_value` for your custom roles.

    * **API Responses:** Look for `[GoHighLevel Sync SUCCESS]:` or `[GoHighLevel Sync ERROR]:` messages related to the API calls.

## Screenshots

(No screenshots yet. Add screenshots of the plugin settings page, and GoHighLevel custom field setup here.)

## Changelog

### 2.0.0 - 2025-07-01

* **Feature:** Implemented deferred synchronization for user profile and role updates made in the WordPress admin area using `wp_schedule_single_event`. This resolves issues where roles might be stripped due to WordPress's internal caching during immediate admin-side updates.

* **Enhancement:** Added `wp_clear_scheduled_hook` to prevent duplicate deferred sync events.

* Updated `README.md` to reflect deferred sync and general improvements.

### 1.9.2 - 2025-07-01

* **Fix:** Added `clean_user_cache($user_id)` before retrieving the user object in `sync_user_to_gohighlevel` to ensure the freshest user data (including all roles) is fetched, addressing caching issues where `$user->roles` might be stale.

### 1.9.1 - 2025-07-01

* **Debug:** Added detailed `error_log` messages within `get_user_roles` to show each role slug being processed and its derived human-readable name, aiding in debugging custom role recognition.

### 1.9.0 - 2025-07-01

* **Fix:** Corrected the `field_value` for custom fields to be an array of human-readable role labels, aligning with GoHighLevel's "Checkbox allowing multiple options" field type.

* **Enhancement:** Updated `get_user_roles` to return an array of human-readable role names.

### 1.8.1 - 2025-07-01

* **Fix:** Added a robust check in `sanitize_options` to ensure it only processes POST requests for the plugin's settings group, preventing `wp_die()` from firing on simple page loads.

### 1.8.0 - 2025-07-01

* **Feature:** Implemented immediate resolution and display of the custom role field ID on the plugin settings page upon saving, providing instant feedback.

* **Enhancement:** Proactive fetching of custom field ID on settings save if inputs are valid.

* **Debug:** Added more specific error messages on the settings page and in logs if custom field ID resolution fails.

### 1.7.0 - 2025-07-01

* **API Endpoint Correction:** Updated API base URL to `https://services.leadconnectorhq.com/` and endpoint path to `contacts/upsert`.

* **Payload Structure Correction:** Moved `locationId` from HTTP header to the JSON request body.

* **Custom Field Structure Correction:** Changed custom field value key from `value` to `field_value` in the API payload.

* **Custom Field Key/ID Handling:** Implemented dynamic fetching and caching of custom field `id` based on its `key` provided in settings.

* **Payload Enhancement:** Added `name` field to the main contact payload as per `curl` example.

* Updated settings page and `README.md` to reflect these changes.

### 1.6.0 - 2025-07-01

* **Feature Update:** Added GoHighLevel Location ID to plugin settings.

* Ensured Location ID is included in the `Location` header for all GoHighLevel API upsert calls.

* Updated settings page and `README.md` to reflect Location ID configuration.

### 1.5.0 - 2025-07-01

* **Major Update:** Switched from OAuth 2.0 to GoHighLevel Private Integrations API Key for simpler authentication.

* Removed all OAuth-related code (authorization flow, token refresh, client ID/secret storage).

* Updated settings page to reflect Private Integrations API Key configuration via `wp-config.php`.

* Modified API calls to use the Private Integrations API Key directly in the Authorization header.

* Updated `README.md` to reflect simplified installation and configuration.

### 1.4.0 - 2025-07-01

* **Security Enhancement:** Implemented nonce verification for OAuth callback to prevent CSRF attacks.

* **Security Enhancement:** Added nonce verification for settings form submissions.

* **Security Enhancement:** Enforced strict SSL certificate verification (`sslverify => true`) for all `wp_remote_post` calls to GoHighLevel API.

* **Security Enhancement:** Improved masking of Client ID (showing last 4 chars) and Client Secret (fully masked) on the settings page.

* **Error Handling:** Enhanced `wp_die()` messages to be more generic for users, while detailed errors are logged.

### 1.3.0 - 2025-06-28

* **Security Improvement:** Moved GoHighLevel Client ID and Client Secret from database options to `wp-config.php` constants for enhanced security.

* Updated settings page UI to reflect `wp-config.php` configuration instructions.

### 1.2.0 - 2025-06-25

* **Feature Update:** Modified to support multiple WordPress user roles syncing to a GoHighLevel "Checkbox allowing multiple options" custom field.

* Updated `get_user_primary_role` to `get_user_roles` to return an array of all roles.

* Adjusted API payload to send an array of roles for the custom field.

* Updated OAuth scope to include `locations.readonly` for reliable `locationId` retrieval.

### 1.1.0 - 2025-06-20

* **Major Update:** Implemented OAuth 2.0 authentication for GoHighLevel API calls.

* Added plugin settings for GoHighLevel Client ID and Client Secret.

* Introduced OAuth authorization flow and token exchange.

* Implemented access token refresh mechanism.

* Added `Location` header to all GoHighLevel API requests.

### 1.0.0 - 2025-06-15

* Initial release.

* Basic user synchronization (name, email, single role) using API key authentication.

## Upgrade Notice

### 2.0.0

This version introduces **deferred synchronization for admin-side user updates**. This is a significant change to ensure all user roles are correctly captured and sent to GoHighLevel, especially when roles are modified in the WordPress admin. No immediate action is required beyond updating the plugin, but be aware that syncs from the admin area will now occur with a slight delay (5 seconds).

### 1.9.2

This update includes a critical fix for user role caching issues. Ensure you update to this version to guarantee all user roles are accurately synced from WordPress to GoHighLevel.

### 1.9.1

This version adds more detailed debug logging for user roles. Update if you are actively troubleshooting role synchronization.

### 1.9.0

This version correctly sends multiple WordPress user roles to GoHighLevel's "Checkbox allowing multiple options" custom fields as an array of human-readable labels. Ensure your GoHighLevel custom field is configured as a "Checkbox allowing multiple options" type.

### 1.8.1

This is a minor bug fix to prevent an unexpected error (`wp_die`) when simply viewing the plugin settings page. Update is recommended.

### 1.8.0

This version provides better feedback on custom field ID resolution directly on the settings page. If you encounter issues with custom fields, this update will help diagnose them.

### 1.7.0

This version includes critical updates to align with the latest GoHighLevel API specifications for `contacts/upsert`. The API endpoint, `locationId` placement in the payload, and custom field structure (`field_value` instead of `value`) have been corrected. Additionally, the plugin now dynamically fetches the custom field `id` based on its `key`. Please ensure your "Role Custom Field Key" is correctly set in the plugin settings.

### 1.6.0

This version now requires you to configure your GoHighLevel Location ID in the plugin settings. Please navigate to `Settings > GoHighLevel Sync` and enter your Location ID to ensure proper synchronization.

### 1.5.0

This is a significant simplification! We've moved from OAuth 2.0 to a Private Integrations API Key. After updating, you **must** remove the `GOHIGHLEVEL_CLIENT_ID` and `GOHIGHLEVEL_CLIENT_SECRET` constants from your `wp-config.php` and instead add `define( 'GOHIGHLEVEL_PRIVATE_API_KEY', '...' );` with your Private Integrations API Key. The "Connect to GoHighLevel" button is no longer needed.

### 1.4.0

This update includes significant security enhancements. Please ensure your `wp-config.php` file is correctly configured with `GOHIGHLEVEL_CLIENT_ID` and `GOHIGHLEVEL_CLIENT_SECRET` as constants. Re-connecting to GoHighLevel via OAuth is highly recommended after this update to ensure nonces are correctly handled.

### 1.3.0

This version moves the GoHighLevel Client ID and Client Secret to `wp-config.php` for better security. After updating, you **must** add `define( 'GOHIGHLEVEL_CLIENT_ID', '...' );` and `define( 'GOHIGHLEVEL_CLIENT_SECRET', '...' );` to your `wp-config.php` file. Existing Client ID/Secret in plugin settings will be ignored.

### 1.2.0

This update adds support for multiple user roles. Ensure your GoHighLevel custom field for roles is set to "Checkbox allowing multiple options" for proper synchronization.

### 1.1.0

This is a major update introducing OAuth 2.0. You will need to create an OAuth application in GoHighLevel and configure the Client ID, Client Secret, and Redirect URI in the plugin settings. You will then need to re-authorize the connection. The old API key setting is no longer used.
