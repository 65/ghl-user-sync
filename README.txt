=== GoHighLevel User Sync ===
Contributors: SixFive Pty Ltd
Tags: gohighlevel, crm, sync, user, role, oauth, integration, contacts
Requires at least: 5.8
Tested up to: 6.5
Stable tag: 1.4.0
License: GPL2
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Synchronizes WordPress user details (name, email, multiple roles) to GoHighLevel CRM using the upsert API with OAuth 2.0, with enhanced security.

== Description ==

The GoHighLevel User Sync plugin provides a robust and secure way to keep your WordPress user data synchronized with your GoHighLevel CRM. This plugin automates the process of sending user details, including their name, email, and all assigned WordPress roles, to GoHighLevel whenever a user is registered, updated, or their role changes.

Key Features:
* **Automatic User Synchronization:** Triggers sync on user registration, profile updates, and role changes.
* **GoHighLevel OAuth 2.0:** Securely connects to your GoHighLevel account using the recommended OAuth 2.0 authentication flow, including automatic access token refreshing.
* **Multiple Role Support:** Sends all WordPress user roles to a designated "Checkbox allowing multiple options" custom field in GoHighLevel.
* **Enhanced Security:** Client ID and Client Secret are stored securely in `wp-config.php` constants, not in the database. Includes nonce verification for CSRF protection and strict SSL certificate validation for API calls.
* **Detailed Logging:** Provides error and success logging to the WordPress debug log for easy troubleshooting.

This plugin ensures that your GoHighLevel contacts are always up-to-date with your WordPress user base, streamlining your CRM efforts.

== Installation ==

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
    * **Add the following lines** *before* the line `/* That's all, stop editing! Happy publishing. */`:

    ```php
    define( 'GOHIGHLEVEL_CLIENT_ID', 'YOUR_GOHIGHLEVEL_CLIENT_ID' );
    define( 'GOHIGHLEVEL_CLIENT_SECRET', 'YOUR_GOHIGHLEVEL_CLIENT_SECRET' );
    ```
    * Replace `YOUR_GOHIGHLEVEL_CLIENT_ID` and `YOUR_GOHIGHLEVEL_CLIENT_SECRET` with the actual credentials from your GoHighLevel OAuth application.

5.  **Create GoHighLevel OAuth Application:**
    * Log in to your GoHighLevel account.
    * Navigate to `Agency Settings > OAuth Application`.
    * Click "Create New App."
    * **App Name:** Give it a descriptive name (e.g., "WordPress Sync").
    * **Redirect URI:** This is CRITICAL. It must exactly match the URL provided in the plugin settings page. Copy the URL displayed under "GoHighLevel OAuth Configuration" in your WordPress plugin settings (it will look something like `https://your-domain.com/wp-admin/admin-post.php?action=gohighlevel_oauth_callback`) and paste it here.
    * **Scopes:** Select at least `contacts.write` and `locations.readonly`.
    * Save your application. GoHighLevel will provide you with a **Client ID** and a **Client Secret**. (These are the values you'll use in `wp-config.php`).

6.  **Configure Plugin Settings in WordPress:**
    * Go to your WordPress admin dashboard.
    * Navigate to `Settings > GoHighLevel Sync`.
    * **Role Custom Field ID:** Enter the ID of the custom field in GoHighLevel where the user's WordPress roles will be stored. Ensure this field in GoHighLevel is a "Checkbox allowing multiple options" type.
    * Click "Save Changes."

7.  **Connect to GoHighLevel:**
    * On the `Settings > GoHighLevel Sync` page, after saving your `wp-config.php` changes and the custom field ID, you will see a "Connect to GoHighLevel" button.
    * Click this button. You will be redirected to GoHighLevel to authorize the connection.
    * Approve the connection. You will then be redirected back to your WordPress plugin settings page, and you should see a "GoHighLevel Connected!" message along with your `Location ID`.

Your plugin is now configured and ready to sync!

== Screenshots ==

(No screenshots yet. Add screenshots of the plugin settings page, OAuth connection process, and GoHighLevel custom field setup here.)

== Changelog ==

= 1.4.0 - 2025-07-01 =
* **Security Enhancement:** Implemented nonce verification for OAuth callback to prevent CSRF attacks.
* **Security Enhancement:** Added nonce verification for settings form submissions.
* **Security Enhancement:** Enforced strict SSL certificate verification (`sslverify => true`) for all `wp_remote_post` calls to GoHighLevel API.
* **Security Enhancement:** Improved masking of Client ID (showing last 4 chars) and Client Secret (fully masked) on the settings page.
* **Error Handling:** Enhanced `wp_die()` messages to be more generic for users, while detailed errors are logged.

= 1.3.0 - 2025-06-28 =
* **Security Improvement:** Moved GoHighLevel Client ID and Client Secret from database options to `wp-config.php` constants for enhanced security.
* Updated settings page UI to reflect `wp-config.php` configuration instructions.

= 1.2.0 - 2025-06-25 =
* **Feature Update:** Modified to support multiple WordPress user roles syncing to a GoHighLevel "Checkbox allowing multiple options" custom field.
* Updated `get_user_primary_role` to `get_user_roles` to return an array of all roles.
* Adjusted API payload to send an array of roles for the custom field.
* Updated OAuth scope to include `locations.readonly` for reliable `locationId` retrieval.

= 1.1.0 - 2025-06-20 =
* **Major Update:** Implemented OAuth 2.0 authentication for GoHighLevel API calls.
* Added plugin settings for GoHighLevel Client ID and Client Secret.
* Introduced OAuth authorization flow and token exchange.
* Implemented access token refresh mechanism.
* Added `Location` header to all GoHighLevel API requests.

= 1.0.0 - 2025-06-15 =
* Initial release.
* Basic user synchronization (name, email, single role) using API key authentication.

== Upgrade Notice ==

= 1.4.0 =
This update includes significant security enhancements. Please ensure your `wp-config.php` file is correctly configured with `GOHIGHLEVEL_CLIENT_ID` and `GOHIGHLEVEL_CLIENT_SECRET` as constants. Re-connecting to GoHighLevel via OAuth is highly recommended after this update to ensure nonces are correctly handled.

= 1.3.0 =
This version moves the GoHighLevel Client ID and Client Secret to `wp-config.php` for better security. After updating, you **must** add `define( 'GOHIGHLEVEL_CLIENT_ID', '...' );` and `define( 'GOHIGHLEVEL_CLIENT_SECRET', '...' );` to your `wp-config.php` file. Existing Client ID/Secret in plugin settings will be ignored.

= 1.2.0 =
This update adds support for multiple user roles. Ensure your GoHighLevel custom field for roles is set to "Checkbox allowing multiple options" for proper synchronization.

= 1.1.0 =
This is a major update introducing OAuth 2.0. You will need to create an OAuth application in GoHighLevel and configure the Client ID, Client Secret, and Redirect URI in the plugin settings. You will then need to re-authorize the connection. The old API key setting is no longer used.
