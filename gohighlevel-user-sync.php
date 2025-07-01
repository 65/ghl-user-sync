<?php
/**
 * Plugin Name: GoHighLevel User Sync
 * Plugin URI:  https://sixfive.io
 * Description: Synchronizes WordPress user details (name, email, role) to GoHighLevel CRM using the upsert API with OAuth 2.0.
 * Version:     1.4.0
 * Author:      SixFive Pty Ltd
 * Author URI:  https://sixfive.io
 * License:     GPL2
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: gohighlevel-user-sync
 * Domain Path: /languages
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * GoHighLevel_User_Sync_Plugin Class
 * Handles all plugin functionality: settings, OAuth flow, API calls, and WordPress hooks.
 */
class GoHighLevel_User_Sync_Plugin {

    // GoHighLevel OAuth Endpoints
    const GHL_AUTHORIZE_URL = 'https://oauth.gohighlevel.com/oauth/authorize';
    const GHL_TOKEN_URL     = 'https://oauth.gohighlevel.com/oauth/token';
    const GHL_API_BASE_URL  = 'https://rest.gohighlevel.com/'; // Base for contact operations

    // Nonce action for OAuth callback
    const OAUTH_NONCE_ACTION = 'gohighlevel_oauth_connect';
    // Nonce name for OAuth callback state parameter
    const OAUTH_NONCE_NAME = 'ghl_oauth_nonce';

    /**
     * Constructor
     * Initializes the plugin by setting up hooks.
     */
    public function __construct() {
        // Add admin menu and register settings.
        add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );

        // Handle OAuth callback.
        add_action( 'admin_post_gohighlevel_oauth_callback', array( $this, 'handle_oauth_callback' ) );

        // Hook into user creation and update events.
        add_action( 'user_register', array( $this, 'sync_user_on_register' ), 10, 1 );
        add_action( 'profile_update', array( $this, 'sync_user_on_update' ), 10, 2 );
        add_action( 'set_user_role', array( $this, 'sync_user_on_role_change' ), 10, 3 ); // user_id, new_role, old_roles

        // Add a filter to ensure the role is updated immediately if changed via other means.
        add_filter( 'pre_set_user_roles', array( $this, 'pre_set_user_roles_filter' ), 10, 3 );
    }

    /**
     * Adds the plugin settings page to the WordPress admin menu.
     */
    public function add_admin_menu() {
        add_options_page(
            __( 'GoHighLevel Sync Settings', 'gohighlevel-user-sync' ),
            __( 'GoHighLevel Sync', 'gohighlevel-user-sync' ),
            'manage_options', // Capability required to access the page.
            'gohighlevel-user-sync', // Unique slug for the page.
            array( $this, 'settings_page_content' ) // Callback function to render the page content.
        );
    }

    /**
     * Registers plugin settings with WordPress Settings API.
     */
    public function register_settings() {
        // Register a setting group.
        register_setting(
            'gohighlevel_user_sync_settings_group', // Option group.
            'gohighlevel_user_sync_options',       // Option name (will store an array of settings).
            array( $this, 'sanitize_options' )     // Sanitize callback.
        );

        // Add a settings section for OAuth configuration.
        add_settings_section(
            'gohighlevel_user_sync_oauth_section', // ID.
            __( 'GoHighLevel OAuth Configuration', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'oauth_section_callback' ), // Callback to render section intro.
            'gohighlevel-user-sync' // Page slug.
        );

        // Client ID and Client Secret fields now provide instructions for wp-config.php.
        add_settings_field(
            'gohighlevel_client_id', // ID.
            __( 'GoHighLevel Client ID', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'client_id_field_callback' ), // Callback to render the field.
            'gohighlevel-user-sync', // Page slug.
            'gohighlevel_user_sync_oauth_section' // Section ID.
        );

        add_settings_field(
            'gohighlevel_client_secret', // ID.
            __( 'GoHighLevel Client Secret', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'client_secret_field_callback' ), // Callback to render the field.
            'gohighlevel-user-sync', // Page slug.
            'gohighlevel_user_sync_oauth_section' // Section ID.
        );

        // Add a settings section for API settings (like custom field ID).
        add_settings_section(
            'gohighlevel_user_sync_api_section', // ID.
            __( 'GoHighLevel API Settings', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'api_section_callback' ), // Callback to render section intro.
            'gohighlevel-user-sync' // Page slug.
        );

        // Add a settings field for the Custom Field ID for Role.
        add_settings_field(
            'gohighlevel_role_custom_field_id', // ID.
            __( 'Role Custom Field ID', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'role_custom_field_id_callback' ), // Callback to render the field.
            'gohighlevel-user-sync', // Page slug.
            'gohighlevel_user_sync_api_section' // Section ID.
        );
    }

    /**
     * Renders the introduction for the OAuth settings section.
     */
    public function oauth_section_callback() {
        echo '<p>' . esc_html__( 'Configure your GoHighLevel OAuth application credentials here. You will need to create an OAuth application in your GoHighLevel Agency Settings.', 'gohighlevel-user-sync' ) . '</p>';
        echo '<p>' . esc_html__( 'The Redirect URI for your GoHighLevel OAuth app should be:', 'gohighlevel-user-sync' ) . ' <code>' . esc_url( admin_url( 'admin-post.php?action=gohighlevel_oauth_callback' ) ) . '</code></p>';

        $options = get_option( 'gohighlevel_user_sync_options' );
        $access_token = isset( $options['access_token'] ) ? $options['access_token'] : '';
        $location_id = isset( $options['location_id'] ) ? $options['location_id'] : '';

        if ( ! empty( $access_token ) && ! empty( $location_id ) ) {
            echo '<p style="color: green;"><strong>' . esc_html__( 'GoHighLevel Connected!', 'gohighlevel-user-sync' ) . '</strong> ' . esc_html__( 'Location ID:', 'gohighlevel-user-sync' ) . ' <code>' . esc_html( $location_id ) . '</code></p>';
        } else {
            echo '<p style="color: red;"><strong>' . esc_html__( 'GoHighLevel Not Connected.', 'gohighlevel-user-sync' ) . '</strong> ' . esc_html__( 'Please connect using the button below after configuring your Client ID and Secret in wp-config.php.', 'gohighlevel-user-sync' ) . '</p>';
        }

        // Display the connect button if Client ID and Secret are defined in wp-config.php.
        if ( defined( 'GOHIGHLEVEL_CLIENT_ID' ) && defined( 'GOHIGHLEVEL_CLIENT_SECRET' ) ) {
            // Generate a nonce for the OAuth connection to prevent CSRF.
            $oauth_nonce = wp_create_nonce( self::OAUTH_NONCE_ACTION );
            $authorize_url = add_query_arg(
                array(
                    'response_type' => 'code',
                    'client_id'     => urlencode( GOHIGHLEVEL_CLIENT_ID ),
                    'scope'         => 'contacts.write locations.readonly', // Request necessary scopes.
                    'redirect_uri'  => urlencode( admin_url( 'admin-post.php?action=gohighlevel_oauth_callback' ) ),
                    'state'         => urlencode( $oauth_nonce ), // Pass nonce as state parameter.
                ),
                self::GHL_AUTHORIZE_URL
            );
            echo '<p><a href="' . esc_url( $authorize_url ) . '" class="button button-primary">' . esc_html__( 'Connect to GoHighLevel', 'gohighlevel-user-sync' ) . '</a></p>';
        } else {
            echo '<p class="description">' . esc_html__( 'Define your GoHighLevel Client ID and Client Secret in your `wp-config.php` file to enable the "Connect to GoHighLevel" button.', 'gohighlevel-user-sync' ) . '</p>';
        }
    }

    /**
     * Renders the introduction for the general API settings section.
     */
    public function api_section_callback() {
        echo '<p>' . esc_html__( 'Enter the custom field ID for the user role in GoHighLevel.', 'gohighlevel-user-sync' ) . '</p>';
        echo '<p>' . esc_html__( 'The custom field ID can be found in your GoHighLevel account under Settings > Custom Fields. Ensure it is a "Checkbox" type field to support multiple roles.', 'gohighlevel-user-sync' ) . '</p>';
    }

    /**
     * Renders the Client ID input field with wp-config.php instructions.
     */
    public function client_id_field_callback() {
        if ( defined( 'GOHIGHLEVEL_CLIENT_ID' ) ) {
            // Mask all but the last 4 characters for display.
            $display_value = str_repeat( '&bull;', strlen( GOHIGHLEVEL_CLIENT_ID ) - 4 ) . substr( GOHIGHLEVEL_CLIENT_ID, -4 );
            echo '<input type="text" value="' . esc_attr( $display_value ) . '" class="regular-text" readonly/>';
            echo '<p class="description">' . esc_html__( 'GoHighLevel Client ID is defined in your `wp-config.php` file.', 'gohighlevel-user-sync' ) . '</p>';
        } else {
            echo '<p class="description">' . esc_html__( 'To define your GoHighLevel Client ID, add the following line to your `wp-config.php` file:', 'gohighlevel-user-sync' ) . '</p>';
            echo '<pre><code>define( \'GOHIGHLEVEL_CLIENT_ID\', \'YOUR_CLIENT_ID_HERE\' );</code></pre>';
        }
    }

    /**
     * Renders the Client Secret input field with wp-config.php instructions.
     */
    public function client_secret_field_callback() {
        if ( defined( 'GOHIGHLEVEL_CLIENT_SECRET' ) ) {
            // Mask the entire secret for display.
            $display_value = str_repeat( '&bull;', strlen( GOHIGHLEVEL_CLIENT_SECRET ) );
            echo '<input type="password" value="' . esc_attr( $display_value ) . '" class="regular-text" readonly/>';
            echo '<p class="description">' . esc_html__( 'GoHighLevel Client Secret is defined in your `wp-config.php` file.', 'gohighlevel-user-sync' ) . '</p>';
        } else {
            echo '<p class="description">' . esc_html__( 'To define your GoHighLevel Client Secret, add the following line to your `wp-config.php` file:', 'gohighlevel-user-sync' ) . '</p>';
            echo '<pre><code>define( \'GOHIGHLEVEL_CLIENT_SECRET\', \'YOUR_CLIENT_SECRET_HERE\' );</code></pre>';
        }
    }

    /**
     * Renders the Role Custom Field ID input field.
     */
    public function role_custom_field_id_callback() {
        $options = get_option( 'gohighlevel_user_sync_options' );
        $role_custom_field_id = isset( $options['role_custom_field_id'] ) ? sanitize_text_field( $options['role_custom_field_id'] ) : '';
        ?>
        <input type="text" name="gohighlevel_user_sync_options[role_custom_field_id]" value="<?php echo esc_attr( $role_custom_field_id ); ?>" class="regular-text" placeholder="<?php esc_attr_e( 'Enter the Custom Field ID for Role', 'gohighlevel-user-sync' ); ?>"/>
        <p class="description"><?php esc_html_e( 'This is the ID of the custom field in GoHighLevel where the user\'s WordPress role will be stored. Example: `2x34567890abcdef12345678`. Ensure this field in GoHighLevel is a "Checkbox" type to support multiple selections.', 'gohighlevel-user-sync' ); ?></p>
        <?php
    }

    /**
     * Sanitizes and validates plugin options.
     *
     * @param array $input The raw input from the settings form.
     * @return array The sanitized options.
     */
    public function sanitize_options( $input ) {
        // Verify nonce for settings form submission.
        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'gohighlevel_user_sync_settings_group-options' ) ) {
            wp_die( __( 'Security check failed. Please try again.', 'gohighlevel-user-sync' ), __( 'Error', 'gohighlevel-user-sync' ), array( 'response' => 403 ) );
        }

        $new_input = array();
        $current_options = get_option( 'gohighlevel_user_sync_options', array() );

        // Preserve existing tokens and location ID.
        $new_input['access_token']  = isset( $current_options['access_token'] ) ? $current_options['access_token'] : '';
        $new_input['refresh_token'] = isset( $current_options['refresh_token'] ) ? $current_options['refresh_token'] : '';
        $new_input['token_expires'] = isset( $current_options['token_expires'] ) ? $current_options['token_expires'] : 0;
        $new_input['location_id']   = isset( $current_options['location_id'] ) ? $current_options['location_id'] : '';

        if ( isset( $input['role_custom_field_id'] ) ) {
            $new_input['role_custom_field_id'] = sanitize_text_field( $input['role_custom_field_id'] );
        }

        // Client ID and Secret are no longer stored in options, so no sanitization or invalidation logic needed here.

        return $new_input;
    }

    /**
     * Renders the full settings page content.
     */
    public function settings_page_content() {
        // Ensure user has capability to access this page.
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( __( 'You do not have sufficient permissions to access this page.', 'gohighlevel-user-sync' ) );
        }
        ?>
        <div class="wrap">
            <h1><?php esc_html_e( 'GoHighLevel User Sync Settings', 'gohighlevel-user-sync' ); ?></h1>
            <form method="post" action="options.php">
                <?php
                // Output security fields for the registered setting group.
                settings_fields( 'gohighlevel_user_sync_settings_group' );
                // Output settings sections and their fields.
                do_settings_sections( 'gohighlevel-user-sync' );
                // Output save button.
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }

    /**
     * Handles the OAuth callback from GoHighLevel.
     * Exchanges the authorization code for access and refresh tokens.
     */
    public function handle_oauth_callback() {
        // Ensure user has capability to access this endpoint.
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( __( 'You do not have sufficient permissions to perform this action.', 'gohighlevel-user-sync' ), __( 'Error', 'gohighlevel-user-sync' ), array( 'response' => 403 ) );
        }

        // Verify the nonce passed as 'state' parameter to prevent CSRF.
        if ( ! isset( $_GET['state'] ) || ! wp_verify_nonce( sanitize_text_field( $_GET['state'] ), self::OAUTH_NONCE_ACTION ) ) {
            error_log( '[GoHighLevel Sync OAuth ERROR]: Nonce verification failed for OAuth callback. Possible CSRF attempt.' );
            wp_die( __( 'Security check failed. Please try again from the plugin settings page.', 'gohighlevel-user-sync' ), __( 'Error', 'gohighlevel-user-sync' ), array( 'response' => 403 ) );
        }

        if ( ! defined( 'GOHIGHLEVEL_CLIENT_ID' ) || ! defined( 'GOHIGHLEVEL_CLIENT_SECRET' ) ) {
            error_log( '[GoHighLevel Sync OAuth ERROR]: GoHighLevel Client ID or Secret not defined in wp-config.php during OAuth callback.' );
            wp_die( __( 'GoHighLevel Client ID or Secret is not configured. Please define them in your wp-config.php file.', 'gohighlevel-user-sync' ), __( 'Configuration Error', 'gohighlevel-user-sync' ) );
        }

        if ( isset( $_GET['code'] ) ) {
            $code = sanitize_text_field( $_GET['code'] );
            $options = get_option( 'gohighlevel_user_sync_options' );

            $redirect_uri = admin_url( 'admin-post.php?action=gohighlevel_oauth_callback' );

            $body = array(
                'client_id'     => GOHIGHLEVEL_CLIENT_ID,
                'client_secret' => GOHIGHLEVEL_CLIENT_SECRET,
                'grant_type'    => 'authorization_code',
                'code'          => $code,
                'redirect_uri'  => $redirect_uri,
            );

            $response = wp_remote_post(
                self::GHL_TOKEN_URL,
                array(
                    'method'    => 'POST',
                    'headers'   => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
                    'body'      => http_build_query( $body ),
                    'timeout'   => 30,
                    'sslverify' => true, // IMPORTANT: Always true in production for security.
                )
            );

            if ( is_wp_error( $response ) ) {
                $error_message = $response->get_error_message();
                error_log( '[GoHighLevel Sync OAuth ERROR]: Token exchange failed: ' . $error_message );
                wp_die( __( 'Error exchanging authorization code for tokens. Please check your network connection and API credentials.', 'gohighlevel-user-sync' ), __( 'Connection Error', 'gohighlevel-user-sync' ) );
            }

            $response_code = wp_remote_retrieve_response_code( $response );
            $response_body = wp_remote_retrieve_body( $response );
            $data          = json_decode( $response_body, true );

            if ( $response_code >= 200 && $response_code < 300 && isset( $data['access_token'] ) ) {
                // Store tokens and expiry.
                $options['access_token']  = sanitize_text_field( $data['access_token'] );
                $options['refresh_token'] = sanitize_text_field( $data['refresh_token'] );
                // Calculate expiry time (current time + expires_in seconds - a buffer).
                $options['token_expires'] = time() + (int) $data['expires_in'] - 300; // 5-minute buffer.
                // Store location ID if provided.
                if ( isset( $data['locationId'] ) ) {
                    $options['location_id'] = sanitize_text_field( $data['locationId'] );
                } elseif ( isset( $data['location_id'] ) ) { // sometimes it's camelCase, sometimes snake_case
                    $options['location_id'] = sanitize_text_field( $data['location_id'] );
                }

                update_option( 'gohighlevel_user_sync_options', $options );
                wp_redirect( admin_url( 'options-general.php?page=gohighlevel-user-sync&ghl_connected=true' ) );
                exit;
            } else {
                error_log( '[GoHighLevel Sync OAuth ERROR]: Invalid token response. Status: ' . $response_code . ', Response: ' . $response_body );
                wp_die( __( 'Failed to obtain access token. Please check your GoHighLevel OAuth application settings (Client ID, Client Secret, Redirect URI) and ensure the correct scopes are granted.', 'gohighlevel-user-sync' ), __( 'API Error', 'gohighlevel-user-sync' ) . ' Debug: ' . esc_html( $response_body ) );
            }
        } elseif ( isset( $_GET['error'] ) ) {
            $error = sanitize_text_field( $_GET['error'] );
            $error_description = isset( $_GET['error_description'] ) ? sanitize_text_field( $_GET['error_description'] ) : '';
            error_log( '[GoHighLevel Sync OAuth ERROR]: Authorization failed. Error: ' . $error . ', Description: ' . $error_description );
            wp_die( __( 'GoHighLevel Authorization Failed: ', 'gohighlevel-user-sync' ) . esc_html( $error_description ), __( 'Authorization Error', 'gohighlevel-user-sync' ) );
        } else {
            error_log( '[GoHighLevel Sync OAuth ERROR]: Invalid OAuth callback request. No code or error parameter found.' );
            wp_die( __( 'Invalid OAuth callback request.', 'gohighlevel-user-sync' ), __( 'Invalid Request', 'gohighlevel-user-sync' ) );
        }
    }

    /**
     * Refreshes the GoHighLevel access token if it's expired or about to expire.
     *
     * @return string|false The new access token on success, false on failure.
     */
    private function refresh_access_token() {
        if ( ! defined( 'GOHIGHLEVEL_CLIENT_ID' ) || ! defined( 'GOHIGHLEVEL_CLIENT_SECRET' ) ) {
            error_log( '[GoHighLevel Sync ERROR]: Cannot refresh token. GoHighLevel Client ID or Secret not defined in wp-config.php.' );
            return false;
        }

        $options = get_option( 'gohighlevel_user_sync_options' );
        $refresh_token = isset( $options['refresh_token'] ) ? $options['refresh_token'] : '';

        if ( empty( $refresh_token ) ) {
            error_log( '[GoHighLevel Sync ERROR]: Cannot refresh token. Refresh Token missing. User may need to re-connect GoHighLevel.' );
            return false;
        }

        $body = array(
            'client_id'     => GOHIGHLEVEL_CLIENT_ID,
            'client_secret' => GOHIGHLEVEL_CLIENT_SECRET,
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refresh_token,
        );

        $response = wp_remote_post(
            self::GHL_TOKEN_URL,
            array(
                'method'    => 'POST',
                'headers'   => array( 'Content-Type' => 'application/x-www-form-urlencoded' ),
                'body'      => http_build_query( $body ),
                'timeout'   => 30,
                'sslverify' => true, // IMPORTANT: Always true in production for security.
            )
        );

        if ( is_wp_error( $response ) ) {
            $error_message = $response->get_error_message();
            error_log( '[GoHighLevel Sync ERROR]: Failed to refresh access token: ' . $error_message );
            return false;
        }

        $response_code = wp_remote_retrieve_response_code( $response );
        $response_body = wp_remote_retrieve_body( $response );
        $data          = json_decode( $response_body, true );

        if ( $response_code >= 200 && $response_code < 300 && isset( $data['access_token'] ) ) {
            $options['access_token']  = sanitize_text_field( $data['access_token'] );
            $options['refresh_token'] = sanitize_text_field( $data['refresh_token'] ); // Refresh token might also be refreshed.
            $options['token_expires'] = time() + (int) $data['expires_in'] - 300; // 5-minute buffer.
            update_option( 'gohighlevel_user_sync_options', $options );
            error_log( '[GoHighLevel Sync SUCCESS]: Access token refreshed successfully.' );
            return $options['access_token'];
        } else {
            error_log( '[GoHighLevel Sync ERROR]: Failed to get new access token during refresh. Status: ' . $response_code . ', Response: ' . $response_body );
            // Invalidate tokens if refresh fails, forcing a re-connection.
            $options['access_token']  = '';
            $options['refresh_token'] = '';
            $options['token_expires'] = 0;
            $options['location_id']   = ''; // Also clear location ID as it might be tied to the token.
            update_option( 'gohighlevel_user_sync_options', $options );
            return false;
        }
    }

    /**
     * Retrieves a valid access token, refreshing it if necessary.
     *
     * @return string|false The valid access token, or false if unable to obtain one.
     */
    private function get_valid_access_token() {
        $options = get_option( 'gohighlevel_user_sync_options' );
        $access_token  = isset( $options['access_token'] ) ? $options['access_token'] : '';
        $token_expires = isset( $options['token_expires'] ) ? (int) $options['token_expires'] : 0;

        // If no access token or it's expired/about to expire, try to refresh.
        if ( empty( $access_token ) || time() >= $token_expires ) {
            error_log( '[GoHighLevel Sync INFO]: Access token expired or missing, attempting to refresh.' );
            $access_token = $this->refresh_access_token();
        }

        return $access_token;
    }

    /**
     * Triggers user synchronization when a new user registers.
     *
     * @param int $user_id The ID of the newly registered user.
     */
    public function sync_user_on_register( $user_id ) {
        $this->sync_user_to_gohighlevel( $user_id );
    }

    /**
     * Triggers user synchronization when a user's profile is updated.
     *
     * @param int     $user_id The ID of the updated user.
     * @param WP_User $old_user_data The WP_User object before the update.
     */
    public function sync_user_on_update( $user_id, $old_user_data ) {
        $this->sync_user_to_gohighlevel( $user_id );
    }

    /**
     * Triggers user synchronization when a user's role changes.
     *
     * @param int    $user_id The ID of the user whose role changed.
     * @param string $role The new role.
     * @param array  $old_roles The old roles.
     */
    public function sync_user_on_role_change( $user_id, $role, $old_roles ) {
        // This hook fires *after* the role is set, so we can directly sync.
        $this->sync_user_to_gohighlevel( $user_id );
    }

    /**
     * Filter to ensure user role changes are immediately reflected before profile_update.
     * This is a safeguard for cases where role changes might not trigger profile_update directly.
     *
     * @param array $new_roles The new roles to be set.
     * @param int   $user_id The ID of the user.
     * @param array $old_roles The old roles of the user.
     * @return array The new roles (unmodified).
     */
    public function pre_set_user_roles_filter( $new_roles, $user_id, $old_roles ) {
        // If roles are actually changing, trigger a sync.
        if ( count( array_diff( $new_roles, $old_roles ) ) > 0 || count( array_diff( $old_roles, $new_roles ) ) > 0 ) {
            // Use a transient to prevent multiple rapid syncs if multiple hooks fire.
            $transient_key = 'gohighlevel_sync_user_' . $user_id;
            if ( ! get_transient( $transient_key ) ) {
                set_transient( $transient_key, true, 5 ); // Cache for 5 seconds to prevent re-sync.
                $this->sync_user_to_gohighlevel( $user_id );
            }
        }
        return $new_roles;
    }

    /**
     * Main function to synchronize WordPress user data to GoHighLevel.
     *
     * @param int $user_id The ID of the WordPress user to sync.
     */
    private function sync_user_to_gohighlevel( $user_id ) {
        $options = get_option( 'gohighlevel_user_sync_options' );
        $role_custom_field_id = isset( $options['role_custom_field_id'] ) ? sanitize_text_field( $options['role_custom_field_id'] ) : '';
        $location_id = isset( $options['location_id'] ) ? sanitize_text_field( $options['location_id'] ) : '';

        // Validate required settings.
        if ( empty( $role_custom_field_id ) ) {
            error_log( '[GoHighLevel Sync ERROR]: GoHighLevel Role Custom Field ID is not set. Please configure it in plugin settings.' );
            return;
        }
        if ( empty( $location_id ) ) {
            error_log( '[GoHighLevel Sync ERROR]: GoHighLevel Location ID is not set. Please connect to GoHighLevel via OAuth.' );
            return;
        }

        $access_token = $this->get_valid_access_token();
        if ( ! $access_token ) {
            error_log( '[GoHighLevel Sync ERROR]: No valid GoHighLevel access token available. Please connect to GoHighLevel.' );
            return;
        }

        $user = get_user_by( 'ID', $user_id );

        if ( ! $user ) {
            error_log( '[GoHighLevel Sync ERROR]: User with ID ' . $user_id . ' not found.' );
            return;
        }

        // Extract user details.
        $first_name = $user->first_name ? $user->first_name : $user->display_name;
        $last_name  = $user->last_name ? $user->last_name : '';
        $email      = $user->user_email;
        $roles      = $this->get_user_roles( $user ); // Get all roles as an array.

        // GoHighLevel API Endpoint for Upsert Contact.
        $api_url = self::GHL_API_BASE_URL . 'v1/contacts/upsert';

        // Prepare the payload for the GoHighLevel API.
        $body = array(
            'firstName' => $first_name,
            'lastName'  => $last_name,
            'email'     => $email,
            // Add custom fields for the role.
            'customFields' => array(
                array(
                    'id'    => $role_custom_field_id,
                    'value' => $roles, // Now sending an array of roles.
                ),
            ),
            // You can add more fields here if needed, e.g., phone, tags etc.
            // 'phone' => $user->phone_number,
            // 'tags' => ['WordPress User', $role],
        );

        // Prepare headers for the API request.
        $headers = array(
            'Content-Type'  => 'application/json',
            'Authorization' => 'Bearer ' . $access_token,
            'Version'       => '2021-07-28', // Recommended API version.
            'Accept'        => 'application/json',
            'Location'      => $location_id, // Crucial for GHL API calls.
        );

        // Make the HTTP POST request using WordPress's HTTP API.
        $response = wp_remote_post(
            $api_url,
            array(
                'method'    => 'POST',
                'headers'   => $headers,
                'body'      => wp_json_encode( $body ),
                'timeout'   => 30, // Set a timeout for the request.
                'sslverify' => true, // IMPORTANT: Always true in production for security.
            )
        );

        // Check for WP_Error.
        if ( is_wp_error( $response ) ) {
            $error_message = $response->get_error_message();
            error_log( '[GoHighLevel Sync ERROR]: Failed to connect to GoHighLevel API for user ' . $email . ': ' . $error_message );
            return;
        }

        // Get the response body and decode it.
        $response_code = wp_remote_retrieve_response_code( $response );
        $response_body = wp_remote_retrieve_body( $response );
        $data          = json_decode( $response_body, true );

        // Log success or error based on the API response.
        if ( $response_code >= 200 && $response_code < 300 ) {
            error_log( '[GoHighLevel Sync SUCCESS]: User ' . $email . ' successfully synced to GoHighLevel. Response: ' . $response_body );
        } else {
            error_log( '[GoHighLevel Sync ERROR]: GoHighLevel API returned an error for user ' . $email . '. Status: ' . $response_code . ', Response: ' . $response_body );
        }
    }

    /**
     * Helper function to get all roles of a user, capitalized.
     *
     * @param WP_User $user The WP_User object.
     * @return array An array of capitalized role names. Returns an empty array if no roles found.
     */
    private function get_user_roles( $user ) {
        $roles = array();
        if ( ! empty( $user->roles ) && is_array( $user->roles ) ) {
            foreach ( $user->roles as $role ) {
                $roles[] = ucfirst( $role ); // Capitalize each role name.
            }
        }
        return $roles;
    }
}

// Instantiate the plugin class.
new GoHighLevel_User_Sync_Plugin();

