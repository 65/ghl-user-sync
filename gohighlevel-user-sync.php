<?php
/**
 * Plugin Name: GoHighLevel User Sync
 * Description: Synchronizes WordPress user details (name, email, role) to GoHighLevel CRM using the upsert API with a Private Integrations API Key and Location ID.
 * Version:     2.0.0
 * Author:      SixFive Pty Ltd
 * Author URI:  https://example.org
 * License:     GPL2
 * License URI: https://www.gnu.gnu.org/licenses/gpl-2.0.html
 * Text Domain: gohighlevel-user-sync
 * Domain Path: /languages
 */

// Exit if accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * GoHighLevel_User_Sync_Plugin Class
 * Handles all plugin functionality: settings, API calls, and WordPress hooks.
 */
class GoHighLevel_User_Sync_Plugin {

    // GoHighLevel API Base URL - Updated to services.leadconnectorhq.com
    const GHL_API_BASE_URL  = 'https://services.leadconnectorhq.com/'; // Base for contact operations
    // Custom action hook for deferred sync
    const DEFERRED_SYNC_ACTION = 'gohighlevel_do_user_sync_deferred';

    /**
     * Constructor
     * Initializes the plugin by setting up hooks.
     */
    public function __construct() {
        // Add admin menu and register settings.
        add_action( 'admin_menu', array( $this, 'add_admin_menu' ) );
        add_action( 'admin_init', array( $this, 'register_settings' ) );

        // Hook into user creation and update events.
        add_action( 'user_register', array( $this, 'sync_user_on_register' ), 10, 1 ); // New user registration is usually immediate
        add_action( 'profile_update', array( $this, 'sync_user_on_update' ), 10, 2 );
        add_action( 'set_user_role', array( $this, 'sync_user_on_role_change' ), 10, 3 ); // user_id, new_role, old_roles

        // Add a filter to ensure the role is updated immediately if changed via other means.
        add_filter( 'pre_set_user_roles', array( $this, 'pre_set_user_roles_filter' ), 10, 3 );

        // Hook for the deferred sync action
        add_action( self::DEFERRED_SYNC_ACTION, array( $this, 'perform_deferred_sync' ), 10, 1 );
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

        // Add a settings section for API Key configuration.
        add_settings_section(
            'gohighlevel_user_sync_api_key_section', // ID.
            __( 'GoHighLevel API Key Configuration', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'api_key_section_callback' ), // Callback to render section intro.
            'gohighlevel-user-sync' // Page slug.
        );

        // Add settings field for Private Integrations API Key.
        add_settings_field(
            'gohighlevel_private_api_key', // ID.
            __( 'GoHighLevel Private API Key', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'private_api_key_field_callback' ), // Callback to render the field.
            'gohighlevel-user-sync', // Page slug.
            'gohighlevel_user_sync_api_key_section' // Section ID.
        );

        // Add a settings section for API settings (like custom field ID and Location ID).
        add_settings_section(
            'gohighlevel_user_sync_api_section', // ID.
            __( 'GoHighLevel API Settings', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'api_section_callback' ), // Callback to render section intro.
            'gohighlevel-user-sync' // Page slug.
        );

        // Add a settings field for the Custom Field Key for Role.
        add_settings_field(
            'gohighlevel_role_custom_field_key', // ID.
            __( 'Role Custom Field Key', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'role_custom_field_key_callback' ), // Callback to render the field.
            'gohighlevel-user-sync', // Page slug.
            'gohighlevel_user_sync_api_section' // Section ID.
        );

        // Add a settings field for the Location ID.
        add_settings_field(
            'gohighlevel_location_id', // ID.
            __( 'GoHighLevel Location ID', 'gohighlevel-user-sync' ), // Title.
            array( $this, 'location_id_field_callback' ), // Callback to render the field.
            'gohighlevel-user-sync', // Page slug.
            'gohighlevel_user_sync_api_section' // Section ID.
        );
    }

    /**
     * Renders the introduction for the API Key settings section.
     */
    public function api_key_section_callback() {
        echo '<p>' . esc_html__( 'Configure your GoHighLevel Private Integrations API Key here. This key should be defined in your `wp-config.php` file for security.', 'gohighlevel-user-sync' ) . '</p>';
        echo '<p>' . esc_html__( 'You can generate a Private Integrations API Key in your GoHighLevel account under `Settings > Private Integrations`.', 'gohighlevel-user-sync' ) . '</p>';
        echo '<p>' . esc_html__( 'The scopes required for this plugin are "Edit Contacts" and "View Custom Fields".', 'gohighlevel-user-sync' ) . '</p>';

        if ( defined( 'GOHIGHLEVEL_PRIVATE_API_KEY' ) ) {
            echo '<p style="color: green;"><strong>' . esc_html__( 'GoHighLevel Private API Key Detected!', 'gohighlevel-user-sync' ) . '</strong></p>';
        } else {
            echo '<p style="color: red;"><strong>' . esc_html__( 'GoHighLevel Private API Key Not Configured.', 'gohighlevel-user-sync' ) . '</strong> ' . esc_html__( 'Please define it in wp-config.php.', 'gohighlevel-user-sync' ) . '</p>';
        }
    }

    /**
     * Renders the introduction for the general API settings section.
     */
    public function api_section_callback() {
        echo '<p>' . esc_html__( 'Enter the custom field KEY for the user role and the Location ID for your GoHighLevel sub-account.', 'gohighlevel-user-sync' ) . '</p>';
        echo '<p>' . esc_html__( 'The custom field KEY can be found by viewing the Custom Field in your GoHighLevel account under Settings > Custom Fields. Ensure it is a "Checkbox" type field to support multiple roles.', 'gohighlevel-user-sync' ) . '</p>';
        echo '<p>' . esc_html__( 'The Location ID can be found in your GoHighLevel sub-account under `Settings > Business Profile`.', 'gohighlevel-user-sync' ) . '</p>';
    }

    /**
     * Renders the Private API Key input field with wp-config.php instructions.
     */
    public function private_api_key_field_callback() {
        if ( defined( 'GOHIGHLEVEL_PRIVATE_API_KEY' ) ) {
            // Mask the entire key for display.
            $display_value = str_repeat( '&bull;', strlen( GOHIGHLEVEL_PRIVATE_API_KEY ) );
            echo '<input type="password" value="' . esc_attr( $display_value ) . '" class="regular-text" readonly/>';
            echo '<p class="description">' . esc_html__( 'GoHighLevel Private API Key is defined in your `wp-config.php` file.', 'gohighlevel-user-sync' ) . '</p>';
        } else {
            echo '<p class="description">' . esc_html__( 'To define your GoHighLevel Private API Key, add the following line to your `wp-config.php` file:', 'gohighlevel-user-sync' ) . '</p>';
            echo '<pre><code>define( \'GOHIGHLEVEL_PRIVATE_API_KEY\', \'YOUR_PRIVATE_API_KEY_HERE\' );</code></pre>';
        }
    }

    /**
     * Renders the Role Custom Field Key input field.
     */
    public function role_custom_field_key_callback() {
        $options = get_option( 'gohighlevel_user_sync_options' );
        $role_custom_field_key = isset( $options['role_custom_field_key'] ) ? sanitize_text_field( $options['role_custom_field_key'] ) : '';
        $location_id = isset( $options['location_id'] ) ? sanitize_text_field( $options['location_id'] ) : '';
        $cached_id = $this->_get_cached_custom_field_id( $role_custom_field_key, $location_id );
        
        // Determine if all necessary inputs are present to attempt ID resolution
        $can_attempt_id_resolution = ! empty( $role_custom_field_key ) && ! empty( $location_id ) && defined( 'GOHIGHLEVEL_PRIVATE_API_KEY' ) && ! empty( GOHIGHLEVEL_PRIVATE_API_KEY );

        ?>
        <input type="text" name="gohighlevel_user_sync_options[role_custom_field_key]" value="<?php echo esc_attr( $role_custom_field_key ); ?>" class="regular-text" placeholder="<?php esc_attr_e( 'Enter the Custom Field Key for Role', 'gohighlevel-user-sync' ); ?>"/>
        <p class="description">
            <?php esc_html_e( 'This is the "Key" of the custom field in GoHighLevel where the user\'s WordPress role will be stored. Example: `my_wordpress_roles`. You can find this by viewing the custom field in your GoHighLevel settings.', 'gohighlevel-user-sync' ); ?>
            <?php if ( $can_attempt_id_resolution ) : ?>
                <?php if ( ! empty( $cached_id ) ) : ?>
                    <br /><span style="color: green;"><strong><?php esc_html_e( 'Resolved ID:', 'gohighlevel-user-sync' ); ?></strong> <code><?php echo esc_html( $cached_id ); ?></code></span>
                <?php else :
                    // If we have all inputs but no cached ID, it means resolution failed or hasn't happened yet.
                    // Attempt to fetch it now for immediate feedback on the settings page.
                    $temp_resolved_id = $this->_fetch_custom_field_id_from_api( GOHIGHLEVEL_PRIVATE_API_KEY, $location_id, $role_custom_field_key );
                    if ( ! empty( $temp_resolved_id ) ) {
                        // If successfully resolved now, update cache and display green.
                        $this->_set_cached_custom_field_id( $role_custom_field_key, $location_id, $temp_resolved_id );
                        // IMPORTANT: Update $cached_id here so the green message is displayed immediately.
                        $cached_id = $temp_resolved_id; 
                        ?>
                        <br /><span style="color: green;"><strong><?php esc_html_e( 'Resolved ID:', 'gohighlevel-user-sync' ); ?></strong> <code><?php echo esc_html( $cached_id ); ?></code></span>
                        <?php
                    } else {
                        // Display error if resolution failed.
                        ?>
                        <br /><span style="color: red;"><strong><?php esc_html_e( 'Error: Custom Field ID could not be resolved.', 'gohighlevel-user-sync' ); ?></strong> <?php esc_html_e( 'Please ensure the Custom Field Key, Location ID, and Private API Key are correct and the API key has permissions to read custom fields. Check your WordPress debug log for details.', 'gohighlevel-user-sync' ); ?></span>
                        <?php
                    }
                endif; ?>
            <?php else : ?>
                <br /><span class="description"><?php esc_html_e( 'Enter a Custom Field Key and Location ID, and define your Private API Key in wp-config.php to resolve the ID.', 'gohighlevel-user-sync' ); ?></span>
            <?php endif; ?>
        </p>
        <?php
    }

    /**
     * Renders the Location ID input field.
     */
    public function location_id_field_callback() {
        $options = get_option( 'gohighlevel_user_sync_options' );
        $location_id = isset( $options['location_id'] ) ? sanitize_text_field( $options['location_id'] ) : '';
        ?>
        <input type="text" name="gohighlevel_user_sync_options[location_id]" value="<?php echo esc_attr( $location_id ); ?>" class="regular-text" placeholder="<?php esc_attr_e( 'Enter your GoHighLevel Location ID', 'gohighlevel-user-sync' ); ?>"/>
        <p class="description"><?php esc_html_e( 'This is the unique ID of your GoHighLevel sub-account (location). You can find it in your GoHighLevel sub-account under `Settings > Business Profile`.', 'gohighlevel-user-sync' ); ?></p>
        <?php
    }

    /**
     * Sanitizes and validates plugin options.
     *
     * @param array $input The raw input from the settings form.
     * @return array The sanitized options.
     */
    public function sanitize_options( $input ) {
        // IMPORTANT FIX: Only proceed with sanitization and nonce verification if this is a POST request
        // and specifically for our settings group. This prevents wp_die on page load (GET requests).
        if ( ! isset( $_POST['option_page'] ) || $_POST['option_page'] !== 'gohighlevel_user_sync_settings_group' ) {
            // This is not a submission for our settings group, or not a POST request.
            // Return the current options to prevent accidental data loss.
            return get_option( 'gohighlevel_user_sync_options', array() );
        }

        // Verify nonce for settings form submission.
        if ( ! isset( $_POST['_wpnonce'] ) || ! wp_verify_nonce( $_POST['_wpnonce'], 'gohighlevel_user_sync_settings_group-options' ) ) {
            wp_die( __( 'Security check failed. Please try again.', 'gohighlevel-user-sync' ), __( 'Error', 'gohighlevel-user-sync' ), array( 'response' => 403 ) );
        }

        $new_input = array();
        $current_options = get_option( 'gohighlevel_user_sync_options', array() );

        // Persist the role custom field key.
        $new_input['role_custom_field_key'] = isset( $input['role_custom_field_key'] ) ? sanitize_text_field( $input['role_custom_field_key'] ) : '';
        // Persist the location ID.
        $new_input['location_id'] = isset( $input['location_id'] ) ? sanitize_text_field( $input['location_id'] ) : '';

        // Initialize cached_custom_field_ids if not set.
        $new_input['cached_custom_field_ids'] = isset( $current_options['cached_custom_field_ids'] ) ? $current_options['cached_custom_field_ids'] : array();

        // If key or location changes, invalidate the cached ID for this combination
        $key_changed = ( isset( $input['role_custom_field_key'] ) && $input['role_custom_field_key'] !== ( $current_options['role_custom_field_key'] ?? '' ) );
        $location_changed = ( isset( $input['location_id'] ) && $input['location_id'] !== ( $current_options['location_id'] ?? '' ) );

        if ( $key_changed || $location_changed ) {
            // Clear the specific cached ID for this combination
            if ( isset( $new_input['cached_custom_field_ids'][ ( $current_options['location_id'] ?? '' ) ][ ( $current_options['role_custom_field_key'] ?? '' ) ] ) ) {
                unset( $new_input['cached_custom_field_ids'][ ( $current_options['location_id'] ?? '' ) ][ ( $current_options['role_custom_field_key'] ?? '' ) ] );
            }

            // Attempt to resolve the ID immediately after saving new settings
            if ( ! empty( $new_input['role_custom_field_key'] ) && ! empty( $new_input['location_id'] ) && defined( 'GOHIGHLEVEL_PRIVATE_API_KEY' ) && ! empty( GOHIGHLEVEL_PRIVATE_API_KEY ) ) {
                $resolved_id = $this->_fetch_custom_field_id_from_api( GOHIGHLEVEL_PRIVATE_API_KEY, $new_input['location_id'], $new_input['role_custom_field_key'] );
                if ( $resolved_id ) {
                    $this->_set_cached_custom_field_id( $new_input['role_custom_field_key'], $new_input['location_id'], $resolved_id );
                    // Update the new_input with the freshly cached ID so it's saved correctly
                    $new_input['cached_custom_field_ids'][ $new_input['location_id'] ][ $new_input['role_custom_field_key'] ] = $resolved_id;
                } else {
                    // Log the failure to resolve ID on save
                    error_log( '[GoHighLevel Sync ERROR]: Failed to resolve custom field ID on settings save for key "' . $new_input['role_custom_field_key'] . '" and location "' . $new_input['location_id'] . '".' );
                }
            }
        }

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
     * Triggers user synchronization when a new user registers.
     *
     * @param int $user_id The ID of the newly registered user.
     */
    public function sync_user_on_register( $user_id ) {
        // New user registration is typically a clean process, direct sync is usually fine.
        $this->sync_user_to_gohighlevel( $user_id );
    }

    /**
     * Triggers user synchronization when a user's profile is updated.
     *
     * @param int     $user_id The ID of the updated user.
     * @param WP_User $old_user_data The WP_User object before the update.
     */
    public function sync_user_on_update( $user_id, $old_user_data ) {
        // Defer sync if update is from admin to avoid caching issues.
        if ( is_admin() ) {
            $this->schedule_deferred_sync( $user_id );
        } else {
            $this->sync_user_to_gohighlevel( $user_id );
        }
    }

    /**
     * Triggers user synchronization when a user's role changes.
     *
     * @param int    $user_id The ID of the user whose role changed.
     * @param string $role The new role.
     * @param array  $old_roles The old roles.
     */
    public function sync_user_on_role_change( $user_id, $role, $old_roles ) {
        // Defer sync if role change is from admin to avoid caching issues.
        if ( is_admin() ) {
            $this->schedule_deferred_sync( $user_id );
        } else {
            $this->sync_user_to_gohighlevel( $user_id );
        }
    }

    /**
     * Schedules a single event for user synchronization.
     * This is used for admin-side updates to ensure data consistency.
     *
     * @param int $user_id The ID of the user to sync.
     */
    private function schedule_deferred_sync( $user_id ) {
        // Clear any existing scheduled events for this user to prevent duplicates.
        wp_clear_scheduled_hook( self::DEFERRED_SYNC_ACTION, array( $user_id ) );

        // Schedule the event to run in a few seconds.
        wp_schedule_single_event( time() + 5, self::DEFERRED_SYNC_ACTION, array( $user_id ) );
        error_log( '[GoHighLevel Sync INFO]: Scheduled deferred sync for user ID: ' . $user_id . ' (Admin update).' );
    }

    /**
     * Callback function for the deferred sync action.
     *
     * @param int $user_id The ID of the user to sync.
     */
    public function perform_deferred_sync( $user_id ) {
        error_log( '[GoHighLevel Sync INFO]: Performing deferred sync for user ID: ' . $user_id );
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
                // Note: The actual sync for role changes is now handled by sync_user_on_role_change
                // which will defer if in admin.
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
        $role_custom_field_key = isset( $options['role_custom_field_key'] ) ? sanitize_text_field( $options['role_custom_field_key'] ) : '';
        $location_id = isset( $options['location_id'] ) ? sanitize_text_field( $options['location_id'] ) : '';

        // Validate required settings.
        if ( empty( $role_custom_field_key ) ) {
            error_log( '[GoHighLevel Sync ERROR]: GoHighLevel Role Custom Field Key is not set. Please configure it in plugin settings.' );
            return;
        }
        if ( empty( $location_id ) ) {
            error_log( '[GoHighLevel Sync ERROR]: GoHighLevel Location ID is not set. Please configure it in plugin settings.' );
            return;
        }

        // Get Private Integrations API Key from wp-config.php.
        if ( ! defined( 'GOHIGHLEVEL_PRIVATE_API_KEY' ) || empty( GOHIGHLEVEL_PRIVATE_API_KEY ) ) {
            error_log( '[GoHighLevel Sync ERROR]: GoHighLevel Private API Key is not defined in wp-config.php.' );
            return;
        }
        $api_key = GOHIGHLEVEL_PRIVATE_API_KEY;

        // --- Fetch/Cache Custom Field ID ---
        $role_custom_field_id = $this->_get_cached_custom_field_id( $role_custom_field_key, $location_id );

        if ( empty( $role_custom_field_id ) ) {
            error_log( '[GoHighLevel Sync INFO]: Custom field ID not found in cache for key "' . $role_custom_field_key . '". Attempting to fetch from API.' );
            $role_custom_field_id = $this->_fetch_custom_field_id_from_api( $api_key, $location_id, $role_custom_field_key );

            if ( empty( $role_custom_field_id ) ) {
                error_log( '[GoHighLevel Sync ERROR]: Could not retrieve GoHighLevel Custom Field ID for key "' . $role_custom_field_key . '" and Location ID "' . $location_id . '". Please ensure the key is correct and the API key has necessary permissions.' );
                return;
            }
            // Cache the fetched ID
            $this->_set_cached_custom_field_id( $role_custom_field_key, $location_id, $role_custom_field_id );
        }
        // --- End Fetch/Cache Custom Field ID ---

        // IMPORTANT FIX: Clear user cache before getting user data to ensure freshest roles.
        // This is crucial for deferred syncs as well.
        clean_user_cache( $user_id );
        $user = get_user_by( 'ID', $user_id );

        if ( ! $user ) {
            error_log( '[GoHighLevel Sync ERROR]: User with ID ' . $user_id . ' not found after cache clear.' );
            return;
        }

        // Extract user details.
        $first_name = $user->first_name ? $user->first_name : $user->display_name;
        $last_name  = $user->last_name ? $user->last_name : '';
        $name       = trim( $first_name . ' ' . $last_name ); // Added 'name' field as per curl example
        $email      = $user->user_email;

        // Debugging: Log raw roles immediately after retrieving the user object
        error_log( '[GoHighLevel Sync DEBUG]: Raw user roles from $user->roles (after cache clear): ' . print_r( $user->roles, true ) );

        $roles_array = $this->get_user_roles( $user ); // Get all roles as an array of human-readable strings.

        // GoHighLevel API Endpoint for Upsert Contact.
        $api_url = self::GHL_API_BASE_URL . 'contacts/upsert'; // Updated endpoint path

        // Prepare the payload for the GoHighLevel API.
        $body = array(
            'firstName' => $first_name,
            'lastName'  => $last_name,
            'name'      => $name,
            'email'     => $email,
            'locationId' => $location_id, // Location ID in the request body.
            // Add custom fields for the role.
            'customFields' => array(
                array(
                    'id'          => $role_custom_field_id, // Use the fetched ID
                    'key'         => $role_custom_field_key, // Include the key as per curl example
                    'field_value' => $roles_array, // Sending an array of human-readable roles.
                ),
            ),
            // You can add more fields here if needed, e.g., phone, tags etc.
            // 'phone' => $user->phone_number,
            // 'tags' => ['WordPress User', $role],
        );

        // Log the full request body for debugging.
        error_log( '[GoHighLevel Sync DEBUG]: Request Body: ' . wp_json_encode( $body ) );

        // Prepare headers for the API request.
        $headers = array(
            'Content-Type'  => 'application/json',
            // For Private Integrations, the API key is passed directly as Authorization: Bearer.
            'Authorization' => 'Bearer ' . $api_key,
            'Version'       => '2021-07-28', // Recommended API version.
            'Accept'        => 'application/json',
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
     * Helper function to get all human-readable roles of a user as an array of strings.
     *
     * @param WP_User $user The WP_User object.
     * @return array An array of human-readable role names. Returns an empty array if no roles found.
     */
    private function get_user_roles( $user ) {
        $roles_array = array();
        if ( ! empty( $user->roles ) && is_array( $user->roles ) ) {
            global $wp_roles; // Access the global WordPress roles object.
            foreach ( $user->roles as $role_slug ) {
                $human_readable_name = '';
                if ( isset( $wp_roles->role_names[ $role_slug ] ) ) {
                    $human_readable_name = $wp_roles->role_names[ $role_slug ]; // Get the human-readable name.
                } else {
                    // Fallback to capitalized slug with spaces if name not found.
                    $human_readable_name = ucfirst( str_replace( '_', ' ', $role_slug ) ); 
                }
                $roles_array[] = $human_readable_name;
                error_log( '[GoHighLevel Sync DEBUG]: Processing role slug: "' . $role_slug . '" -> Human-readable name: "' . $human_readable_name . '"' );
            }
        }
        error_log( '[GoHighLevel Sync DEBUG]: Final roles array for GoHighLevel: ' . wp_json_encode( $roles_array ) );
        return $roles_array; // Return the array directly.
    }

    /**
     * Retrieves a cached custom field ID for a given key and location.
     *
     * @param string $field_key The custom field key.
     * @param string $location_id The GoHighLevel location ID.
     * @return string|false The cached field ID on success, false if not found.
     */
    private function _get_cached_custom_field_id( $field_key, $location_id ) {
        $options = get_option( 'gohighlevel_user_sync_options' );
        if ( isset( $options['cached_custom_field_ids'][ $location_id ][ $field_key ] ) ) {
            return $options['cached_custom_field_ids'][ $location_id ][ $field_key ];
        }
        return false;
    }

    /**
     * Caches a custom field ID for a given key and location.
     *
     * @param string $field_key The custom field key.
     * @param string $location_id The GoHighLevel location ID.
     * @param string $field_id The ID to cache.
     */
    private function _set_cached_custom_field_id( $field_key, $location_id, $field_id ) {
        $options = get_option( 'gohighlevel_user_sync_options' );
        if ( ! isset( $options['cached_custom_field_ids'] ) ) {
            $options['cached_custom_field_ids'] = array();
        }
        if ( ! isset( $options['cached_custom_field_ids'][ $location_id ] ) ) {
            $options['cached_custom_field_ids'][ $location_id ] = array();
        }
        $options['cached_custom_field_ids'][ $location_id ][ $field_key ] = $field_id;
        update_option( 'gohighlevel_user_sync_options', $options );
    }

    /**
     * Fetches the custom field ID from the GoHighLevel API based on its key.
     *
     * @param string $api_key The Private Integrations API Key.
     * @param string $location_id The GoHighLevel location ID.
     * @param string $field_key The custom field key to look up.
     * @return string|false The custom field ID on success, false on failure.
     */
    private function _fetch_custom_field_id_from_api( $api_key, $location_id, $field_key ) {
        if ( empty( $api_key ) || empty( $location_id ) || empty( $field_key ) ) {
            error_log( '[GoHighLevel Sync ERROR]: _fetch_custom_field_id_from_api called with missing parameters. API Key, Location ID, or Field Key is empty.' );
            return false;
        }

        $api_url = self::GHL_API_BASE_URL . 'locations/' . $location_id . '/customFields/';

        $headers = array(
            'Accept'        => 'application/json',
            'Authorization' => 'Bearer ' . $api_key,
            'Version'       => '2021-07-28',
        );

        error_log( '[GoHighLevel Sync INFO]: Attempting to fetch custom field ID for key "' . $field_key . '" from API for location "' . $location_id . '".' );

        $response = wp_remote_get(
            $api_url,
            array(
                'headers'   => $headers,
                'timeout'   => 30,
                'sslverify' => true,
            )
        );

        if ( is_wp_error( $response ) ) {
            $error_message = $response->get_error_message();
            error_log( '[GoHighLevel Sync ERROR]: Failed to fetch custom fields from API for key "' . $field_key . '", Location ID "' . $location_id . '". WP_Error: ' . $error_message );
            return false;
        }

        $response_code = wp_remote_retrieve_response_code( $response );
        $response_body = wp_remote_retrieve_body( $response );
        $data          = json_decode( $response_body, true );

        if ( $response_code >= 200 && $response_code < 300 && isset( $data['customFields'] ) && is_array( $data['customFields'] ) ) {
            foreach ( $data['customFields'] as $field ) {
                if ( isset( $field['fieldKey'] ) && $field['fieldKey'] === $field_key && isset( $field['id'] ) ) {
                    error_log( '[GoHighLevel Sync INFO]: Successfully resolved custom field ID "' . $field['id'] . '" for key "' . $field_key . '".' );
                    return sanitize_text_field( $field['id'] );
                }
            }
            error_log( '[GoHighLevel Sync ERROR]: Custom field with key "' . $field_key . '" not found in GoHighLevel API response for location "' . $location_id . '". Response: ' . $response_body );
            return false;
        } else {
            error_log( '[GoHighLevel Sync ERROR]: Failed to retrieve custom fields from GoHighLevel API. Status: ' . $response_code . ', Response: ' . $response_body );
            return false;
        }
    }
}

// Instantiate the plugin class.
new GoHighLevel_User_Sync_Plugin();
