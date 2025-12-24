<?php
/**
 * Plugin Name: Security User Auditor
 * Plugin URI: https://example.com
 * Description: Advanced user management tool to find hidden users, view permissions, and clean compromised accounts
 * Version: 1.0.0
 * Author: Security Team
 * License: GPL v2 or later
 * Text Domain: security-user-auditor
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

class SecurityUserAuditor {
    
    private $capabilities_list;
    
    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
        add_action('wp_ajax_sua_delete_user', array($this, 'ajax_delete_user'));
        add_action('wp_ajax_sua_get_user_details', array($this, 'ajax_get_user_details'));
        add_action('admin_init', array($this, 'register_settings'));
        
        // Initialize capabilities list
        $this->capabilities_list = $this->get_all_capabilities();
    }
    
    /**
     * Register plugin settings
     */
    public function register_settings() {
        register_setting('sua_settings_group', 'sua_scan_hidden_users');
        register_setting('sua_settings_group', 'sua_auto_scan');
        register_setting('sua_settings_group', 'sua_notify_on_hidden');
    }
    
    /**
     * Add admin menu
     */
    public function add_admin_menu() {
        add_menu_page(
            'Security User Audit',
            'User Auditor',
            'manage_options',
            'security-user-auditor',
            array($this, 'display_admin_page'),
            'dashicons-shield',
            30
        );
        
        add_submenu_page(
            'security-user-auditor',
            'User Scanner',
            'Scan Users',
            'manage_options',
            'security-user-auditor-scan',
            array($this, 'display_scanner_page')
        );
        
        add_submenu_page(
            'security-user-auditor',
            'Settings',
            'Settings',
            'manage_options',
            'security-user-auditor-settings',
            array($this, 'display_settings_page')
        );
    }
    
    /**
     * Enqueue admin scripts
     */
    public function enqueue_admin_scripts($hook) {
        if (strpos($hook, 'security-user-auditor') !== false) {
            wp_enqueue_style('sua-admin-css', plugin_dir_url(__FILE__) . 'assets/css/admin.css', array(), '1.0.0');
            wp_enqueue_script('sua-admin-js', plugin_dir_url(__FILE__) . 'assets/js/admin.js', array('jquery'), '1.0.0', true);
            
            wp_localize_script('sua-admin-js', 'sua_ajax', array(
                'ajax_url' => admin_url('admin-ajax.php'),
                'nonce' => wp_create_nonce('sua_ajax_nonce'),
                'confirm_delete' => __('Are you sure you want to delete this user? This action cannot be undone.', 'security-user-auditor'),
                'deleting' => __('Deleting...', 'security-user-auditor'),
                'success' => __('Success!', 'security-user-auditor'),
                'error' => __('Error!', 'security-user-auditor')
            ));
        }
    }
    
    /**
     * Get all users including potential hidden ones
     */
    private function get_all_users_including_hidden() {
        global $wpdb;
        
        $users = array();
        
        // Method 1: Standard WordPress users
        $standard_users = get_users(array(
            'fields' => 'all_with_meta'
        ));
        
        foreach ($standard_users as $user) {
            $users[$user->ID] = array(
                'source' => 'standard',
                'data' => $user
            );
        }
        
        // Method 2: Direct database query (finds users hidden from admin queries)
        $db_users = $wpdb->get_results(
            "SELECT * FROM {$wpdb->users} WHERE 1=1"
        );
        
        foreach ($db_users as $db_user) {
            if (!isset($users[$db_user->ID])) {
                $user_obj = new WP_User($db_user->ID);
                $users[$db_user->ID] = array(
                    'source' => 'database',
                    'data' => $user_obj
                );
            }
        }
        
        // Method 3: Check user_meta for hidden flags
        $hidden_users = $wpdb->get_results(
            "SELECT user_id, meta_key, meta_value 
             FROM {$wpdb->usermeta} 
             WHERE meta_key LIKE '%hidden%' 
             OR meta_key LIKE '%_pre_user%'
             OR meta_key LIKE '%backdoor%'
             OR meta_value LIKE '%hidden%'"
        );
        
        foreach ($hidden_users as $hidden) {
            if (!isset($users[$hidden->user_id])) {
                $user_obj = new WP_User($hidden->user_id);
                if ($user_obj->exists()) {
                    $users[$hidden->user_id] = array(
                        'source' => 'hidden_meta',
                        'data' => $user_obj,
                        'hidden_meta' => array($hidden->meta_key => $hidden->meta_value)
                    );
                }
            }
        }
        
        return $users;
    }
    
    /**
     * Get all WordPress capabilities
     */
    private function get_all_capabilities() {
        global $wp_roles;
        
        $capabilities = array();
        
        if (!isset($wp_roles)) {
            $wp_roles = new WP_Roles();
        }
        
        foreach ($wp_roles->roles as $role) {
            if (isset($role['capabilities']) && is_array($role['capabilities'])) {
                foreach ($role['capabilities'] as $cap => $value) {
                    $capabilities[$cap] = $cap;
                }
            }
        }
        
        // Add additional common capabilities
        $additional_caps = array(
            'edit_dashboard',
            'export',
            'import',
            'unfiltered_html',
            'edit_files',
            'edit_plugins',
            'edit_themes',
            'update_plugins',
            'delete_plugins',
            'install_plugins',
            'update_themes',
            'install_themes',
            'update_core',
            'manage_network',
            'manage_sites',
            'create_users',
            'delete_users',
            'remove_users',
            'promote_users'
        );
        
        foreach ($additional_caps as $cap) {
            $capabilities[$cap] = $cap;
        }
        
        ksort($capabilities);
        return $capabilities;
    }
    
    /**
     * Get user capabilities in detail
     */
    private function get_user_capabilities_details($user_id) {
        $user = get_userdata($user_id);
        $capabilities = array();
        
        if (!$user) {
            return $capabilities;
        }
        
        foreach ($this->capabilities_list as $cap) {
            if ($user->has_cap($cap)) {
                $capabilities[$cap] = array(
                    'has_cap' => true,
                    'source' => 'unknown'
                );
                
                // Try to determine where the capability came from
                if (isset($user->caps[$cap])) {
                    $capabilities[$cap]['source'] = 'direct_assignment';
                } else {
                    // Check if it comes from a role
                    foreach ($user->roles as $role) {
                        $role_obj = get_role($role);
                        if ($role_obj && isset($role_obj->capabilities[$cap]) && $role_obj->capabilities[$cap]) {
                            $capabilities[$cap]['source'] = 'role: ' . $role;
                            break;
                        }
                    }
                }
            }
        }
        
        return $capabilities;
    }
    
    /**
     * Check if user is suspicious
     */
    private function is_suspicious_user($user) {
        $suspicious_patterns = array(
            'adminbackup',
            'backupadmin',
            'hiddenuser',
            'testuser',
            'demo',
            'temp',
            'backdoor',
            'hacker',
            'root',
            'system',
            'unknown',
            'wordpress',
            'wpadmin',
            'administrator_backup',
            'emergency'
        );
        
        $suspicious = false;
        $reasons = array();
        
        // Check username patterns
        $username = strtolower($user->user_login);
        foreach ($suspicious_patterns as $pattern) {
            if (strpos($username, $pattern) !== false) {
                $suspicious = true;
                $reasons[] = 'Suspicious username pattern: ' . $pattern;
                break;
            }
        }
        
        // Check email patterns
        $email = strtolower($user->user_email);
        if (strpos($email, 'example.com') !== false || 
            strpos($email, 'test.com') !== false ||
            strpos($email, 'localhost') !== false) {
            $suspicious = true;
            $reasons[] = 'Suspicious email address';
        }
        
        // Check registration date
        $registered = strtotime($user->user_registered);
        $now = time();
        $days_old = ($now - $registered) / DAY_IN_SECONDS;
        
        if ($days_old < 1) {
            $suspicious = true;
            $reasons[] = 'Very recently created account';
        }
        
        // Check last login (if we have that data)
        $last_login = get_user_meta($user->ID, 'last_login', true);
        if (!$last_login && $days_old > 30) {
            // Account created more than 30 days ago but never logged in
            $suspicious = true;
            $reasons[] = 'Old account with no login history';
        }
        
        return array(
            'suspicious' => $suspicious,
            'reasons' => $reasons
        );
    }
    
    /**
     * Display main admin page
     */
    public function display_admin_page() {
        $users = $this->get_all_users_including_hidden();
        ?>
        <div class="wrap sua-admin-wrap">
            <h1>Security User Auditor</h1>
            <p class="description">Comprehensive user management and security audit tool</p>
            
            <div class="notice notice-warning">
                <p><strong>Warning:</strong> This tool reveals all users including potentially hidden backdoor accounts. Use with caution.</p>
            </div>
            
            <div class="sua-stats-box">
                <div class="sua-stat-card">
                    <h3><?php echo count($users); ?></h3>
                    <p>Total Users Found</p>
                </div>
                <div class="sua-stat-card">
                    <h3><?php echo count($this->capabilities_list); ?></h3>
                    <p>Capabilities Tracked</p>
                </div>
                <div class="sua-stat-card">
                    <h3><?php echo $this->count_suspicious_users($users); ?></h3>
                    <p>Suspicious Users</p>
                </div>
            </div>
            
            <div class="sua-users-table-container">
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Display Name</th>
                            <th>Roles</th>
                            <th>Source</th>
                            <th>Status</th>
                            <th>Registered</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($users as $user_data): 
                            $user = $user_data['data'];
                            $source = $user_data['source'];
                            $suspicious = $this->is_suspicious_user($user);
                            $row_class = $suspicious['suspicious'] ? 'sua-suspicious-row' : '';
                        ?>
                        <tr class="<?php echo $row_class; ?>" data-user-id="<?php echo $user->ID; ?>">
                            <td><?php echo $user->ID; ?></td>
                            <td>
                                <strong><?php echo esc_html($user->user_login); ?></strong>
                                <?php if ($suspicious['suspicious']): ?>
                                    <span class="dashicons dashicons-warning" title="<?php echo esc_attr(implode(', ', $suspicious['reasons'])); ?>"></span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo esc_html($user->user_email); ?></td>
                            <td><?php echo esc_html($user->display_name); ?></td>
                            <td>
                                <?php 
                                $roles = $user->roles;
                                if (!empty($roles)) {
                                    echo implode(', ', array_map('esc_html', $roles));
                                } else {
                                    echo '<em>No roles assigned</em>';
                                }
                                ?>
                            </td>
                            <td>
                                <span class="sua-source-badge sua-source-<?php echo esc_attr($source); ?>">
                                    <?php echo esc_html(ucfirst($source)); ?>
                                </span>
                            </td>
                            <td>
                                <?php if (in_array('administrator', $user->roles)): ?>
                                    <span class="sua-role-badge sua-role-admin">Administrator</span>
                                <?php elseif (!empty($user->roles)): ?>
                                    <span class="sua-role-badge"><?php echo esc_html(ucfirst(reset($user->roles))); ?></span>
                                <?php else: ?>
                                    <span class="sua-role-badge sua-role-none">No Role</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo date_i18n(get_option('date_format'), strtotime($user->user_registered)); ?></td>
                            <td>
                                <button class="button button-small sua-view-details" data-user-id="<?php echo $user->ID; ?>">
                                    <span class="dashicons dashicons-visibility"></span> Details
                                </button>
                                <?php if ($user->ID != get_current_user_id()): ?>
                                    <button class="button button-small button-danger sua-delete-user" data-user-id="<?php echo $user->ID; ?>" data-username="<?php echo esc_attr($user->user_login); ?>">
                                        <span class="dashicons dashicons-trash"></span> Delete
                                    </button>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <!-- User Details Modal -->
            <div id="sua-user-details-modal" class="sua-modal" style="display: none;">
                <div class="sua-modal-content">
                    <div class="sua-modal-header">
                        <h2>User Details</h2>
                        <button class="sua-modal-close">&times;</button>
                    </div>
                    <div class="sua-modal-body">
                        <div id="sua-user-details-content"></div>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
    
    /**
     * Count suspicious users
     */
    private function count_suspicious_users($users) {
        $count = 0;
        foreach ($users as $user_data) {
            $suspicious = $this->is_suspicious_user($user_data['data']);
            if ($suspicious['suspicious']) {
                $count++;
            }
        }
        return $count;
    }
    
    /**
     * Display scanner page
     */
    public function display_scanner_page() {
        ?>
        <div class="wrap">
            <h1>Advanced User Scanner</h1>
            
            <div class="card">
                <h2>Deep Scan Options</h2>
                <form method="post" action="">
                    <?php wp_nonce_field('sua_deep_scan', 'sua_scan_nonce'); ?>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="scan_type">Scan Type</label>
                            </th>
                            <td>
                                <select name="scan_type" id="scan_type">
                                    <option value="quick">Quick Scan (Standard WordPress)</option>
                                    <option value="deep">Deep Scan (Database Level)</option>
                                    <option value="full">Full Scan (Database + File System)</option>
                                </select>
                                <p class="description">Deep scans may take longer but find more hidden users.</p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="check_meta">Check User Metadata</label>
                            </th>
                            <td>
                                <input type="checkbox" name="check_meta" id="check_meta" value="1" checked>
                                <label for="check_meta">Examine user meta data for hidden flags</label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="check_files">Check File System</label>
                            </th>
                            <td>
                                <input type="checkbox" name="check_files" id="check_files" value="1">
                                <label for="check_files">Scan for user-related files in plugins/themes</label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="fix_issues">Auto-fix Issues</label>
                            </th>
                            <td>
                                <input type="checkbox" name="fix_issues" id="fix_issues" value="1">
                                <label for="fix_issues">Automatically fix common issues found</label>
                                <p class="description warning">Warning: This will make changes automatically!</p>
                            </td>
                        </tr>
                    </table>
                    
                    <p class="submit">
                        <button type="submit" name="start_scan" class="button button-primary">
                            <span class="dashicons dashicons-search"></span> Start Scan
                        </button>
                    </p>
                </form>
            </div>
            
            <?php
            if (isset($_POST['start_scan']) && check_admin_referer('sua_deep_scan', 'sua_scan_nonce')) {
                $this->run_deep_scan($_POST);
            }
            ?>
            
            <div class="card">
                <h2>Quick Actions</h2>
                <div class="sua-quick-actions">
                    <button class="button" onclick="suaExportUsers()">
                        <span class="dashicons dashicons-download"></span> Export User List
                    </button>
                    <button class="button" onclick="suaCheckAdminCount()">
                        <span class="dashicons dashicons-admin-users"></span> Check Admin Count
                    </button>
                    <button class="button button-secondary" onclick="suaClearCache()">
                        <span class="dashicons dashicons-update"></span> Clear Scan Cache
                    </button>
                </div>
            </div>
        </div>
        
        <script>
        function suaExportUsers() {
            alert('Export feature would be implemented here');
        }
        
        function suaCheckAdminCount() {
            alert('Admin count check would be implemented here');
        }
        
        function suaClearCache() {
            if (confirm('Clear scan cache?')) {
                // AJAX call to clear cache
            }
        }
        </script>
        <?php
    }
    
    /**
     * Run deep scan
     */
    private function run_deep_scan($options) {
        global $wpdb;
        
        echo '<div class="card"><h2>Scan Results</h2>';
        
        $issues_found = array();
        
        // 1. Check for database inconsistencies
        $db_users = $wpdb->get_results("SELECT ID FROM {$wpdb->users}");
        $wp_users = get_users(array('fields' => 'ID'));
        
        $db_ids = array();
        foreach ($db_users as $u) {
            $db_ids[] = $u->ID;
        }
        
        $diff = array_diff($db_ids, $wp_users);
        
        if (!empty($diff)) {
            $issues_found[] = array(
                'type' => 'critical',
                'message' => 'Found ' . count($diff) . ' users in database not visible in WordPress admin: ' . implode(', ', $diff),
                'fix' => 'remove_hidden_users'
            );
        }
        
        // 2. Check user_meta for suspicious entries
        $suspicious_meta = $wpdb->get_results(
            "SELECT user_id, meta_key, meta_value 
             FROM {$wpdb->usermeta} 
             WHERE meta_key LIKE '%backdoor%' 
             OR meta_key LIKE '%hidden%'
             OR meta_key LIKE '%_pre_%'
             OR meta_key LIKE '%malware%'
             OR meta_key LIKE '%hack%'
             OR meta_value LIKE '%eval%'
             OR meta_value LIKE '%base64%'
             OR meta_value LIKE '%script%'"
        );
        
        if (!empty($suspicious_meta)) {
            $issues_found[] = array(
                'type' => 'warning',
                'message' => 'Found ' . count($suspicious_meta) . ' suspicious user meta entries',
                'details' => $suspicious_meta
            );
        }
        
        // 3. Check for users with no roles
        $users_no_roles = get_users(array(
            'meta_query' => array(
                array(
                    'key' => $wpdb->get_blog_prefix() . 'capabilities',
                    'compare' => 'NOT EXISTS'
                )
            )
        ));
        
        if (!empty($users_no_roles)) {
            $issues_found[] = array(
                'type' => 'info',
                'message' => 'Found ' . count($users_no_roles) . ' users with no roles assigned'
            );
        }
        
        // Display results
        if (empty($issues_found)) {
            echo '<div class="notice notice-success"><p>No issues found! Your user database appears clean.</p></div>';
        } else {
            echo '<div class="sua-scan-results">';
            foreach ($issues_found as $issue) {
                $class = 'notice-' . $issue['type'];
                echo '<div class="notice ' . $class . '"><p><strong>' . ucfirst($issue['type']) . ':</strong> ' . $issue['message'] . '</p>';
                
                if (isset($issue['details'])) {
                    echo '<ul>';
                    foreach ($issue['details'] as $detail) {
                        echo '<li>User ID ' . $detail->user_id . ': ' . $detail->meta_key . ' = ' . esc_html(substr($detail->meta_value, 0, 100)) . '</li>';
                    }
                    echo '</ul>';
                }
                
                if (isset($issue['fix']) && isset($options['fix_issues'])) {
                    $this->apply_fix($issue['fix'], $issue);
                }
                
                echo '</div>';
            }
            echo '</div>';
        }
        
        echo '</div>';
    }
    
    /**
     * Apply fixes
     */
    private function apply_fix($fix_type, $issue) {
        switch ($fix_type) {
            case 'remove_hidden_users':
                echo '<p><em>Auto-fix would remove hidden users here...</em></p>';
                break;
        }
    }
    
    /**
     * Display settings page
     */
    public function display_settings_page() {
        ?>
        <div class="wrap">
            <h1>Security User Auditor Settings</h1>
            
            <form method="post" action="options.php">
                <?php settings_fields('sua_settings_group'); ?>
                <?php do_settings_sections('sua_settings_group'); ?>
                
                <table class="form-table">
                    <tr>
                        <th scope="row">Automatic Scanning</th>
                        <td>
                            <input type="checkbox" name="sua_auto_scan" value="1" <?php checked(get_option('sua_auto_scan'), 1); ?>>
                            <label for="sua_auto_scan">Run automatic scans daily</label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Email Notifications</th>
                        <td>
                            <input type="checkbox" name="sua_notify_on_hidden" value="1" <?php checked(get_option('sua_notify_on_hidden'), 1); ?>>
                            <label for="sua_notify_on_hidden">Email admin when hidden users are found</label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Deep Scan Sensitivity</th>
                        <td>
                            <select name="sua_scan_hidden_users">
                                <option value="low" <?php selected(get_option('sua_scan_hidden_users'), 'low'); ?>>Low (Standard checks only)</option>
                                <option value="medium" <?php selected(get_option('sua_scan_hidden_users'), 'medium'); ?>>Medium (Database level)</option>
                                <option value="high" <?php selected(get_option('sua_scan_hidden_users'), 'high'); ?>>High (Full system scan)</option>
                            </select>
                            <p class="description">Higher sensitivity finds more issues but uses more resources.</p>
                        </td>
                    </tr>
                </table>
                
                <?php submit_button(); ?>
            </form>
            
            <div class="card">
                <h2>Database Cleanup</h2>
                <p>Remove orphaned user metadata and clean up database:</p>
                <button class="button button-secondary" onclick="suaCleanupDatabase()">
                    <span class="dashicons dashicons-database"></span> Clean Database
                </button>
                <p class="description">This will remove user metadata for non-existent users.</p>
            </div>
        </div>
        
        <script>
        function suaCleanupDatabase() {
            if (confirm('This will clean up orphaned user data. Continue?')) {
                // AJAX cleanup call
                alert('Database cleanup would run here');
            }
        }
        </script>
        <?php
    }
    
    /**
     * AJAX: Delete user
     */
    public function ajax_delete_user() {
        // Security check
        if (!check_ajax_referer('sua_ajax_nonce', 'nonce', false)) {
            wp_die('Security check failed');
        }
        
        // Permission check
        if (!current_user_can('delete_users')) {
            wp_die('Insufficient permissions');
        }
        
        $user_id = intval($_POST['user_id']);
        $current_user_id = get_current_user_id();
        
        // Prevent deleting yourself
        if ($user_id == $current_user_id) {
            wp_send_json_error(array(
                'message' => 'You cannot delete your own account'
            ));
        }
        
        // Check if user exists
        $user = get_userdata($user_id);
        if (!$user) {
            wp_send_json_error(array(
                'message' => 'User not found'
            ));
        }
        
        // Log the deletion attempt
        $this->log_action('user_deletion', array(
            'deleted_user_id' => $user_id,
            'deleted_username' => $user->user_login,
            'deleted_by' => $current_user_id
        ));
        
        // Delete the user
        if (is_multisite()) {
            $result = wpmu_delete_user($user_id);
        } else {
            require_once(ABSPATH . 'wp-admin/includes/user.php');
            $result = wp_delete_user($user_id);
        }
        
        if ($result) {
            wp_send_json_success(array(
                'message' => 'User deleted successfully',
                'user_id' => $user_id
            ));
        } else {
            wp_send_json_error(array(
                'message' => 'Failed to delete user'
            ));
        }
    }
    
    /**
     * AJAX: Get user details
     */
    public function ajax_get_user_details() {
        // Security check
        if (!check_ajax_referer('sua_ajax_nonce', 'nonce', false)) {
            wp_die('Security check failed');
        }
        
        $user_id = intval($_POST['user_id']);
        $user = get_userdata($user_id);
        
        if (!$user) {
            wp_send_json_error(array('message' => 'User not found'));
        }
        
        $capabilities = $this->get_user_capabilities_details($user_id);
        $suspicious = $this->is_suspicious_user($user);
        
        // Get user meta
        $user_meta = get_user_meta($user_id);
        $filtered_meta = array();
        foreach ($user_meta as $key => $value) {
            // Filter out sensitive data
            if (!preg_match('/password|auth|token|secret|key|salt/i', $key)) {
                $filtered_meta[$key] = is_array($value) && count($value) === 1 ? $value[0] : $value;
            }
        }
        
        $response = array(
            'success' => true,
            'user' => array(
                'ID' => $user->ID,
                'username' => $user->user_login,
                'email' => $user->user_email,
                'display_name' => $user->display_name,
                'roles' => $user->roles,
                'registered' => $user->user_registered,
                'last_login' => get_user_meta($user_id, 'last_login', true),
                'post_count' => count_user_posts($user_id)
            ),
            'capabilities' => $capabilities,
            'meta' => $filtered_meta,
            'suspicious' => $suspicious,
            'total_capabilities' => count($capabilities)
        );
        
        wp_send_json($response);
    }
    
    /**
     * Log actions
     */
    private function log_action($action, $data) {
        $log_entry = array(
            'timestamp' => current_time('mysql'),
            'action' => $action,
            'user_id' => get_current_user_id(),
            'data' => $data
        );
        
        $logs = get_option('sua_audit_logs', array());
        $logs[] = $log_entry;
        
        // Keep only last 100 logs
        if (count($logs) > 100) {
            $logs = array_slice($logs, -100);
        }
        
        update_option('sua_audit_logs', $logs);
    }
}

// Initialize the plugin
function sua_init() {
    new SecurityUserAuditor();
}
add_action('plugins_loaded', 'sua_init');

// Create database table on activation
register_activation_hook(__FILE__, 'sua_activate');
function sua_activate() {
    // Create audit log table
    global $wpdb;
    $table_name = $wpdb->prefix . 'sua_audit_logs';
    
    $charset_collate = $wpdb->get_charset_collate();
    
    $sql = "CREATE TABLE IF NOT EXISTS $table_name (
        id bigint(20) NOT NULL AUTO_INCREMENT,
        timestamp datetime DEFAULT CURRENT_TIMESTAMP,
        action varchar(100) NOT NULL,
        user_id bigint(20) NOT NULL,
        ip_address varchar(45),
        data longtext,
        PRIMARY KEY (id),
        KEY action (action),
        KEY user_id (user_id),
        KEY timestamp (timestamp)
    ) $charset_collate;";
    
    require_once(ABSPATH . 'wp-admin/includes/upgrade.php');
    dbDelta($sql);
    
    // Set default options
    add_option('sua_scan_hidden_users', 'medium');
    add_option('sua_auto_scan', '0');
    add_option('sua_notify_on_hidden', '1');
}

// Deactivation hook
register_deactivation_hook(__FILE__, 'sua_deactivate');
function sua_deactivate() {
    // Optional: Clear scheduled scans
    wp_clear_scheduled_hook('sua_daily_scan');
}

// Add CSS file
add_action('admin_head', 'sua_admin_styles');
function sua_admin_styles() {
    ?>
    <style>
    .sua-admin-wrap { margin: 20px 0; }
    .sua-stats-box { display: flex; gap: 20px; margin: 20px 0; }
    .sua-stat-card { 
        flex: 1; 
        background: #fff; 
        padding: 20px; 
        border: 1px solid #ccd0d4; 
        border-radius: 4px; 
        text-align: center; 
    }
    .sua-stat-card h3 { margin: 0; font-size: 2em; color: #2271b1; }
    .sua-stat-card p { margin: 5px 0 0; color: #646970; }
    .sua-suspicious-row { background-color: #fff0f0 !important; }
    .sua-suspicious-row td { border-left: 3px solid #d63638 !important; }
    .sua-source-badge { 
        padding: 3px 8px; 
        border-radius: 3px; 
        font-size: 11px; 
        font-weight: 600; 
        text-transform: uppercase; 
    }
    .sua-source-database { background: #f0f6fc; color: #2271b1; }
    .sua-source-hidden_meta { background: #f0f0f1; color: #50575e; }
    .sua-role-badge { 
        display: inline-block; 
        padding: 2px 6px; 
        background: #f0f6fc; 
        border-radius: 3px; 
        font-size: 12px; 
    }
    .sua-role-admin { background: #f0f6fc; color: #2271b1; border: 1px solid #2271b1; }
    .sua-role-none { background: #f0f0f1; color: #50575e; }
    .button-danger { background: #d63638; border-color: #d63638; color: white; }
    .button-danger:hover { background: #b32d2e; border-color: #b32d2e; }
    .sua-modal { 
        position: fixed; 
        top: 0; left: 0; 
        width: 100%; height: 100%; 
        background: rgba(0,0,0,0.5); 
        z-index: 9999; 
        display: flex; 
        align-items: center; 
        justify-content: center; 
    }
    .sua-modal-content { 
        background: white; 
        width: 90%; 
        max-width: 800px; 
        max-height: 90vh; 
        border-radius: 5px; 
        overflow: hidden; 
        box-shadow: 0 0 20px rgba(0,0,0,0.3); 
    }
    .sua-modal-header { 
        padding: 20px; 
        background: #f0f0f1; 
        border-bottom: 1px solid #ccd0d4; 
        display: flex; 
        justify-content: space-between; 
        align-items: center; 
    }
    .sua-modal-body { padding: 20px; overflow-y: auto; max-height: 70vh; }
    .sua-modal-close { 
        background: none; 
        border: none; 
        font-size: 24px; 
        cursor: pointer; 
        color: #50575e; 
    }
    .sua-capabilities-grid { 
        display: grid; 
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); 
        gap: 10px; 
        margin-top: 10px; 
    }
    .sua-capability-item { 
        padding: 8px; 
        background: #f6f7f7; 
        border-radius: 3px; 
        border-left: 3px solid #72aee6; 
    }
    .sua-capability-role { 
        font-size: 11px; 
        color: #50575e; 
        margin-top: 3px; 
    }
    .sua-quick-actions { display: flex; gap: 10px; margin: 20px 0; }
    </style>
    <?php
}

// Add JavaScript
add_action('admin_footer', 'sua_admin_scripts');
function sua_admin_scripts() {
    ?>
    <script>
    jQuery(document).ready(function($) {
        // View user details
        $('.sua-view-details').on('click', function() {
            var userId = $(this).data('user-id');
            
            $.ajax({
                url: sua_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'sua_get_user_details',
                    user_id: userId,
                    nonce: sua_ajax.nonce
                },
                beforeSend: function() {
                    $('#sua-user-details-content').html('<p>Loading...</p>');
                    $('#sua-user-details-modal').show();
                },
                success: function(response) {
                    if (response.success) {
                        var user = response.user;
                        var html = '';
                        
                        // Basic info
                        html += '<h3>User Information</h3>';
                        html += '<table class="widefat">';
                        html += '<tr><th>Username</th><td>' + user.username + '</td></tr>';
                        html += '<tr><th>Email</th><td>' + user.email + '</td></tr>';
                        html += '<tr><th>Display Name</th><td>' + user.display_name + '</td></tr>';
                        html += '<tr><th>Roles</th><td>' + user.roles.join(', ') + '</td></tr>';
                        html += '<tr><th>Registered</th><td>' + user.registered + '</td></tr>';
                        html += '<tr><th>Post Count</th><td>' + user.post_count + '</td></tr>';
                        html += '</table>';
                        
                        // Capabilities
                        html += '<h3>Capabilities (' + response.total_capabilities + ')</h3>';
                        html += '<div class="sua-capabilities-grid">';
                        
                        $.each(response.capabilities, function(cap, details) {
                            html += '<div class="sua-capability-item">';
                            html += '<strong>' + cap + '</strong>';
                            html += '<div class="sua-capability-role">' + details.source + '</div>';
                            html += '</div>';
                        });
                        
                        html += '</div>';
                        
                        // User Meta
                        if (Object.keys(response.meta).length > 0) {
                            html += '<h3>User Metadata</h3>';
                            html += '<table class="widefat">';
                            
                            $.each(response.meta, function(key, value) {
                                html += '<tr>';
                                html += '<th>' + key + '</th>';
                                html += '<td>' + (typeof value === 'object' ? JSON.stringify(value) : value) + '</td>';
                                html += '</tr>';
                            });
                            
                            html += '</table>';
                        }
                        
                        $('#sua-user-details-content').html(html);
                    } else {
                        $('#sua-user-details-content').html('<p>Error loading user details.</p>');
                    }
                }
            });
        });
        
        // Delete user
        $('.sua-delete-user').on('click', function(e) {
            e.preventDefault();
            
            var userId = $(this).data('user-id');
            var username = $(this).data('username');
            
            if (!confirm(sua_ajax.confirm_delete + '\n\nUser: ' + username)) {
                return;
            }
            
            var $button = $(this);
            $button.prop('disabled', true).text(sua_ajax.deleting);
            
            $.ajax({
                url: sua_ajax.ajax_url,
                type: 'POST',
                data: {
                    action: 'sua_delete_user',
                    user_id: userId,
                    nonce: sua_ajax.nonce
                },
                success: function(response) {
                    if (response.success) {
                        alert(sua_ajax.success + ' ' + response.data.message);
                        $button.closest('tr').fadeOut(300, function() {
                            $(this).remove();
                        });
                    } else {
                        alert(sua_ajax.error + ' ' + response.data.message);
                        $button.prop('disabled', false).html('<span class="dashicons dashicons-trash"></span> Delete');
                    }
                },
                error: function() {
                    alert(sua_ajax.error + ' Network error');
                    $button.prop('disabled', false).html('<span class="dashicons dashicons-trash"></span> Delete');
                }
            });
        });
        
        // Close modal
        $('.sua-modal-close, .sua-modal').on('click', function(e) {
            if (e.target === this || $(e.target).hasClass('sua-modal-close')) {
                $('#sua-user-details-modal').hide();
            }
        });
        
        // Prevent modal close when clicking inside
        $('.sua-modal-content').on('click', function(e) {
            e.stopPropagation();
        });
    });
    </script>
    <?php
}

// Add dashboard widget
add_action('wp_dashboard_setup', 'sua_dashboard_widget');
function sua_dashboard_widget() {
    if (current_user_can('manage_options')) {
        wp_add_dashboard_widget(
            'sua_dashboard_widget',
            'Security User Audit',
            'sua_dashboard_widget_content'
        );
    }
}

function sua_dashboard_widget_content() {
    $users = get_users(array('fields' => 'ID'));
    $admin_count = 0;
    
    foreach ($users as $user_id) {
        $user = get_userdata($user_id);
        if (in_array('administrator', $user->roles)) {
            $admin_count++;
        }
    }
    
    echo '<p>Total Users: ' . count($users) . '</p>';
    echo '<p>Administrators: ' . $admin_count . '</p>';
    echo '<p><a href="' . admin_url('admin.php?page=security-user-auditor') . '" class="button button-primary">View All Users</a></p>';
    
    // Quick scan for suspicious users
    echo '<hr><h4>Quick Check:</h4>';
    
    $suspicious = array();
    foreach (get_users() as $user) {
        if (strpos(strtolower($user->user_login), 'backup') !== false ||
            strpos(strtolower($user->user_login), 'hidden') !== false ||
            strpos(strtolower($user->user_email), 'example.com') !== false) {
            $suspicious[] = $user->user_login;
        }
    }
    
    if (!empty($suspicious)) {
        echo '<div class="notice notice-warning inline"><p>Suspicious users found: ' . implode(', ', $suspicious) . '</p></div>';
    } else {
        echo '<p>No obviously suspicious users found.</p>';
    }
}
?>