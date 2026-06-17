<?php

/**
 * Activation / upgrade routines.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Handles creating the blocklist table and seeding default options.
 */
class Activator
{
    /**
     * Fully-qualified blocked-IPs table name.
     *
     * @return string
     */
    public static function table_name()
    {
        global $wpdb;

        return $wpdb->prefix.'wlkns_wws_blocked_ips';
    }

    /**
     * Default plugin settings. All hardening features default to on.
     *
     * @return array
     */
    public static function default_settings()
    {
        return [
            // Plugins & themes.
            'disable_plugin_install' => true,
            'disable_theme_install' => true,
            // Content & auth.
            'disable_comments' => true,
            'disable_password_reset' => true,
            // API & exposure.
            'disable_rest_api' => true,
            'disable_xmlrpc' => true,
            'disable_application_passwords' => true,
            'disable_file_editing' => true,
            'hide_wp_version' => true,
            // Login protection.
            'login_hardening' => true,
            'login_limiter' => true,
            'login_threshold' => 5,
            'login_window_minutes' => 15,
            'login_block_minutes' => 60,
            // Login emails (opt-in; off by default — silent until a recipient is picked).
            'login_emails' => false,
            'login_emails_recipient' => 0,
            // Honeypot (trap paths are loaded from honeypot.txt).
            'honeypot' => true,
            'honeypot_threshold' => 3,
            'honeypot_window_minutes' => 15,
            'honeypot_block_minutes' => 60,
            // Head cleanup.
            'head_disable_emojis' => true,
            'head_remove_feed_links' => true,
            'head_remove_oembed' => true,
            'head_remove_rel_links' => true,
            'head_remove_wlwmanifest' => true,
            'head_remove_rest_link' => true,
            'head_remove_resource_hints' => true,
        ];
    }

    /**
     * Run on plugin activation.
     */
    public static function activate()
    {
        self::create_table();

        if (get_option(WLKNS_WWS_OPTION, false) === false) {
            add_option(WLKNS_WWS_OPTION, self::default_settings());
        }

        update_option(WLKNS_WWS_DB_OPTION, WLKNS_WWS_DB_VERSION);
    }

    /**
     * Run on every load; applies schema upgrades when the stored version lags.
     */
    public static function maybe_upgrade()
    {
        if (get_option(WLKNS_WWS_DB_OPTION) === WLKNS_WWS_DB_VERSION) {
            return;
        }

        self::create_table();
        update_option(WLKNS_WWS_DB_OPTION, WLKNS_WWS_DB_VERSION);
    }

    /**
     * Create / update the blocked-IPs table via dbDelta.
     */
    private static function create_table()
    {
        global $wpdb;

        $table = self::table_name();
        $charset_collate = $wpdb->get_charset_collate();

        // dbDelta is picky: two spaces after PRIMARY KEY, lowercase types, no backticks needed.
        $sql = "CREATE TABLE {$table} (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			ip_address varchar(45) NOT NULL,
			reason varchar(191) NOT NULL DEFAULT '',
			context varchar(191) DEFAULT NULL,
			blocked_at datetime NOT NULL,
			expires_at datetime DEFAULT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY ip_address (ip_address),
			KEY expires_at (expires_at)
		) {$charset_collate};";

        require_once ABSPATH.'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }
}
