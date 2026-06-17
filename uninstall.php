<?php

/**
 * Uninstall cleanup: drop the blocklist table and delete options.
 */
defined('WP_UNINSTALL_PLUGIN') || exit;

global $wpdb;

$table = $wpdb->prefix.'wlkns_wws_blocked_ips';
// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery -- one-off uninstall cleanup.
$wpdb->query("DROP TABLE IF EXISTS {$table}");

delete_option('wlkns_wws_settings');
delete_option('wlkns_wws_db_version');
