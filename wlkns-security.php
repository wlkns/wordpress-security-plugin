<?php

use WLKNS\Security\Plugin;

/**
 * Plugin Name:       WLKNS Security
 * Plugin URI:        https://wlkns.co
 * Description:        Lightweight WordPress hardening plugin — blocks brute-force logins with IP banning, traps bots with honeypots, and disables risky features. All toggleable, zero phone-home. Configure everything under the Security menu.
 * Version:           1.0.2
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            WLKNS LTD
 * Author URI:        https://wlkns.co
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       wlkns-security
 */
defined('ABSPATH') || exit;

define('WLKNS_WWS_VERSION', '1.0.2');
define('WLKNS_WWS_DB_VERSION', '2');
define('WLKNS_WWS_FILE', __FILE__);
define('WLKNS_WWS_DIR', plugin_dir_path(__FILE__));
define('WLKNS_WWS_URL', plugin_dir_url(__FILE__));
define('WLKNS_WWS_OPTION', 'wlkns_wws_settings');
define('WLKNS_WWS_DB_OPTION', 'wlkns_wws_db_version');

require_once WLKNS_WWS_DIR.'includes/class-activator.php';
require_once WLKNS_WWS_DIR.'includes/class-plugin.php';

register_activation_hook(__FILE__, ['\WLKNS\Security\Activator', 'activate']);

Plugin::instance()->init();
