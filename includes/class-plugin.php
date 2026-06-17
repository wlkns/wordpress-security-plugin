<?php

/**
 * Plugin loader.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Wires the plugin together: loads dependencies and boots enabled features.
 */
final class Plugin
{
    /**
     * Singleton instance.
     *
     * @var Plugin|null
     */
    private static $instance = null;

    /**
     * Resolved settings.
     *
     * @var Settings
     */
    private $settings;

    /**
     * Get the shared instance.
     *
     * @return Plugin
     */
    public static function instance()
    {
        if (self::$instance === null) {
            self::$instance = new self;
        }

        return self::$instance;
    }

    /**
     * Constructor — load dependencies.
     */
    private function __construct()
    {
        $this->require_files();
        $this->settings = new Settings;
    }

    /**
     * Require every class file. Kept explicit (no autoloader) for clarity.
     */
    private function require_files()
    {
        $includes = WLKNS_WWS_DIR.'includes/';

        require_once $includes.'class-blocklist.php';
        require_once $includes.'class-settings.php';
        require_once $includes.'class-admin.php';
        require_once $includes.'class-blocklist-table.php';

        $features = $includes.'features/';

        require_once $features.'class-feature.php';
        require_once $features.'class-request-guard.php';
        require_once $features.'class-honeypot.php';
        require_once $features.'class-login-limiter.php';
        require_once $features.'class-login-hardening.php';
        require_once $features.'class-disable-plugin-install.php';
        require_once $features.'class-disable-theme-install.php';
        require_once $features.'class-disable-comments.php';
        require_once $features.'class-disable-password-reset.php';
        require_once $features.'class-disable-rest-api.php';
        require_once $features.'class-disable-xmlrpc.php';
        require_once $features.'class-disable-application-passwords.php';
        require_once $features.'class-disable-file-editing.php';
        require_once $features.'class-hide-wp-version.php';
        require_once $features.'class-head-cleanup.php';
        require_once $features.'class-login-emails.php';
    }

    /**
     * Register hooks and boot features.
     */
    public function init()
    {
        add_action('plugins_loaded', [Activator::class, 'maybe_upgrade']);
        add_action('init', [$this, 'load_textdomain']);

        // Admin UI is always available so the site owner can manage settings & blocks.
        if (is_admin()) {
            (new Admin($this->settings))->register();
        }

        $this->boot_features();
    }

    /**
     * Load the plugin text domain.
     */
    public function load_textdomain()
    {
        load_plugin_textdomain('wlkns-security', false, dirname(plugin_basename(WLKNS_WWS_FILE)).'/languages');
    }

    /**
     * Instantiate features whose toggle is enabled.
     */
    private function boot_features()
    {
        $s = $this->settings;

        // Request guard runs whenever there could be blocked IPs (limiter or honeypot on).
        if ($s->is_enabled('login_limiter') || $s->is_enabled('honeypot')) {
            (new Request_Guard($s))->register();
        }

        $map = [
            'honeypot' => Honeypot::class,
            'login_limiter' => Login_Limiter::class,
            'login_hardening' => Login_Hardening::class,
            'login_emails' => Login_Emails::class,
            'disable_plugin_install' => Disable_Plugin_Install::class,
            'disable_theme_install' => Disable_Theme_Install::class,
            'disable_comments' => Disable_Comments::class,
            'disable_password_reset' => Disable_Password_Reset::class,
            'disable_rest_api' => Disable_Rest_Api::class,
            'disable_xmlrpc' => Disable_Xmlrpc::class,
            'disable_application_passwords' => Disable_Application_Passwords::class,
            'disable_file_editing' => Disable_File_Editing::class,
            'hide_wp_version' => Hide_Wp_Version::class,
        ];

        foreach ($map as $key => $class) {
            if ($s->is_enabled($key)) {
                (new $class($s))->register();
            }
        }

        // Head cleanup gates each removal internally, so boot it once if any
        // of its toggles are on.
        $head_keys = [
            'head_disable_emojis',
            'head_remove_feed_links',
            'head_remove_oembed',
            'head_remove_rel_links',
            'head_remove_wlwmanifest',
            'head_remove_rest_link',
            'head_remove_resource_hints',
        ];

        foreach ($head_keys as $key) {
            if ($s->is_enabled($key)) {
                (new Head_Cleanup($s))->register();
                break;
            }
        }
    }

    /**
     * Expose settings to other components.
     *
     * @return Settings
     */
    public function settings()
    {
        return $this->settings;
    }
}
