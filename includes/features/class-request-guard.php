<?php

/**
 * Request-time enforcement of the IP blocklist.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Denies any request from a currently-blocked IP, as early as practical.
 */
class Request_Guard extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        // Run early, before features and routing, but after WP core is loaded.
        add_action('plugins_loaded', [$this, 'guard'], 1);
    }

    /**
     * Block the request if the client IP is on the blocklist.
     */
    public function guard()
    {
        $ip = Blocklist::client_ip();

        if ($ip === '' || ! Blocklist::is_blocked($ip)) {
            return;
        }

        $this->deny();
    }

    /**
     * Emit a 403 and stop.
     */
    private function deny()
    {
        if (! headers_sent()) {
            status_header(403);
            nocache_headers();
        }

        wp_die(
            esc_html__('Access denied.', 'wlkns-security'),
            esc_html__('Forbidden', 'wlkns-security'),
            ['response' => 403]
        );
    }
}
