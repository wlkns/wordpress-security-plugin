<?php

/**
 * Login attempt limiter.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Tracks failed logins per IP and writes a timed block once the threshold is hit.
 *
 * The per-IP attempt counter lives in a transient (ephemeral); only the actual
 * block is persisted to the blocklist table.
 */
class Login_Limiter extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_action('wp_login_failed', [$this, 'record_failure']);
        add_filter('authenticate', [$this, 'check_blocked'], 30);
        add_action('wp_login', [$this, 'clear_attempts']);
    }

    /**
     * Increment the failure counter; block the IP when it reaches the threshold.
     */
    public function record_failure()
    {
        Blocklist::record_offense(
            Blocklist::client_ip(),
            'login',
            $this->settings->get_int('login_threshold'),
            $this->settings->get_int('login_window_minutes'),
            $this->settings->get_int('login_block_minutes'),
            __('failed login', 'wlkns-security')
        );
    }

    /**
     * Reject authentication outright for a blocked IP.
     *
     * @param  \WP_User|\WP_Error|null  $user  Auth result so far.
     * @return \WP_User|\WP_Error|null
     */
    public function check_blocked($user)
    {
        $ip = Blocklist::client_ip();

        if ($ip !== '' && Blocklist::is_blocked($ip)) {
            return new \WP_Error(
                'wlkns_wws_too_many_attempts',
                __('<strong>Error:</strong> Too many failed login attempts. Try again later.', 'wlkns-security')
            );
        }

        return $user;
    }

    /**
     * Clear the attempt counter on a successful login.
     */
    public function clear_attempts()
    {
        Blocklist::clear_offense(Blocklist::client_ip(), 'login');
    }
}
