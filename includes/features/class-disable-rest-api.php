<?php

/**
 * Block the REST API for unauthenticated requests.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Returns 401 for logged-out REST requests; logged-in users are unaffected.
 */
class Disable_Rest_Api extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_filter('rest_authentication_errors', [$this, 'require_auth']);
    }

    /**
     * Require authentication for any REST request.
     *
     * @param  \WP_Error|true|null  $result  Current auth result.
     * @return \WP_Error|true|null
     */
    public function require_auth($result)
    {
        // Respect an error another handler has already set.
        if (is_wp_error($result)) {
            return $result;
        }

        if (! is_user_logged_in()) {
            return new \WP_Error(
                'wlkns_wws_rest_disabled',
                __('The REST API is restricted to authenticated users.', 'wlkns-security'),
                ['status' => 401]
            );
        }

        return $result;
    }
}
