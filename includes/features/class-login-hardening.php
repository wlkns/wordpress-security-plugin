<?php

/**
 * Login hardening: generic errors + user-enumeration blocking.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Hides which credential was wrong and blocks author/REST user enumeration.
 */
class Login_Hardening extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_filter('login_errors', [$this, 'generic_error']);
        add_action('template_redirect', [$this, 'block_author_enum']);
        add_filter('rest_endpoints', [$this, 'block_rest_user_routes']);
    }

    /**
     * Replace login errors with a single generic message.
     *
     * @return string
     */
    public function generic_error()
    {
        return __('<strong>Error:</strong> Invalid login details.', 'wlkns-security');
    }

    /**
     * Block ?author=N enumeration for logged-out visitors.
     */
    public function block_author_enum()
    {
        if (is_user_logged_in() || is_admin()) {
            return;
        }

        $author = get_query_var('author');
        $raw = isset($_GET['author']) ? sanitize_text_field(wp_unslash($_GET['author'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only enumeration guard.

        if (! empty($author) || is_author() || is_numeric($raw)) {
            wp_safe_redirect(home_url('/'), 301);
            exit;
        }
    }

    /**
     * Strip the REST user routes for logged-out visitors.
     *
     * @param  array  $endpoints  Registered endpoints.
     * @return array
     */
    public function block_rest_user_routes($endpoints)
    {
        if (is_user_logged_in()) {
            return $endpoints;
        }

        foreach (['/wp/v2/users', '/wp/v2/users/(?P<id>[\d]+)'] as $route) {
            if (isset($endpoints[$route])) {
                unset($endpoints[$route]);
            }
        }

        return $endpoints;
    }
}
