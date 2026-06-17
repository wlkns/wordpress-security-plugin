<?php

/**
 * Disable password resets.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Prevents password resets and hides/blocks the lost-password flow.
 */
class Disable_Password_Reset extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_filter('allow_password_reset', '__return_false');
        add_filter('lostpassword_url', '__return_empty_string');
        add_action('login_form_lostpassword', [$this, 'block_endpoint']);
        add_action('login_form_retrievepassword', [$this, 'block_endpoint']);
        add_action('login_head', [$this, 'hide_lost_password_link']);
    }

    /**
     * Hide the "Lost your password?" link on the login page.
     *
     * wp-login.php hardcodes that anchor in #nav with no filter to remove it,
     * so hide it with CSS. When registration is off, #nav holds only that link
     * and can be hidden wholesale; otherwise target the anchor whose href our
     * lostpassword_url filter has already emptied, leaving "Register" intact.
     */
    public function hide_lost_password_link()
    {
        $selector = get_option('users_can_register') ? '#nav a[href=""]' : '#nav';
        printf('<style id="wlkns-wws-hide-lostpw">%s{display:none}</style>', $selector); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- fixed literal selector.
    }

    /**
     * Redirect the lost-password endpoints back to the login form.
     */
    public function block_endpoint()
    {
        wp_safe_redirect(wp_login_url());
        exit;
    }
}
