<?php

/**
 * Disable application passwords.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Turns off WordPress application passwords (REST/API auth tokens).
 */
class Disable_Application_Passwords extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_filter('wp_is_application_passwords_available', '__return_false');
    }
}
