<?php

/**
 * Disable XML-RPC.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Turns off XML-RPC, pingbacks and the related discovery headers.
 */
class Disable_Xmlrpc extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_filter('xmlrpc_enabled', '__return_false');
        add_filter('xmlrpc_methods', '__return_empty_array');
        add_filter('wp_headers', [$this, 'remove_pingback_header']);
        add_filter('pings_open', '__return_false', 20);

        // Remove the RSD link (used for XML-RPC discovery).
        remove_action('wp_head', 'rsd_link');
    }

    /**
     * Strip the X-Pingback response header.
     *
     * @param  array  $headers  Headers.
     * @return array
     */
    public function remove_pingback_header($headers)
    {
        if (isset($headers['X-Pingback'])) {
            unset($headers['X-Pingback']);
        }

        return $headers;
    }
}
