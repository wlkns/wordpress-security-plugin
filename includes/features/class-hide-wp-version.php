<?php

/**
 * Hide the WordPress version.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Removes the generator tag and strips core version query strings from assets.
 */
class Hide_Wp_Version extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        remove_action('wp_head', 'wp_generator');
        add_filter('the_generator', '__return_empty_string');
        add_filter('style_loader_src', [$this, 'strip_version'], 10, 1);
        add_filter('script_loader_src', [$this, 'strip_version'], 10, 1);
    }

    /**
     * Remove the ?ver= query arg when it matches the core WordPress version.
     *
     * @param  string  $src  Asset URL.
     * @return string
     */
    public function strip_version($src)
    {
        global $wp_version;

        if ($src && strpos($src, 'ver='.$wp_version) !== false) {
            $src = remove_query_arg('ver', $src);
        }

        return $src;
    }
}
