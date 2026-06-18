<?php

/**
 * Block the REST API for unauthenticated requests.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Returns 401 for logged-out REST requests; logged-in users are unaffected.
 *
 * Routes listed in the "REST API whitelist" setting are exempt from the 401.
 * Matching is case-insensitive against the resolved REST route (without the
 * /wp-json prefix): without a wildcard it is a prefix match (so /wp/v2/posts
 * also covers /wp/v2/posts/123); patterns containing * use glob-style matching.
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

        // Logged-in users (and the block editor) are unaffected.
        if (is_user_logged_in()) {
            return $result;
        }

        // Whitelisted endpoints are exempt from the block.
        if ($this->is_whitelisted($this->current_route())) {
            return $result;
        }

        return new \WP_Error(
            'wlkns_wws_rest_disabled',
            __('The REST API is restricted to authenticated users.', 'wlkns-security'),
            ['status' => 401]
        );
    }

    /**
     * The REST route being requested, lower-cased and without the /wp-json prefix.
     *
     * @return string
     */
    private function current_route()
    {
        $route = '';

        if (isset($GLOBALS['wp']->query_vars['rest_route'])) {
            $route = (string) $GLOBALS['wp']->query_vars['rest_route'];
        }

        // Fallback: derive from the request URI and strip the REST prefix.
        if ($route === '') {
            $uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
            $path = (string) wp_parse_url($uri, PHP_URL_PATH);
            $prefix = '/'.trim(rest_get_url_prefix(), '/');

            if (strpos($path, $prefix.'/') === 0) {
                $path = substr($path, strlen($prefix));
            } elseif ($path === $prefix) {
                $path = '/';
            }

            $route = $path;
        }

        $route = strtolower($route);

        if ($route === '' || $route[0] !== '/') {
            $route = '/'.$route;
        }

        return $route;
    }

    /**
     * Does the requested route match any whitelist pattern?
     *
     * @param  string  $route  Lower-cased REST route.
     * @return bool
     */
    private function is_whitelisted($route)
    {
        foreach ($this->whitelist_patterns() as $pattern) {
            if ($this->path_matches($route, $pattern)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Parse the whitelist setting into a normalised pattern list (cached).
     *
     * Accepts entries with or without the /wp-json prefix; trims, lower-cases,
     * skips blank and # comment lines, and ensures a leading slash.
     *
     * @return string[]
     */
    private function whitelist_patterns()
    {
        static $patterns = null;

        if ($patterns !== null) {
            return $patterns;
        }

        $patterns = [];
        $prefix = '/'.trim(rest_get_url_prefix(), '/');

        foreach (preg_split('/\R/', $this->settings->get_string('rest_api_whitelist')) as $line) {
            $line = strtolower(trim((string) $line));

            if ($line === '' || $line[0] === '#') {
                continue;
            }

            if ($line[0] !== '/') {
                $line = '/'.$line;
            }

            // Strip an optional leading /wp-json prefix so entries compare to the route.
            if (strpos($line, $prefix.'/') === 0) {
                $line = substr($line, strlen($prefix));
            } elseif ($line === $prefix) {
                $line = '/';
            }

            $patterns[] = $line;
        }

        return $patterns;
    }

    /**
     * Match a route against a single whitelist pattern.
     *
     * Without a wildcard this is a prefix match; with * it is glob-style from
     * the start of the route (* matches any characters).
     *
     * @param  string  $route  Lower-cased REST route.
     * @param  string  $pattern  Lower-cased whitelist pattern.
     * @return bool
     */
    private function path_matches($route, $pattern)
    {
        if (strpos($pattern, '*') === false) {
            return strpos($route, $pattern) === 0;
        }

        $regex = '#^'.implode('.*', array_map(
            static function ($part) {
                return preg_quote($part, '#');
            },
            explode('*', $pattern)
        )).'#';

        return preg_match($regex, $route) === 1;
    }
}
