<?php

/**
 * Honeypot trap paths.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Counts requests from logged-out visitors to trap paths listed in honeypot.txt
 * and blocks the IP once the configured threshold is reached within the window.
 *
 * Without a wildcard, matching is a case-insensitive prefix match, so a trap
 * like "/.env" also covers "/.env.testing". Patterns containing * use glob-style
 * matching from the start of the path (* matches any characters).
 *
 * Caveat: only requests that reach PHP/WordPress can be trapped. Files that
 * exist and are served directly by the web server (or blocked at that layer)
 * never hit this code.
 */
class Honeypot extends Feature
{
    /**
     * Trap-path list file (one path per line).
     *
     * @return string
     */
    public static function trap_paths_file()
    {
        return WLKNS_WWS_DIR.'honeypot.txt';
    }

    /**
     * Trap paths from honeypot.txt (lower-case). Falls back to built-in defaults
     * when the file is missing or empty.
     *
     * @return string[]
     */
    public static function trap_paths()
    {
        static $paths = null;

        if ($paths !== null) {
            return $paths;
        }

        $paths = self::parse_trap_paths_file(self::trap_paths_file());

        if (empty($paths)) {
            $paths = self::default_trap_paths();
        }

        return $paths;
    }

    /**
     * Built-in defaults used when honeypot.txt is missing or empty.
     *
     * @return string[]
     */
    private static function default_trap_paths()
    {
        return [
            '/.env',
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config.php.save',
            '/wp-config.php~',
            '/wp-config.php.old',
            '/wp-content/plugins/wp-file-manager/readme.txt',
            '/.git',
            '/wp-admin/install.php',
            '/wp-admin/setup-config.php',
            '/vendor/phpunit/phpunit/src/util/php/eval-stdin.php',
            '/.aws/credentials',
            '/.ssh/id_rsa',
            '/phpinfo.php',
            '/info.php',
        ];
    }

    /**
     * Parse a trap-path file into a normalised path list.
     *
     * @param  string  $file  Absolute path to the file.
     * @return string[]
     */
    private static function parse_trap_paths_file($file)
    {
        if (! is_readable($file)) {
            return [];
        }

        $lines = file($file, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            return [];
        }

        $paths = [];

        foreach ($lines as $line) {
            $line = trim((string) $line);

            if ($line === '' || $line[0] === '#') {
                continue;
            }

            $paths[] = strtolower($line);
        }

        return $paths;
    }

    /**
     * Register hooks.
     */
    public function register()
    {
        // Early, but after the user is known so we never trap a logged-in admin.
        add_action('init', [$this, 'maybe_trap'], 1);
    }

    /**
     * Record an offence (and possibly block) if the request path matches a trap.
     */
    public function maybe_trap()
    {
        if (is_user_logged_in()) {
            return;
        }

        $request = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
        $path = strtolower((string) wp_parse_url($request, PHP_URL_PATH));

        if ($path === '' || ! $this->matches_trap($path)) {
            return;
        }

        $blocked = Blocklist::record_offense(
            Blocklist::client_ip(),
            'honeypot',
            $this->settings->get_int('honeypot_threshold'),
            $this->settings->get_int('honeypot_window_minutes'),
            $this->settings->get_int('honeypot_block_minutes'),
            __('honeypot request', 'wlkns-security')
        );

        // Below the threshold: stay silent and let WordPress serve a normal 404.
        if (! $blocked) {
            return;
        }

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

    /**
     * Does the request path match any trap path?
     *
     * @param  string  $path  Lower-cased request path.
     * @return bool
     */
    private function matches_trap($path)
    {
        foreach (self::trap_paths() as $trap) {
            if (self::path_matches_trap($path, $trap)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Match a request path against a single trap pattern.
     *
     * @param  string  $path  Lower-cased request path.
     * @param  string  $trap  Lower-cased trap pattern.
     * @return bool
     */
    private static function path_matches_trap($path, $trap)
    {
        if (strpos($trap, '*') === false) {
            return strpos($path, $trap) === 0;
        }

        $regex = '#^'.implode('.*', array_map(
            static function ($part) {
                return preg_quote($part, '#');
            },
            explode('*', $trap)
        )).'#';

        return preg_match($regex, $path) === 1;
    }
}
