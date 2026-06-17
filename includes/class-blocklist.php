<?php

/**
 * Blocked-IP data layer.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Read/write access to the blocked-IPs table plus the shared client-IP helper.
 */
class Blocklist
{
    /**
     * Fully-qualified table name.
     *
     * @return string
     */
    public static function table()
    {
        return Activator::table_name();
    }

    /**
     * Best-effort client IP.
     *
     * We deliberately trust only REMOTE_ADDR. Forwarded headers
     * (X-Forwarded-For, etc.) are trivially spoofable, so a site behind a
     * reverse proxy / CDN must adapt this. Returns '' when unavailable.
     *
     * @return string
     */
    public static function client_ip()
    {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? wp_unslash($_SERVER['REMOTE_ADDR']) : '';
        $ip = filter_var($ip, FILTER_VALIDATE_IP);

        return $ip ? $ip : '';
    }

    /**
     * Is the given IP currently blocked (permanent, or not-yet-expired)?
     *
     * @param  string  $ip  IP address.
     * @return bool
     */
    public static function is_blocked($ip)
    {
        global $wpdb;

        if ($ip === '') {
            return false;
        }

        $table = self::table();
        $now = current_time('mysql', true);

        $found = $wpdb->get_var(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is internal.
                "SELECT id FROM {$table} WHERE ip_address = %s AND ( expires_at IS NULL OR expires_at > %s ) LIMIT 1",
                $ip,
                $now
            )
        );

        return $found !== null;
    }

    /**
     * Block an IP. Upserts on the unique ip_address index so re-blocking
     * refreshes the reason / expiry rather than failing.
     *
     * @param  string  $ip  IP address.
     * @param  string  $reason  Human-readable reason (e.g. "5 failed logins").
     * @param  string  $type  Machine category: login | honeypot | manual.
     * @param  string|null  $expires  UTC 'Y-m-d H:i:s' expiry, or null for permanent.
     * @return bool
     */
    public static function block($ip, $reason, $type = 'manual', $expires = null)
    {
        global $wpdb;

        $ip = filter_var($ip, FILTER_VALIDATE_IP);
        if (! $ip) {
            return false;
        }

        $table = self::table();
        $now = current_time('mysql', true);
        $reason = substr((string) $reason, 0, 191);
        $type = in_array($type, ['login', 'honeypot', 'manual'], true) ? $type : 'manual';

        // $wpdb->prepare() casts a null %s argument to an empty string, which is
        // an invalid datetime under MySQL strict mode and silently fails the
        // insert. Emit a literal NULL for permanent (no-expiry) blocks instead.
        $expires_placeholder = $expires === null ? 'NULL' : '%s';
        $args = [$ip, $reason, $type, $now];

        if ($expires !== null) {
            $args[] = $expires;
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is internal; expires placeholder is a fixed literal.
        $sql = $wpdb->prepare(
            "INSERT INTO {$table} ( ip_address, reason, context, blocked_at, expires_at )
			 VALUES ( %s, %s, %s, %s, {$expires_placeholder} )
			 ON DUPLICATE KEY UPDATE reason = VALUES(reason), context = VALUES(context), blocked_at = VALUES(blocked_at), expires_at = VALUES(expires_at)",
            $args
        );

        return $wpdb->query($sql) !== false;
    }

    /**
     * Transient key for an IP's per-type offence counter.
     *
     * @param  string  $ip  IP address.
     * @param  string  $type  Offence type.
     * @return string
     */
    private static function offense_key($ip, $type)
    {
        return 'wlkns_wws_offense_'.$type.'_'.md5($ip);
    }

    /**
     * Record an offence for an IP and block it once the threshold is reached
     * within the rolling window.
     *
     * The counter lives in a transient (window = its TTL); only the resulting
     * timed block is persisted to the table.
     *
     * @param  string  $ip  IP address.
     * @param  string  $type  Machine category (login | honeypot | manual).
     * @param  int  $threshold  Occurrences that trigger a block.
     * @param  int  $window_minutes  Window in which occurrences are counted.
     * @param  int  $block_minutes  How long the resulting block lasts.
     * @param  string  $noun  Singular noun for the reason (e.g. "failed login").
     * @return bool True if this offence triggered a block.
     */
    public static function record_offense($ip, $type, $threshold, $window_minutes, $block_minutes, $noun)
    {
        if ($ip === '') {
            return false;
        }

        $threshold = max(1, (int) $threshold);
        $window_minutes = max(1, (int) $window_minutes);
        $block_minutes = max(1, (int) $block_minutes);

        $key = self::offense_key($ip, $type);
        $count = (int) get_transient($key) + 1;

        if ($count >= $threshold) {
            /* translators: 1: number of occurrences, 2: offence noun (e.g. "failed login"). */
            $reason = sprintf(_n('%1$d %2$s', '%1$d %2$ss', $count, 'wlkns-security'), $count, $noun);
            $expires = gmdate('Y-m-d H:i:s', time() + ($block_minutes * MINUTE_IN_SECONDS));

            self::block($ip, $reason, $type, $expires);
            delete_transient($key);

            return true;
        }

        set_transient($key, $count, $window_minutes * MINUTE_IN_SECONDS);

        return false;
    }

    /**
     * Clear an IP's offence counter for a given type (e.g. after success).
     *
     * @param  string  $ip  IP address.
     * @param  string  $type  Offence type.
     * @return void
     */
    public static function clear_offense($ip, $type)
    {
        if ($ip !== '') {
            delete_transient(self::offense_key($ip, $type));
        }
    }

    /**
     * Remove a block by IP.
     *
     * @param  string  $ip  IP address.
     * @return bool
     */
    public static function unblock($ip)
    {
        global $wpdb;

        return $wpdb->delete(self::table(), ['ip_address' => $ip], ['%s']) !== false;
    }

    /**
     * Fetch rows for the admin table.
     *
     * @param  array  $args  { per_page, offset }.
     * @return array[] Array of row objects as associative arrays.
     */
    public static function all($args = [])
    {
        global $wpdb;

        $per_page = isset($args['per_page']) ? max(1, (int) $args['per_page']) : 50;
        $offset = isset($args['offset']) ? max(0, (int) $args['offset']) : 0;
        $table = self::table();

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is internal.
        return $wpdb->get_results(
            $wpdb->prepare(
                "SELECT * FROM {$table} ORDER BY blocked_at DESC LIMIT %d OFFSET %d",
                $per_page,
                $offset
            ),
            ARRAY_A
        );
    }

    /**
     * Total number of blocked rows.
     *
     * @return int
     */
    public static function count()
    {
        global $wpdb;

        $table = self::table();

        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is internal.
        return (int) $wpdb->get_var("SELECT COUNT(*) FROM {$table}");
    }

    /**
     * Delete expired (lapsed) blocks.
     *
     * @return void
     */
    public static function purge_expired()
    {
        global $wpdb;

        $table = self::table();
        $now = current_time('mysql', true);

        $wpdb->query(
            $wpdb->prepare(
                // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name is internal.
                "DELETE FROM {$table} WHERE expires_at IS NOT NULL AND expires_at <= %s",
                $now
            )
        );
    }
}
