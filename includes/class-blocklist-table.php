<?php

/**
 * Blocked-IPs list table.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

if (! class_exists('\WP_List_Table')) {
    require_once ABSPATH.'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Lists blocked IPs with a per-row Unblock action.
 */
class Blocklist_Table extends \WP_List_Table
{
    const PER_PAGE = 50;

    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct(
            [
                'singular' => 'blocked_ip',
                'plural' => 'blocked_ips',
                'ajax' => false,
            ]
        );
    }

    /**
     * Column definitions.
     *
     * @return array
     */
    public function get_columns()
    {
        return [
            'ip_address' => __('IP address', 'wlkns-security'),
            'reason' => __('Reason', 'wlkns-security'),
            'blocked_at' => __('Blocked at (UTC)', 'wlkns-security'),
            'expires_at' => __('Expires (UTC)', 'wlkns-security'),
        ];
    }

    /**
     * Prepare rows.
     */
    public function prepare_items()
    {
        $this->_column_headers = [$this->get_columns(), [], []];

        $total = Blocklist::count();
        $current = $this->get_pagenum();
        $offset = ($current - 1) * self::PER_PAGE;
        $this->items = Blocklist::all(
            [
                'per_page' => self::PER_PAGE,
                'offset' => $offset,
            ]
        );

        $this->set_pagination_args(
            [
                'total_items' => $total,
                'per_page' => self::PER_PAGE,
            ]
        );
    }

    /**
     * Default column rendering.
     *
     * @param  array  $item  Row.
     * @param  string  $column_name  Column.
     * @return string
     */
    public function column_default($item, $column_name)
    {
        $value = isset($item[$column_name]) ? $item[$column_name] : '';

        if ($column_name === 'expires_at' && empty($value)) {
            return '<em>'.esc_html__('Permanent', 'wlkns-security').'</em>';
        }

        return esc_html((string) $value);
    }

    /**
     * IP column with the Unblock row action.
     *
     * @param  array  $item  Row.
     * @return string
     */
    public function column_ip_address($item)
    {
        $ip = $item['ip_address'];
        $url = wp_nonce_url(
            add_query_arg(
                [
                    'action' => 'wlkns_wws_unblock',
                    'ip' => rawurlencode($ip),
                ],
                admin_url('admin-post.php')
            ),
            'wlkns_wws_unblock_'.$ip
        );

        $actions = [
            'unblock' => sprintf(
                '<a href="%s" onclick="return confirm(\'%s\');">%s</a>',
                esc_url($url),
                esc_js(__('Unblock this IP?', 'wlkns-security')),
                esc_html__('Unblock', 'wlkns-security')
            ),
        ];

        return sprintf('<strong>%s</strong> %s', esc_html($ip), $this->row_actions($actions));
    }

    /**
     * Empty-state message.
     */
    public function no_items()
    {
        esc_html_e('No IPs are currently blocked.', 'wlkns-security');
    }
}
