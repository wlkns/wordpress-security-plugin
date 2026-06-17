<?php

/**
 * Settings storage + Settings API registration.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Reads the single option array and renders/sanitises the settings form.
 */
class Settings
{
    const GROUP = 'wlkns_wws';

    const PAGE = 'wlkns-security';

    /**
     * Resolved settings (defaults merged with stored values).
     *
     * @var array
     */
    private $values;

    /**
     * Constructor.
     */
    public function __construct()
    {
        $stored = get_option(WLKNS_WWS_OPTION, []);
        $this->values = wp_parse_args(is_array($stored) ? $stored : [], Activator::default_settings());
    }

    /**
     * All resolved values.
     *
     * @return array
     */
    public function all()
    {
        return $this->values;
    }

    /**
     * Is a boolean toggle enabled?
     *
     * @param  string  $key  Setting key.
     * @return bool
     */
    public function is_enabled($key)
    {
        return ! empty($this->values[$key]);
    }

    /**
     * Integer setting.
     *
     * @param  string  $key  Setting key.
     * @return int
     */
    public function get_int($key)
    {
        return isset($this->values[$key]) ? (int) $this->values[$key] : 0;
    }

    /**
     * Raw string setting.
     *
     * @param  string  $key  Setting key.
     * @return string
     */
    public function get_string($key)
    {
        return isset($this->values[$key]) ? (string) $this->values[$key] : '';
    }

    /**
     * Register the option, sections and fields with the Settings API.
     */
    public function register()
    {
        register_setting(
            self::GROUP,
            WLKNS_WWS_OPTION,
            [
                'type' => 'array',
                'sanitize_callback' => [$this, 'sanitize'],
                'default' => Activator::default_settings(),
            ]
        );

        $sections = [
            'plugins_themes' => __('Plugins & Themes', 'wlkns-security'),
            'content_auth' => __('Content & Authentication', 'wlkns-security'),
            'api_exposure' => __('API & Exposure', 'wlkns-security'),
            'login' => __('Login Protection', 'wlkns-security'),
            'login_emails' => __('Login Emails', 'wlkns-security'),
            'honeypot' => __('Honeypot', 'wlkns-security'),
            'head_cleanup' => __('Head Cleanup', 'wlkns-security'),
        ];

        foreach ($sections as $id => $title) {
            add_settings_section('wlkns_wws_'.$id, $title, '__return_false', self::PAGE);
        }

        $checkboxes = [
            'plugins_themes' => [
                'disable_plugin_install' => [__('Disable plugin installs', 'wlkns-security'), __('Hide and block the “Add New” plugin and upload screens. Existing plugins can still be activated.', 'wlkns-security')],
                'disable_theme_install' => [__('Disable theme installs', 'wlkns-security'), __('Hide and block adding/uploading new themes. Switching existing themes still works.', 'wlkns-security')],
            ],
            'content_auth' => [
                'disable_comments' => [__('Disable comments', 'wlkns-security'), __('Close comments site-wide, remove the Comments admin menu and the comment form.', 'wlkns-security')],
                'disable_password_reset' => [__('Disable password resets', 'wlkns-security'), __('Prevent users from resetting their password and hide the “Lost your password?” link.', 'wlkns-security')],
            ],
            'api_exposure' => [
                'disable_rest_api' => [__('Block unauthenticated REST API', 'wlkns-security'), __('Return 401 for logged-out REST requests. Logged-in users (and the block editor) are unaffected.', 'wlkns-security')],
                'disable_xmlrpc' => [__('Disable XML-RPC', 'wlkns-security'), __('Disable /xmlrpc.php and pingbacks — a common brute-force/DDoS amplification vector.', 'wlkns-security')],
                'disable_application_passwords' => [__('Disable application passwords', 'wlkns-security'), __('Turn off WordPress application passwords (API auth tokens).', 'wlkns-security')],
                'disable_file_editing' => [__('Disable file editing', 'wlkns-security'), __('Disable the built-in theme and plugin code editors (DISALLOW_FILE_EDIT).', 'wlkns-security')],
                'hide_wp_version' => [__('Hide WordPress version', 'wlkns-security'), __('Remove the generator meta tag and version query strings from assets.', 'wlkns-security')],
            ],
            'login' => [
                'login_hardening' => [__('Harden login & block user enumeration', 'wlkns-security'), __('Use a generic login error message and block ?author=N and REST user enumeration.', 'wlkns-security')],
                'login_limiter' => [__('Limit login attempts', 'wlkns-security'), __('Temporarily block an IP after too many failed logins.', 'wlkns-security')],
            ],
            'login_emails' => [
                'login_emails' => [__('Email on login', 'wlkns-security'), __('Send an email to the selected administrator whenever any user logs in.', 'wlkns-security')],
            ],
            'honeypot' => [
                'honeypot' => [__('Enable honeypot', 'wlkns-security'), __('Block an IP after repeated requests to the trap paths in honeypot.txt.', 'wlkns-security')],
            ],
            'head_cleanup' => [
                'head_disable_emojis' => [__('Disable emojis', 'wlkns-security'), __('Remove the emoji detection script and styles (front-end and admin) and the emoji DNS-prefetch. Browser-native emoji still render.', 'wlkns-security')],
                'head_remove_feed_links' => [__('Remove feed links', 'wlkns-security'), __('Remove the RSS/Atom feed <link> tags from the head. The feeds themselves still work if requested directly.', 'wlkns-security')],
                'head_remove_oembed' => [__('Remove oEmbed discovery', 'wlkns-security'), __('Remove the oEmbed discovery <link> tags and the host JS — stops other sites auto-embedding your posts.', 'wlkns-security')],
                'head_remove_rel_links' => [__('Remove rel & shortlink tags', 'wlkns-security'), __('Remove prev/next, index/parent/start rel links and the wp-shortlink <link> from the head.', 'wlkns-security')],
                'head_remove_wlwmanifest' => [__('Remove WLW manifest link', 'wlkns-security'), __('Remove the Windows Live Writer manifest <link> — only used by the long-defunct WLW desktop client.', 'wlkns-security')],
                'head_remove_rest_link' => [__('Remove REST API link', 'wlkns-security'), __('Remove the REST API discovery <link rel="https://api.w.org/"> from the head. Does not disable the REST API itself.', 'wlkns-security')],
                'head_remove_resource_hints' => [__('Remove resource hints', 'wlkns-security'), __('Remove the dns-prefetch / preconnect resource-hint <link> tags WordPress prints into the head.', 'wlkns-security')],
            ],
        ];

        foreach ($checkboxes as $section => $fields) {
            foreach ($fields as $key => $labels) {
                add_settings_field(
                    $key,
                    $labels[0],
                    [$this, 'render_checkbox'],
                    self::PAGE,
                    'wlkns_wws_'.$section,
                    [
                        'key' => $key,
                        'description' => $labels[1],
                        'label_for' => $key,
                    ]
                );
            }
        }

        // Numeric login-limiter fields (N failures within W minutes → block for B minutes).
        $this->add_throttle_fields(
            'wlkns_wws_login',
            'login',
            [
                'threshold' => __('Max failed attempts', 'wlkns-security'),
                'window' => __('Within (minutes)', 'wlkns-security'),
                'block' => __('Block for (minutes)', 'wlkns-security'),
            ]
        );

        // Numeric honeypot fields.
        $this->add_throttle_fields(
            'wlkns_wws_honeypot',
            'honeypot',
            [
                'threshold' => __('Max trap hits', 'wlkns-security'),
                'window' => __('Within (minutes)', 'wlkns-security'),
                'block' => __('Block for (minutes)', 'wlkns-security'),
            ]
        );

        // Recipient picker for the login-email notifications.
        add_settings_field(
            'login_emails_recipient',
            __('Notify', 'wlkns-security'),
            [$this, 'render_user_select'],
            self::PAGE,
            'wlkns_wws_login_emails',
            [
                'key' => 'login_emails_recipient',
                'label_for' => 'login_emails_recipient',
            ]
        );

        // Read-only display of trap paths loaded from honeypot.txt.
        add_settings_field(
            'honeypot_paths_display',
            __('Trap paths', 'wlkns-security'),
            [$this, 'render_trap_paths'],
            self::PAGE,
            'wlkns_wws_honeypot'
        );
    }

    /**
     * Register the three throttle number fields (threshold/window/block) for a feature.
     *
     * @param  string  $section  Settings section id.
     * @param  string  $prefix  Setting-key prefix (login | honeypot).
     * @param  array  $labels  Labels keyed by threshold|window|block.
     */
    private function add_throttle_fields($section, $prefix, $labels)
    {
        $fields = [
            'threshold' => [$prefix.'_threshold', 1, 1000],
            'window' => [$prefix.'_window_minutes', 1, 10080],
            'block' => [$prefix.'_block_minutes', 1, 10080],
        ];

        foreach ($fields as $part => $field) {
            [$key, $min, $max] = $field;
            add_settings_field(
                $key,
                $labels[$part],
                [$this, 'render_number'],
                self::PAGE,
                $section,
                [
                    'key' => $key,
                    'min' => $min,
                    'max' => $max,
                    'label_for' => $key,
                ]
            );
        }
    }

    /**
     * Render a checkbox field.
     *
     * @param  array  $args  Field args.
     */
    public function render_checkbox($args)
    {
        $key = $args['key'];
        printf(
            '<label><input type="checkbox" id="%1$s" name="%2$s[%1$s]" value="1" %3$s /> %4$s</label>',
            esc_attr($key),
            esc_attr(WLKNS_WWS_OPTION),
            checked($this->is_enabled($key), true, false),
            esc_html($args['description'])
        );
    }

    /**
     * Render a number field.
     *
     * @param  array  $args  Field args.
     */
    public function render_number($args)
    {
        $key = $args['key'];
        $desc = isset($args['description']) ? $args['description'] : '';
        printf(
            '<input type="number" id="%1$s" name="%2$s[%1$s]" value="%3$d" min="%4$d" max="%5$d" class="small-text" />%6$s',
            esc_attr($key),
            esc_attr(WLKNS_WWS_OPTION),
            esc_attr($this->get_int($key)),
            esc_attr($args['min']),
            esc_attr($args['max']),
            $desc === '' ? '' : ' <span class="description">'.esc_html($desc).'</span>'
        );
    }

    /**
     * Render a dropdown of administrators (the login-email recipient).
     *
     * @param  array  $args  Field args.
     */
    public function render_user_select($args)
    {
        $key = $args['key'];
        $selected = $this->get_int($key);
        $admins = get_users(
            [
                'role' => 'administrator',
                'orderby' => 'display_name',
                'fields' => ['ID', 'display_name', 'user_email'],
            ]
        );

        printf(
            '<select id="%1$s" name="%2$s[%1$s]">',
            esc_attr($key),
            esc_attr(WLKNS_WWS_OPTION)
        );

        printf(
            '<option value="0">%s</option>',
            esc_html__('— Select an administrator —', 'wlkns-security')
        );

        foreach ($admins as $admin) {
            printf(
                '<option value="%1$d" %2$s>%3$s</option>',
                (int) $admin->ID,
                selected($selected, (int) $admin->ID, false),
                esc_html(sprintf('%1$s (%2$s)', $admin->display_name, $admin->user_email))
            );
        }

        echo '</select>';
        printf(
            '<p class="description">%s</p>',
            esc_html__('The administrator who receives a notification each time someone logs in.', 'wlkns-security')
        );
    }

    /**
     * Render the trap-path list loaded from honeypot.txt.
     */
    public function render_trap_paths()
    {
        $paths = Honeypot::trap_paths();
        $rows = max(3, min(20, count($paths)));

        printf(
            '<textarea rows="%1$d" class="large-text code" readonly disabled>%2$s</textarea><p class="description">%3$s</p>',
            $rows,
            esc_textarea(implode("\n", $paths)),
            esc_html(sprintf(
                /* translators: %s: honeypot.txt filename */
                __('Loaded from %s (one path per line; # comments allowed). Without *, a path matches as a prefix. With *, * matches any characters (e.g. /*.php). Edit the file on the server to change traps.', 'wlkns-security'),
                'honeypot.txt'
            ))
        );
    }

    /**
     * Sanitise submitted settings.
     *
     * @param  array  $input  Raw submitted values.
     * @return array
     */
    public function sanitize($input)
    {
        $input = is_array($input) ? $input : [];
        $defaults = Activator::default_settings();
        $clean = [];

        foreach ($defaults as $key => $default) {
            if (is_bool($default)) {
                $clean[$key] = ! empty($input[$key]);
            }
        }

        // Throttle integers: threshold 1–1000, window/block 1–10080 minutes.
        $ranges = [
            'login_threshold' => 1000,
            'login_window_minutes' => 10080,
            'login_block_minutes' => 10080,
            'honeypot_threshold' => 1000,
            'honeypot_window_minutes' => 10080,
            'honeypot_block_minutes' => 10080,
        ];

        foreach ($ranges as $key => $max) {
            $value = isset($input[$key]) ? (int) $input[$key] : (int) $defaults[$key];
            $clean[$key] = min($max, max(1, $value));
        }

        // Login-email recipient: must be an existing administrator, else 0 (none).
        $recipient = isset($input['login_emails_recipient']) ? absint($input['login_emails_recipient']) : 0;
        $clean['login_emails_recipient'] = ($recipient && user_can($recipient, 'manage_options')) ? $recipient : 0;

        return $clean;
    }
}
