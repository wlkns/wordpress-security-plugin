<?php
/**
 * Admin menu, settings page and Blocked IPs page.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Builds the Security admin area.
 */
class Admin
{
    const BLOCKED_SLUG = 'wlkns-security-blocked';

    /**
     * Settings instance.
     *
     * @var Settings
     */
    private $settings;

    /**
     * Constructor.
     *
     * @param  Settings  $settings  Settings.
     */
    public function __construct(Settings $settings)
    {
        $this->settings = $settings;
    }

    /**
     * Register admin hooks.
     */
    public function register()
    {
        add_action('admin_menu', [$this, 'add_menu']);
        add_action('admin_init', [$this->settings, 'register']);
        add_action('admin_post_wlkns_wws_unblock', [$this, 'handle_unblock']);
        add_action('admin_post_wlkns_wws_block', [$this, 'handle_block']);
    }

    /**
     * Register the menu and subpages.
     */
    public function add_menu()
    {
        add_menu_page(
            __('Security', 'wlkns-security'),
            __('Security', 'wlkns-security'),
            'manage_options',
            Settings::PAGE,
            [$this, 'render_settings'],
            'dashicons-shield',
            80
        );

        add_submenu_page(
            Settings::PAGE,
            __('Security Settings', 'wlkns-security'),
            __('Settings', 'wlkns-security'),
            'manage_options',
            Settings::PAGE,
            [$this, 'render_settings']
        );

        add_submenu_page(
            Settings::PAGE,
            __('Blocked IPs', 'wlkns-security'),
            __('Blocked IPs', 'wlkns-security'),
            'manage_options',
            self::BLOCKED_SLUG,
            [$this, 'render_blocked']
        );
    }

    /**
     * Render the settings page.
     */
    public function render_settings()
    {
        if (! current_user_can('manage_options')) {
            return;
        }
        ?>
		<div class="wrap">
			<h1><?php esc_html_e('WLKNS Security', 'wlkns-security'); ?></h1>
			<p><?php esc_html_e('Toggle the hardening features below. All are enabled by default.', 'wlkns-security'); ?></p>
			<form action="options.php" method="post">
				<?php
                settings_fields(Settings::GROUP);
        do_settings_sections(Settings::PAGE);
        submit_button();
        ?>
			</form>
		</div>
		<?php
    }

    /**
     * Render the Blocked IPs page.
     */
    public function render_blocked()
    {
        if (! current_user_can('manage_options')) {
            return;
        }

        Blocklist::purge_expired();

        $table = new Blocklist_Table;
        $table->prepare_items();
        ?>
		<div class="wrap">
			<h1><?php esc_html_e('Blocked IPs', 'wlkns-security'); ?></h1>
			<?php $this->maybe_render_notice(); ?>

			<h2><?php esc_html_e('Block an IP manually', 'wlkns-security'); ?></h2>
			<form action="<?php echo esc_url(admin_url('admin-post.php')); ?>" method="post">
				<input type="hidden" name="action" value="wlkns_wws_block" />
				<?php wp_nonce_field('wlkns_wws_block'); ?>
				<input type="text" name="ip" class="regular-text" placeholder="<?php esc_attr_e('e.g. 203.0.113.10', 'wlkns-security'); ?>" />
				<?php submit_button(__('Block IP', 'wlkns-security'), 'secondary', 'submit', false); ?>
			</form>

			<h2 style="margin-top:2em;"><?php esc_html_e('Currently blocked', 'wlkns-security'); ?></h2>
			<form method="get">
				<input type="hidden" name="page" value="<?php echo esc_attr(self::BLOCKED_SLUG); ?>" />
				<?php $table->display(); ?>
			</form>
		</div>
		<?php
    }

    /**
     * Handle the per-row unblock action.
     */
    public function handle_unblock()
    {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do that.', 'wlkns-security'));
        }

        $ip = isset($_REQUEST['ip']) ? sanitize_text_field(wp_unslash($_REQUEST['ip'])) : '';
        check_admin_referer('wlkns_wws_unblock_'.$ip);

        if ($ip !== '') {
            Blocklist::unblock($ip);
        }

        $this->redirect_back('unblocked');
    }

    /**
     * Handle a manual block submission.
     */
    public function handle_block()
    {
        if (! current_user_can('manage_options')) {
            wp_die(esc_html__('You are not allowed to do that.', 'wlkns-security'));
        }

        check_admin_referer('wlkns_wws_block');

        $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';

        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $blocked = Blocklist::block($ip, __('Manual block', 'wlkns-security'), 'manual');
            $this->redirect_back($blocked ? 'blocked' : 'failed');
        }

        $this->redirect_back('invalid');
    }

    /**
     * Render a dismissible notice based on the ?wlkns_notice query arg.
     */
    private function maybe_render_notice()
    {
        $status = isset($_GET['wlkns_notice']) ? sanitize_key(wp_unslash($_GET['wlkns_notice'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- read-only display flag.

        $messages = [
            'unblocked' => ['updated', __('IP unblocked.', 'wlkns-security')],
            'blocked' => ['updated', __('IP blocked.', 'wlkns-security')],
            'failed' => ['error', __('Could not block that IP. Please try again.', 'wlkns-security')],
            'invalid' => ['error', __('That is not a valid IP address.', 'wlkns-security')],
        ];

        if (! isset($messages[$status])) {
            return;
        }

        printf(
            '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>',
            esc_attr($messages[$status][0] === 'error' ? 'error' : 'success'),
            esc_html($messages[$status][1])
        );
    }

    /**
     * Redirect back to the Blocked IPs page with a status notice.
     *
     * @param  string  $status  Status key.
     */
    private function redirect_back($status)
    {
        wp_safe_redirect(
            add_query_arg(
                [
                    'page' => self::BLOCKED_SLUG,
                    'wlkns_notice' => $status,
                ],
                admin_url('admin.php')
            )
        );
        exit;
    }
}
