<?php

/**
 * Disable theme installs / uploads.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Blocks adding new themes while leaving switching of existing ones intact.
 */
class Disable_Theme_Install extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_filter('map_meta_cap', [$this, 'deny_caps'], 10, 2);
        add_action('admin_menu', [$this, 'remove_menu'], 999);
        add_action('admin_init', [$this, 'guard_screen']);
    }

    /**
     * Deny the install/upload capabilities.
     *
     * @param  array  $caps  Mapped caps.
     * @param  string  $cap  Requested cap.
     * @return array
     */
    public function deny_caps($caps, $cap)
    {
        if (in_array($cap, ['install_themes', 'upload_themes'], true)) {
            return ['do_not_allow'];
        }

        return $caps;
    }

    /**
     * Remove the "Add New Theme" submenu.
     */
    public function remove_menu()
    {
        remove_submenu_page('themes.php', 'theme-install.php');
    }

    /**
     * Block direct access to the install screen.
     */
    public function guard_screen()
    {
        global $pagenow;

        if ($pagenow === 'theme-install.php') {
            wp_die(
                esc_html__('Installing themes is disabled.', 'wlkns-security'),
                esc_html__('Forbidden', 'wlkns-security'),
                ['response' => 403]
            );
        }
    }
}
