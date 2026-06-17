<?php

/**
 * Disable comments site-wide.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Closes comments everywhere and removes the comment UI.
 */
class Disable_Comments extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_action('init', [$this, 'remove_support']);

        add_filter('comments_open', '__return_false', 20);
        add_filter('pings_open', '__return_false', 20);
        add_filter('comments_array', '__return_empty_array', 20);

        add_action('admin_menu', [$this, 'remove_menu']);
        add_action('admin_init', [$this, 'redirect_admin_page']);
        add_action('wp_dashboard_setup', [$this, 'remove_dashboard_widget']);
        add_action('wp_before_admin_bar_render', [$this, 'remove_admin_bar_node']);
    }

    /**
     * Remove comment + trackback support from every post type.
     */
    public function remove_support()
    {
        foreach (get_post_types() as $post_type) {
            if (post_type_supports($post_type, 'comments')) {
                remove_post_type_support($post_type, 'comments');
                remove_post_type_support($post_type, 'trackbacks');
            }
        }
    }

    /**
     * Remove the Comments admin menu.
     */
    public function remove_menu()
    {
        remove_menu_page('edit-comments.php');
    }

    /**
     * Redirect away from the comments admin screen.
     */
    public function redirect_admin_page()
    {
        global $pagenow;

        if ($pagenow === 'edit-comments.php') {
            wp_safe_redirect(admin_url());
            exit;
        }
    }

    /**
     * Remove the "Recent Comments" dashboard widget.
     */
    public function remove_dashboard_widget()
    {
        remove_meta_box('dashboard_recent_comments', 'dashboard', 'normal');
    }

    /**
     * Remove the comments node from the admin bar.
     */
    public function remove_admin_bar_node()
    {
        global $wp_admin_bar;

        if (is_object($wp_admin_bar)) {
            $wp_admin_bar->remove_node('comments');
        }
    }
}
