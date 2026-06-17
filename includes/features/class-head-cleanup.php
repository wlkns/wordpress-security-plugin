<?php

/**
 * Remove default wp_head / wp_print_styles output (head cleanup).
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Strips selected default tags WordPress prints into the document head.
 *
 * Each removal is gated by its own setting so site owners can opt in to only
 * the parts they want. Note: wp_generator (Hide_Wp_Version) and rsd_link
 * (Disable_Xmlrpc) are handled by their own features and intentionally not
 * duplicated here.
 */
class Head_Cleanup extends Feature
{
    /**
     * Register hooks for every enabled head-cleanup toggle.
     */
    public function register()
    {
        if ($this->settings->is_enabled('head_disable_emojis')) {
            $this->disable_emojis();
        }

        if ($this->settings->is_enabled('head_remove_feed_links')) {
            // RSS/Atom feed <link> tags.
            remove_action('wp_head', 'feed_links', 2);
            remove_action('wp_head', 'feed_links_extra', 3);
        }

        if ($this->settings->is_enabled('head_remove_oembed')) {
            // oEmbed discovery <link> and the host JS that powers embeds.
            remove_action('wp_head', 'wp_oembed_add_discovery_links');
            remove_action('wp_head', 'wp_oembed_add_host_js');
        }

        if ($this->settings->is_enabled('head_remove_rel_links')) {
            // Prev/next, index/parent/start rel links and the shortlink tag.
            // (Several were dropped from core long ago — harmless no-ops.)
            remove_action('wp_head', 'adjacent_posts_rel_link_wp_head');
            remove_action('wp_head', 'index_rel_link');
            remove_action('wp_head', 'parent_post_rel_link');
            remove_action('wp_head', 'start_post_rel_link');
            remove_action('wp_head', 'wp_shortlink_wp_head');
        }

        if ($this->settings->is_enabled('head_remove_wlwmanifest')) {
            // Windows Live Writer manifest link.
            remove_action('wp_head', 'wlwmanifest_link');
        }

        if ($this->settings->is_enabled('head_remove_rest_link')) {
            // REST API discovery <link rel="https://api.w.org/">.
            remove_action('wp_head', 'rest_output_link_wp_head');
        }

        if ($this->settings->is_enabled('head_remove_resource_hints')) {
            // dns-prefetch / preconnect resource hints.
            remove_action('wp_head', 'wp_resource_hints', 2);
        }
    }

    /**
     * Fully disable emoji support (scripts, styles and the DNS prefetch),
     * front-end and admin, so no broken half-state remains.
     */
    private function disable_emojis()
    {
        remove_action('wp_head', 'print_emoji_detection_script', 7);
        remove_action('admin_print_scripts', 'print_emoji_detection_script');
        remove_action('wp_print_styles', 'print_emoji_styles');
        remove_action('admin_print_styles', 'print_emoji_styles');
        remove_filter('the_content_feed', 'wp_staticize_emoji');
        remove_filter('comment_text_rss', 'wp_staticize_emoji');
        remove_filter('wp_mail', 'wp_staticize_emoji_for_email');

        add_filter('tiny_mce_plugins', [$this, 'remove_tinymce_emoji']);
        add_filter('wp_resource_hints', [$this, 'remove_emoji_prefetch'], 10, 2);
    }

    /**
     * Drop the emoji plugin from the TinyMCE plugin list.
     *
     * @param  array  $plugins  TinyMCE plugins.
     * @return array
     */
    public function remove_tinymce_emoji($plugins)
    {
        if (! is_array($plugins)) {
            return [];
        }

        return array_diff($plugins, ['wpemoji']);
    }

    /**
     * Remove the emoji CDN from the dns-prefetch resource hints.
     *
     * @param  array  $urls  Resource-hint URLs.
     * @param  string  $relation_type  The hint relation type.
     * @return array
     */
    public function remove_emoji_prefetch($urls, $relation_type)
    {
        if ($relation_type !== 'dns-prefetch') {
            return $urls;
        }

        $emoji_svg = apply_filters('emoji_svg_url', 'https://s.w.org/images/core/emoji/');

        return array_filter(
            $urls,
            static function ($url) use ($emoji_svg) {
                return is_string($url) ? strpos($url, $emoji_svg) === false : true;
            }
        );
    }
}
