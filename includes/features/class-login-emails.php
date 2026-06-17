<?php

/**
 * Login email notifications.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Emails a chosen administrator whenever any user logs in.
 *
 * The recipient is a single WordPress user ID stored in settings; if none is
 * selected the feature stays silent.
 */
class Login_Emails extends Feature
{
    /**
     * Register hooks.
     */
    public function register()
    {
        add_action('wp_login', [$this, 'notify'], 10, 2);
    }

    /**
     * Send the login notification to the configured recipient.
     *
     * @param  string  $user_login  Username of the user who logged in.
     * @param  \WP_User  $user  The user that logged in.
     */
    public function notify($user_login, $user)
    {
        $recipient_id = $this->settings->get_int('login_emails_recipient');

        if (! $recipient_id) {
            return;
        }

        $recipient = get_userdata($recipient_id);

        if (! $recipient || empty($recipient->user_email)) {
            return;
        }

        if (! $user instanceof \WP_User) {
            $user = get_user_by('login', $user_login);
        }

        if (! $user) {
            return;
        }

        $site = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $ip = Blocklist::client_ip();
        $ip = $ip === '' ? __('unknown', 'wlkns-security') : $ip;
        $role = ! empty($user->roles) ? implode(', ', $user->roles) : __('none', 'wlkns-security');
        $when = wp_date('Y-m-d H:i:s T');

        /* translators: 1: site name, 2: username. */
        $subject = sprintf(__('[%1$s] Login: %2$s', 'wlkns-security'), $site, $user->user_login);

        $lines = [
            /* translators: %s: site name. */
            sprintf(__('A user just logged in to %s.', 'wlkns-security'), $site),
            '',
            /* translators: %s: username. */
            sprintf(__('Username:     %s', 'wlkns-security'), $user->user_login),
            /* translators: %s: display name. */
            sprintf(__('Display name: %s', 'wlkns-security'), $user->display_name),
            /* translators: %s: comma-separated role list. */
            sprintf(__('Role:         %s', 'wlkns-security'), $role),
            /* translators: %s: source IP address. */
            sprintf(__('IP address:   %s', 'wlkns-security'), $ip),
            /* translators: %s: date and time of the login. */
            sprintf(__('Time:         %s', 'wlkns-security'), $when),
        ];

        wp_mail($recipient->user_email, $subject, implode("\n", $lines));
    }
}
