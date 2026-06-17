<?php

/**
 * Disable the built-in file editors.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Disables the theme/plugin code editors via DISALLOW_FILE_EDIT.
 */
class Disable_File_Editing extends Feature
{
    /**
     * Register — define the constant if it isn't already set.
     */
    public function register()
    {
        if (! defined('DISALLOW_FILE_EDIT')) {
            define('DISALLOW_FILE_EDIT', true);
        }
    }
}
