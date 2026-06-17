<?php

/**
 * Base feature class.
 */

namespace WLKNS\Security;

defined('ABSPATH') || exit;

/**
 * Common base for every hardening feature. Each subclass wires its own hooks
 * in register(), which is only called when the feature's toggle is enabled.
 */
abstract class Feature
{
    /**
     * Settings instance.
     *
     * @var Settings
     */
    protected $settings;

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
     * Register the feature's hooks.
     */
    abstract public function register();
}
