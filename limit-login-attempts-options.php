<?php
/*
  Limit Login Attempts: options handling
  Version 2.0beta4

  Copyright 2008, 2009, 2010 Johan Eenfeldt

  Licenced under the GNU GPL:

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/* Die if included directly (without any PHP warnings, etc) */
if (!defined('ABSPATH'))
    die();

/*
 * Constants
 */

/* Current version of plugin options */
define('LIMIT_LOGIN_OPTIONS_VERSION', 2);

/* Option name in WP options table */
define('LIMIT_LOGIN_OPTIONS_WPOPTION', 'limit_login_options');

/*
 * Variables
 *
 * Assignments are for default value -- change on admin page.
 *
 * This file is included in function context. This means that these variables
 * are "global" only to this file unless defined with $GLOBALS.
 */

/* Runtime options, loaded from options table */
$GLOBALS['limit_login_options'] = array();

/* Default values for options (not global -- only visible in this file) */
$limit_login_options_default =
	array(
	      /* Plugin options version (for easier plugin upgrades) */
	      'version' => LIMIT_LOGIN_OPTIONS_VERSION

	      /* Are we behind a proxy? */
	      , 'client_type' => LIMIT_LOGIN_DIRECT_ADDR

	      /* Lock out after this many tries */
	      , 'allowed_retries' => 4

	      /* Lock out for this many seconds */
	      , 'lockout_duration' => 1200 // 20 minutes

	      /* Long lock out after this many lockouts */
	      , 'allowed_lockouts' => 4

	      /* Long lock out for this many seconds */
	      , 'long_duration' => 86400 // 24 hours

	      /* Reset failed attempts after this many seconds */
	      , 'valid_duration' => 86400 // 24 hours

	      /* Notify on lockout. Values: '', 'log', 'email', 'log,email' */
	      , 'lockout_notify' => 'log'

	      /* If notify by email, do so after this number of lockouts */
	      , 'notify_email_after' => 4

	      /* Enforce limit on new user registrations for IP */
	      , 'register_enforce' => true

	      /* Allow this many new user registrations ... */
	      , 'register_allowed' => 3

	      /* ... during this time */
	      , 'register_duration' => 86400 // 24 hours

	      /* Allow password reset using login name? */
	      , 'disable_pwd_reset_username' => true

	      /* ... for capability level_xx or higher */
	      , 'pwd_reset_username_limit' => 1

	      /* Allow password resets at all? */
	      , 'disable_pwd_reset' => false

	      /* ... for capability level_xx or higher */
	      , 'pwd_reset_limit' => 1
	      );



/*
 * Functions start here
 */

/* Get current value for option */
function limit_login_option($option_name) {
	global $limit_login_options;

	if (isset($limit_login_options[$option_name]))
		return $limit_login_options[$option_name];
	return null;
}


/* Cast value to same type as default value */
function limit_login_cast_value($value, $default_value) {
	if (is_bool($default_value))
		return !!$value;
	if (is_numeric($default_value))
		return intval($value);
	return strval($value);
}


/* Cast option value to correct type */
function limit_login_cast_option($name, $value) {
	global $limit_login_options_default;

	if (!isset($limit_login_options_default[$name]))
		return null;

	return limit_login_cast_value($value, $limit_login_options_default[$name]);
}


/* Setup plugin options */
function limit_login_setup_options() {
	global $limit_login_options, $limit_login_options_default;

	$options = get_option(LIMIT_LOGIN_OPTIONS_WPOPTION);

	if ($options === false || !is_array($options)) {
		$limit_login_options = $limit_login_options_default;
		return;
	}

	/* Only use the options we understand */
	foreach ($limit_login_options_default as $name => $default_value) {
		if (!isset($options[$name])) {
			$limit_login_options[$name] = $default_value;
			continue;
		}

		$limit_login_options[$name] = limit_login_cast_option($name, $options[$name]);
	}

	limit_login_sanitize_options();
}


/* Check if stored options exists */
function limit_login_options_exists() {
	return get_option(LIMIT_LOGIN_OPTIONS_WPOPTION) !== false;
}


/* Update options in db from global variable */
function limit_login_update_options() {
	global $limit_login_options;

	/* This will automatically create option if it does not exist */
	update_option(LIMIT_LOGIN_OPTIONS_WPOPTION, $limit_login_options);
}


/* Make sure the variables make sense */
function limit_login_sanitize_options() {
	global $limit_login_options;

	// todo: more checks?

	$notify_email_after = max(1, intval(limit_login_option('notify_email_after')));
	$limit_login_options['notify_email_after'] = min(limit_login_option('allowed_lockouts'), $notify_email_after);

	$args = explode(',', limit_login_option('lockout_notify'));
	$args_allowed = explode(',', LIMIT_LOGIN_LOCKOUT_NOTIFY_ALLOWED);
	$new_args = array();
	foreach ($args as $a) {
		if (in_array($a, $args_allowed)) {
			$new_args[] = $a;
		}
	}
	$limit_login_options['lockout_notify'] = implode(',', $new_args);

	if ( limit_login_option('client_type') != LIMIT_LOGIN_DIRECT_ADDR
		 && limit_login_option('client_type') != LIMIT_LOGIN_PROXY_ADDR ) {
		$limit_login_options['client_type'] = LIMIT_LOGIN_DIRECT_ADDR;
	}
}


/* Get options from $_POST[] and update plugin options */
function limit_login_get_options_from_post() {
	global $limit_login_options, $limit_login_options_default;

	$option_multiple =
		array('lockout_duration' => 60, 'valid_duration' => 3600
		      , 'long_duration' => 3600, 'register_duration' => 3600);

	foreach ($limit_login_options_default as $name => $default_value) {
		if (is_bool($default_value)) {
			/*
			 * Must be handled separately as un-selected checkbox
			 * is not sent at all by the browser.
			 */
			$limit_login_options[$name] = isset($_POST[$name]) && $_POST[$name] == '1';
			continue;
		}

		if (!isset($_POST[$name]))
			continue;

		$value = limit_login_cast_value($_POST[$name], $default_value);

		/* All time values are stored as seconds */
		if (is_numeric($default_value) && array_key_exists($name, $option_multiple))
			$value = $value * $option_multiple[$name];

		if (is_string($default_value) && get_magic_quotes_gpc())
			$value = stripslashes($value);

		$limit_login_options[$name] = $value;
	}

	/* Special handling for lockout_notify */
	$v = array();
	if (isset($_POST['lockout_notify_log'])) {
		$v[] = 'log';
	}
	if (isset($_POST['lockout_notify_email'])) {
		$v[] = 'email';
	}
	$limit_login_options['lockout_notify'] = implode(',', $v);

	limit_login_sanitize_options();
	limit_login_update_options();
}
?>