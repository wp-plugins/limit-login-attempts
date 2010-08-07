<?php
/*
  Limit Login Attempts: plugin upgrade functions
  Version 2.0beta4

  Copyright 2009, 2010 Johan Eenfeldt

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
 * Functions related to plugin upgrade
 */

/* Upgrade options from previous version if necessary */
function limit_login_upgrade_if_necessary() {
	/* Upgrade from version 1 options? */
	if (limit_login_options_exists() || !limit_login_v1_options_exists())
		return;

	// todo: upgrade statistics!
	limit_login_v1_upgrade_options();
	limit_login_v1_delete_options();
}


/*
 * Plugin options v1 => v2
 */

/*
 * Options available in plugin version 1.x 
 *
 * This file is included in function context, so the variable is only "global"
 * to this file.
 */
$limit_login_options_v1 =
	array('client_type', 'allowed_retries', 'lockout_duration'
	      , 'allowed_lockouts', 'long_duration', 'valid_duration', 'cookies'
	      , 'lockout_notify', 'notify_email_after');

/* Check if v1 style options exists */
function limit_login_v1_options_exists() {
	global $limit_login_options_v1;

	foreach ($limit_login_options_v1 as $name => $value) {
		$a = get_option('limit_login_' . $name);

		if ($a !== false)
			return true;
	}

	return false;
}


/* Get stored v1 style options */
function limit_login_v1_get_options() {
	global $limit_login_options_v1;

	$options = array();

	foreach ($limit_login_options_1 as $name => $value) {
		$a = get_option('limit_login_' . $name);

		if ($a === false)
			continue;

		$options[$name] = $a;
	}

	return $options;
}


/*
 * Upgrade from old v1 style options (and store modified options)
 * 
 * Note that startup will have populated $limit_login_options with default
 * values.
 */
function limit_login_v1_upgrade_options() {
	global $limit_login_options;

	$old_options = limit_login_v1_get_options();
	if (empty($old_options))
		return;

	foreach($limit_login_options AS $name => $value) {
		if (!isset($old_options[$name]))
			continue;
		$limit_login_options[$name] = $old_options[$name];
	}

	limit_login_sanitize_options();
	limit_login_update_options();
}


/* Delete v1 style stored options */
function limit_login_v1_delete_options() {
	global $limit_login_options_v1;

	foreach ($limit_login_options_v1 as $name => $value) {
		$option_name = 'limit_login_' . $name;
		if (get_option($option_name) !== false)
			delete_option($option_name);
	}
}
?>