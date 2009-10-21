<?php
/*
  Limit Login Attempts: upgrade functions
  Version 2.0beta5

  Copyright 2008, 2009 Johan Eenfeldt

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


/*
 * Functions related to plugin upgrade
 */

/* Check if 1.x style options exists */
function limit_login_v1x_options_exists() {
	global $limit_login_options;

	foreach ($limit_login_options as $name => $value) {
		$a = get_option('limit_login_' . $name)


		return true;
	}

	return false;
}

/* Get 1.x style options */
function limit_login_v1x_setup_options() {
	global $limit_login_options;

	foreach ($limit_login_options as $name => $value) {
		$a = get_option('limit_login_' . $name);

		if ($a === false)
			continue;

		$limit_login_options[$name] = limit_login_cast_option($a);
	}

	limit_login_sanitize_options();
}

/* Delete 1.x style options */
function limit_login_v1x_delete_options() {
	global $limit_login_options;

	foreach ($limit_login_options as $name => $value) {
		$option_name = 'limit_login_' . $name;
		if (get_option($option_name) !== false)
			delete_option($option_name);
	}
}

/*  */
function limit_login_update_warning() {
	if (limit_login_v2x_options_exists() || !limit_login_v1x_options_exists())
		return false;

	/* Check if options differ from default */
	global $limit_login_options;

	$different = false;

	foreach ($limit_login_options as $name => $value) {
		$a = get_option('limit_login_' . $name);

		if ($a === false)
			continue;

		if ($limit_login_options[$name] == limit_login_cast_option($a))
			continue;

		$different = true;
		break;
	}

	/* 
	 * If old style options exists but are all default values we can delete
	 * them. Even if user downgrades to 1.x version of plugin the same option
	 * values will be used;
	 */
	if (!$different)
		limit_login_v1x_delete_options();

	return $different;
}
?>