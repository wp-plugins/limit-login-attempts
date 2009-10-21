<?php
/*
  Plugin Name: Limit Login Attempts
  Plugin URI: http://devel.kostdoktorn.se/limit-login-attempts
  Description: Limit rate of login attempts, including by way of cookies, for each IP.
  Author: Johan Eenfeldt
  Author URI: http://devel.kostdoktorn.se
  Version: 2.0beta4

  Copyright 2008, 2009 Johan Eenfeldt

  Thanks to Michael Skerwiderski for reverse proxy handling.

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
 * Constants
 */

/* Different ways to get remote address: direct & behind proxy */
define('LIMIT_LOGIN_DIRECT_ADDR', 'REMOTE_ADDR');
define('LIMIT_LOGIN_PROXY_ADDR', 'HTTP_X_FORWARDED_FOR');

/* Notify value checked against these in limit_login_sanitize_options() */
define('LIMIT_LOGIN_LOCKOUT_NOTIFY_ALLOWED', 'log,email');

/*
 * Variables
 *
 * Assignments are for default value -- change in admin page.
 */

$limit_login_options =
	array(
		  /* Are we behind a proxy? */
		  'client_type' => LIMIT_LOGIN_DIRECT_ADDR

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

		  /* Also limit malformed/forged cookies?
		   *
		   * NOTE: Only works in WP 2.7+, as necessary actions were added then.
		   */
		  , 'cookies' => true

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

		  /* Allow password reset using login name?
		   *
		   * NOTE: Only works in WP 2.6.5+, as necessary filter was added then.
		   */
		  , 'disable_pwd_reset_username' => true

		  /* ... for capability level_xx or higher */
		  , 'pwd_reset_username_limit' => 1

		  /* Allow password resets at all?
		   *
		   * NOTE: Only works in WP 2.6.5+, as necessary filter was added then.
		   */
		  , 'disable_pwd_reset' => false

		  /* ... for capability level_xx or higher */
		  , 'pwd_reset_limit' => 1
		  );

$limit_login_my_error_shown = false; /* have we shown our stuff? */
$limit_login_just_lockedout = false; /* started this pageload??? */
$limit_login_nonempty_credentials = false; /* user and pwd nonempty */
$limit_login_statistics = null; /* statistics, stored in option table */

/* Level of the different roles. Used for descriptive purposes only */
$limit_login_level_role =
	array(0 => __('Subscriber','limit-login-attempts')
		  , 1 => __('Contributor','limit-login-attempts')
		  , 2 => __('Author','limit-login-attempts')
		  , 7 => __('Editor','limit-login-attempts')
		  , 10 => __('Administrator','limit-login-attempts'));

/*
 * Startup
 */

limit_login_setup();


/*
 * Functions start here
 */

/* Get options and setup filters & actions */
function limit_login_setup() {
	$loaded = load_plugin_textdomain('limit-login-attempts'
									 , dirname(plugin_basename(__FILE__)) . '/languages');

	if (!$loaded)
		load_plugin_textdomain('limit-login-attempts'
							   , dirname(plugin_basename(__FILE__)) . '/languages-1.x');

	limit_login_setup_options();

	/* Filters and actions */
	add_action('wp_login_failed', 'limit_login_failed');
	add_filter('wp_authenticate_user', 'limit_login_wp_authenticate_user', 99999, 2);
	add_action('wp_authenticate', 'limit_login_track_credentials', 10, 2);
	add_action('login_head', 'limit_login_add_error_message', 10);
	add_action('login_errors', 'limit_login_fixup_error_messages');

	if (limit_login_option('cookies')) {
		add_action('plugins_loaded', 'limit_login_handle_cookies', 99999);
		add_action('auth_cookie_bad_hash', 'limit_login_failed_cookie');
		add_action('auth_cookie_bad_username', 'limit_login_failed_cookie');
	}

	if (limit_login_option('register_enforce')) {
		limit_login_require_file('registrations');

		add_filter('registration_errors', 'limit_login_filter_registration');
		add_filter('login_message', 'limit_login_reg_filter_login_message');
		/* This needs to run before limit_login_add_error_message() */
		add_action('login_head', 'limit_login_add_reg_error_message', 9);
	}

	if (limit_login_option('disable_pwd_reset') || limit_login_option('disable_pwd_reset_username')) {
		add_filter('allow_password_reset', 'limit_login_filter_pwd_reset', 10, 2);
	}

	if (is_admin()) {
		limit_login_require_file('admin');

		add_action('admin_menu', 'limit_login_admin_menu');
		add_filter('plugin_action_links', 'limit_login_filter_plugin_actions', 10, 2 );
	}
}


/* Load additional plugin code file */
function limit_login_require_file($name) {
	$file_name = dirname(__FILE__) . '/limit-login-attempts-' . $name . '.php';
	require_once($file_name);
}


/* Get correct remote address */
function limit_login_get_address($type_name = '') {
	$type = $type_name;
	if (empty($type)) {
		$type = limit_login_option('client_type');
	}

	if (isset($_SERVER[$type])) {
		return $_SERVER[$type];
	}

	/*
	 * Not found. Did we get proxy type from option?
	 * If so, try to fall back to direct address.
	 */
	if ( empty($type_name) && $type == LIMIT_LOGIN_PROXY_ADDR
		 && isset($_SERVER[LIMIT_LOGIN_DIRECT_ADDR])) {

		/*
		 * NOTE: Even though we fall back to direct address -- meaning you
		 * can get a mostly working plugin when set to PROXY mode while in
		 * fact directly connected to Internet it is not safe!
		 *
		 * Client can itself send HTTP_X_FORWARDED_FOR header fooling us
		 * regarding which IP should be banned.
		 */

		return $_SERVER[LIMIT_LOGIN_DIRECT_ADDR];
	}
	
	return '';
}


/* Helpfunction to check ip in time array (lockout/valid)
 *
 * Returns true if array exists, ip is key in array, and value (time) is not
 * past.
 */
function limit_login_check_time($check_array, $ip = null) {
	if (!$ip)
		$ip = limit_login_get_address();

	return (is_array($check_array) && isset($check_array[$ip])
			&& time() <= $check_array[$ip]);
}


/* Is it ok to login? */
function is_limit_login_ok() {
	/* Test that there is not a (still valid) lockout on ip in lockouts array */
	return !limit_login_check_time(limit_login_get_array('lockouts'));
}


/* Filter: allow login attempt? (called from wp_authenticate()) */
function limit_login_wp_authenticate_user($user, $password) {
	if (is_wp_error($user) || is_limit_login_ok() ) {
		return $user;
	}

	global $limit_login_my_error_shown;
	$limit_login_my_error_shown = true;

	$error = new WP_Error();
	$error->add('too_many_retries', limit_login_error_msg());
	return $error;
}


/*
 * Action: called in plugin_loaded (really early) to make sure we do not allow
 * auth cookies while locked out.
 */
function limit_login_handle_cookies() {
	if (is_limit_login_ok()) {
		return;
	}

	if (empty($_COOKIE[AUTH_COOKIE]) && empty($_COOKIE[SECURE_AUTH_COOKIE])
		&& empty($_COOKIE[LOGGED_IN_COOKIE])) {
		return;
	}

	wp_clear_auth_cookie();

	if (!empty($_COOKIE[AUTH_COOKIE])) {
		$_COOKIE[AUTH_COOKIE] = '';
	}
	if (!empty($_COOKIE[SECURE_AUTH_COOKIE])) {
		$_COOKIE[SECURE_AUTH_COOKIE] = '';
	}
	if (!empty($_COOKIE[LOGGED_IN_COOKIE])) {
		$_COOKIE[LOGGED_IN_COOKIE] = '';
	}
}


/* Action: failed cookie login wrapper for limit_login_failed() */
function limit_login_failed_cookie($arg) {
	limit_login_failed($arg);
	wp_clear_auth_cookie();
}

/*
 * Action when login attempt failed
 *
 * Increase nr of retries (if necessary). Reset valid value. Setup
 * lockout if nr of retries are above threshold. And more!
 */
function limit_login_failed($arg) {
	$ip = limit_login_get_address();

	$lockouts = limit_login_get_array('lockouts');
	if (limit_login_check_time($lockouts, $ip)) {
		/* if currently locked-out, do not add to retries */
		return;
	}

	/* Get the arrays with retries and retries-valid information */
	$retries = limit_login_get_array('retries');
	$valid = limit_login_get_array('retries_valid');

	/* Check validity and add one to retries */
	if (isset($retries[$ip]) && limit_login_check_time($valid, $ip)) {
		$retries[$ip] ++;
	} else {
		$retries[$ip] = 1;
	}
	$valid[$ip] = time() + limit_login_option('valid_duration');

	/* lockout? */
	if($retries[$ip] % limit_login_option('allowed_retries') == 0) {
		global $limit_login_just_lockedout;

		$limit_login_just_lockedout = true;

		/* setup lockout, reset retries as needed */
		$retries_long = limit_login_option('allowed_retries')
			* limit_login_option('allowed_lockouts');
		if ($retries[$ip] >= $retries_long) {
			/* long lockout */
			$lockouts[$ip] = time() + limit_login_option('long_duration');
			unset($retries[$ip]);
			unset($valid[$ip]);
		} else {
			/* normal lockout */
			$lockouts[$ip] = time() + limit_login_option('lockout_duration');
		}

		/* try to find username which failed */
		$user = '';
		if (is_string($arg)) {
			/* action: wp_login_failed */
			$user = $arg;
		} elseif (is_array($arg) && array_key_exists('username', $arg)) {
			/* action: auth_cookie_bad_* */
			$user = $arg['username'];
		}

		/* do housecleaning and save values */
		limit_login_cleanup($retries, $lockouts, $valid);

		/* do any notification */
		limit_login_notify($user);

		/* increase statistics */
		$total = limit_login_statistic_add('lockouts_total');
	} else {
		/* not lockout (yet!), do housecleaning and save values */
		limit_login_cleanup($retries, null, $valid);
	}
}


/* Clean up any old lockouts and old retries and save arrays */
function limit_login_cleanup($retries = null, $lockouts = null, $valid = null) {
	$now = time();
	$lockouts = !is_null($lockouts) ? $lockouts : limit_login_get_array('lockouts');

	/* remove old lockouts */
	foreach ($lockouts as $ip => $lockout) {
		if ($lockout < $now) {
			unset($lockouts[$ip]);
		}
	}
	limit_login_save_array('lockouts', $lockouts);

	/* remove retries that are no longer valid */
	$valid = !is_null($valid) ? $valid : limit_login_get_array('retries_valid');
	$retries = !is_null($retries) ? $retries : limit_login_get_array('retries');
	if (!empty($valid) && !empty($retries)) {
		foreach ($valid as $ip => $lockout) {
			if ($lockout < $now) {
				unset($valid[$ip]);
				unset($retries[$ip]);
			}
		}

		/* go through retries directly, if for some reason they've gone out of sync */
		foreach ($retries as $ip => $retry) {
			if (!isset($valid[$ip])) {
				unset($retries[$ip]);
			}
		}

		limit_login_save_array('retries', $retries);
		limit_login_save_array('retries_valid', $valid);
	}

	/* do the same for the registration arrays, if necessary */
	if (limit_login_option('register_enforce'))
		limit_login_reg_cleanup();
}


/* Check if user have level capability */
function limit_login_user_has_level($userid, $level) {
	$userid = intval($userid);
	$level = intval($level);

	if ($userid <= 0) {
		return false;
	}

	$user = new WP_User($userid);

	return ($user && $user->has_cap($level));
}


/* Filter: enforce that password reset is allowed */
function limit_login_filter_pwd_reset($b, $userid) {
	$limit = null;

	/* What limit (max privilege level) to use, if any */
	if (limit_login_option('disable_pwd_reset')) {
		/* limit on all pwd resets */
		$limit = limit_login_option('pwd_reset_limit');
	}

	if (limit_login_option('disable_pwd_reset_username') && !strpos($_POST['user_login'], '@')) {
		/* limit on pwd reset using user name */
		$limit_username = limit_login_option('pwd_reset_username_limit');

		/* use lowest limit */
		if (is_null($limit) || $limit > $limit_username) {
			$limit = $limit_username;
		}
	}

	if (is_null($limit)) {
		/* Current reset not limited */
		return $b;
	}

	/* Test if user have this level */
	if (!limit_login_user_has_level($userid, $limit)) {
		return $b;
	}

	/* Not allowed -- use same error as retrieve_password() */
	$error = new WP_Error();
	$error->add('invalidcombo', __('<strong>ERROR</strong>: Invalid username or e-mail.', 'limit-login-attempts'));
	return $error;
}


/*
 * Notification functions
 */

/* Email notification of lockout to admin (if configured) */
function limit_login_notify_email($user) {
	$ip = limit_login_get_address();
	$retries = limit_login_get_array('retries');

	/* Check if we are at the right nr to do notification
	 * 
	 * Todo: this always sends notification on long lockout (when $retries[$ip]
	 * is reset).
	 */
	if ( isset($retries[$ip])
		 && ( ($retries[$ip] / limit_login_option('allowed_retries'))
			  % limit_login_option('notify_email_after') ) != 0 ) {
		return;
	}

	/* Format message. First current lockout duration */
	if (!isset($retries[$ip])) {
		/* longer lockout */
		$count = limit_login_option('allowed_retries')
			* limit_login_option('allowed_lockouts');
		$lockouts = limit_login_option('allowed_lockouts');
		$time = round(limit_login_option('long_duration') / 3600);
		$when = sprintf(__ngettext('%d hour', '%d hours', $time, 'limit-login-attempts'), $time);
	} else {
		/* normal lockout */
		$count = $retries[$ip];
		$lockouts = floor($count / limit_login_option('allowed_retries'));
		$time = round(limit_login_option('lockout_duration') / 60);
		$when = sprintf(__ngettext('%d minute', '%d minutes', $time, 'limit-login-attempts'), $time);
	}

	$subject = sprintf(__("[%s] Too many failed login attempts", 'limit-login-attempts')
					   , get_option('blogname'));
	$message = sprintf(__("%d failed login attempts (%d lockout(s)) from IP: %s"
						  , 'limit-login-attempts') . "\r\n\r\n"
					   , $count, $lockouts, $ip);
	if ($user != '') {
		$message .= sprintf(__("Last user attempted: %s", 'limit-login-attempts')
							 . "\r\n\r\n" , $user);
	}
	$message .= sprintf(__("IP was blocked for %s", 'limit-login-attempts'), $when);

	@wp_mail(get_option('admin_email'), $subject, $message);
}


/* Logging of lockout (if configured) */
function limit_login_notify_log($user) {
	$log = limit_login_get_array('logged');
	$ip = limit_login_get_address();

	/* can be written much simpler, if you do not mind php warnings */
	if (isset($log[$ip])) {
		if (isset($log[$ip][$user])) {	
			$log[$ip][$user]++;
		} else {
			$log[$ip][$user] = 1;
		}
	} else {
		$log[$ip] = array($user => 1);
	}
	limit_login_save_array('logged', $log);
}


/* Handle notification in event of lockout */
function limit_login_notify($user) {
	$args = explode(',', limit_login_option('lockout_notify'));

	if (empty($args)) {
		return;
	}

	foreach ($args as $mode) {
		switch (trim($mode)) {
		case 'email':
			limit_login_notify_email($user);
			break;
		case 'log':
			limit_login_notify_log($user);
			break;
		}
	}
}


/*
 * Handle (och filter) messages and errors shown
 */


/* Construct informative error message */
function limit_login_error_msg($lockout_option = 'lockouts', $msg = '') {
	$ip = limit_login_get_address();
	$lockouts = limit_login_get_array($lockout_option);

	if ($msg == '') {
		$msg = __('<strong>ERROR</strong>: Too many failed login attempts.', 'limit-login-attempts') . ' ';
	}

	if (!isset($lockouts[$ip]) || time() >= $lockouts[$ip]) {
		/* Huh? No lockout? */
		$msg .= __('Please try again later.', 'limit-login-attempts');
		return $msg;
	}

	$when = ceil(($lockouts[$ip] - time()) / 60);
	if ($when > 60) {
		$when = ceil($when / 60);
		$msg .= sprintf(__ngettext('Please try again in %d hour.', 'Please try again in %d hours.', $when, 'limit-login-attempts'), $when);
	} else {
		$msg .= sprintf(__ngettext('Please try again in %d minute.', 'Please try again in %d minutes.', $when, 'limit-login-attempts'), $when);
	}

	return $msg;
}


/* Construct retries remaining message */
function limit_login_retries_remaining_msg() {
	$ip = limit_login_get_address();
	$retries = limit_login_get_array('retries');
	$valid = limit_login_get_array('retries_valid');

	/* Should we show retries remaining? */
	if (!isset($retries[$ip]) || !isset($valid[$ip]) || time() > $valid[$ip]) {
		/* no: no valid retries */
		return '';
	}
	if (($retries[$ip] % limit_login_option('allowed_retries')) == 0 ) {
		/* no: already been locked out for these retries */
		return '';
	}

	$remaining = max((limit_login_option('allowed_retries') - ($retries[$ip] % limit_login_option('allowed_retries'))), 0);
	return sprintf(__ngettext("<strong>%d</strong> attempt remaining.", "<strong>%d</strong> attempts remaining.", $remaining, 'limit-login-attempts'), $remaining);
}


/* Return current (error) message to show, if any */
function limit_login_get_message() {
	if (!is_limit_login_ok()) {
		return limit_login_error_msg();
	}

	return limit_login_retries_remaining_msg();
}


/* Should we show errors and messages on this page? */
function should_limit_login_show_msg() {
	if (isset($_GET['key'])) {
		/* reset password */
		return false;
	}

	$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : '';

	return ( $action != 'lostpassword' && $action != 'retrievepassword'
			 && $action != 'resetpass' && $action != 'rp'
			 && $action != 'register' );
}


/* Fix up the error message before showing it */
function limit_login_fixup_error_messages($content) {
	global $limit_login_just_lockedout, $limit_login_nonempty_credentials, $limit_login_my_error_shown;

	if (!should_limit_login_show_msg()) {
		return $content;
	}

	/*
	 * During lockout we do not want to show any other error messages (like
	 * unknown user or empty password) -- unless this was the attempt that
	 * locked us out.
	 */
	if (!is_limit_login_ok() && !$limit_login_just_lockedout) {
		return limit_login_error_msg();
	}

	/*
	 * We want to filter the messages 'Invalid username' and 'Invalid password'
	 * as that is an information leak regarding user account names.
	 *
	 * Also, if there are more than one error message, put an extra <br /> tag
	 * between them.
	 */
	$msgs = explode("<br />\n", $content);

	if (strlen(end($msgs)) == 0) {
		/* remove last entry empty string */
		array_pop($msgs);
	}

	$count = count($msgs);
	$my_warn_count = $limit_login_my_error_shown ? 1 : 0;

	if ($limit_login_nonempty_credentials && $count > $my_warn_count) {
		/* Replace error message, including ours if necessary */
		$content = __('<strong>ERROR</strong>: Incorrect username or password.', 'limit-login-attempts') . "<br />\n";
		if ($limit_login_my_error_shown) {
			$content .= "<br />\n" . limit_login_get_message() . "<br />\n";
		}
		return $content;
	} elseif ($count <= 1) {
		return $content;
	}

	$new = '';
	while ($count-- > 0) {
		$new .= array_shift($msgs) . "<br />\n";
		if ($count > 0) {
			$new .= "<br />\n";
		}
	}

	return $new;
}


/* Add a message to login page when necessary */
function limit_login_add_error_message() {
	global $error, $limit_login_my_error_shown;

	if (!should_limit_login_show_msg() || $limit_login_my_error_shown) {
		return;
	}

	$msg = limit_login_get_message();

	if ($msg != '') {
		$limit_login_my_error_shown = true;
		$error .= $msg;
	}

	return;
}


/* Keep track of if user or password are empty, to filter errors correctly */
function limit_login_track_credentials($user, $password) {
	global $limit_login_nonempty_credentials;

	$limit_login_nonempty_credentials = (!empty($user) && !empty($password));
}


/* Does wordpress version support cookie option? */
function limit_login_support_cookie_option() {
	global $wp_version;
	return (version_compare($wp_version, '2.7', '>='));
}


/* Does wordpress version support password reset options? */
function limit_login_support_pwd_reset_options() {
	global $wp_version;
	return (version_compare($wp_version, '2.6.5', '>='));
}


/*
 * Handle plugin options
 */

/* Get current option value */
function limit_login_option($option_name) {
	global $limit_login_options;

	if (isset($limit_login_options[$option_name])) {
		return $limit_login_options[$option_name];
	} else {
		return null;
	}
}


/* Cast option value to correct type */
function limit_login_cast_option($name, $value) {
	global $limit_login_options;

	/* Make sure type is correct */
	if (is_bool($limit_login_options[$name])) {
		$value = !!$value;
	} elseif (is_numeric($limit_login_options[$name])) {
		$value = intval($value);
	} else {
		$value = (string) $value;
	}

	return $value;
}


/* Setup global variables from options */
function limit_login_setup_options() {
	global $limit_login_options;

	$options = get_option('limit_login_options');

	if ($options === false || !is_array($options)) {
		return;
	}

	/* Only use the options we understand */
	foreach ($limit_login_options as $name => $value) {
		if (!isset($options[$name]))
			continue;

		$limit_login_options[$name] = limit_login_cast_option($name, $options[$name]);
	}

	limit_login_sanitize_options();
}


/* Update options in db from global variable */
function limit_login_update_options() {
	global $limit_login_options;

	return update_option('limit_login_options', $limit_login_options);
}


/* Make sure the variables make sense */
function limit_login_sanitize_options() {
	global $limit_login_options;

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

	$cookies = limit_login_option('cookies')
		&& limit_login_support_cookie_option() ? true : false;

	$limit_login_options['cookies'] = $cookies;

	if ( limit_login_option('client_type') != LIMIT_LOGIN_DIRECT_ADDR
		 && limit_login_option('client_type') != LIMIT_LOGIN_PROXY_ADDR ) {
		$limit_login_options['client_type'] = LIMIT_LOGIN_DIRECT_ADDR;
	}

	$pwd_reset_func_supported = limit_login_support_pwd_reset_options();
	$pwd_reset_username = limit_login_option('disable_pwd_reset_username')
		&& $pwd_reset_func_supported;
	$pwd_reset = limit_login_option('disable_pwd_reset')
		&& $pwd_reset_func_supported;

	$limit_login_options['disable_pwd_reset_username'] = $pwd_reset_username;
	$limit_login_options['disable_pwd_reset'] = $pwd_reset;
}


/* Get stored array -- add if necessary */
function limit_login_get_array($array_name) {
	$real_array_name = 'limit_login_' . $array_name;

	$a = get_option($real_array_name);

	if ($a === false) {
		$a = array();
		add_option($real_array_name, $a);
	}

	return $a;
}


/* Store array */
function limit_login_save_array($array_name, $a) {
	$real_array_name = 'limit_login_' . $array_name;
	update_option($real_array_name, $a);
}


function limit_login_statistic_get($name) {
	global $limit_login_statistics;

	if (!isset($limit_login_statistics) || $limit_login_statistics == null) {
		$limit_login_statistics = get_option('limit_login_statistics');
		
		if ($limit_login_statistics === false) {
			$limit_login_statistics = Array();
			add_option('limit_login_statistics', $limit_login_statistics, '', 'no');
		}
	}

	return isset($limit_login_statistics[$name])
		? $limit_login_statistics[$name] : 0;
}

function limit_login_statistic_set($name, $value) {
	global $limit_login_statistics;

	$limit_login_statistics[$name] = $value;
	update_option('limit_login_statistics', $limit_login_statistics);
}

function limit_login_statistic_add($name) {
	limit_login_statistic_set($name, 1 + limit_login_statistic_get($name));
}
?>
