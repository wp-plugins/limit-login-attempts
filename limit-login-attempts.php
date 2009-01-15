<?php
/*
  Plugin Name: Limit Login Attempts
  Plugin URI: http://devel.kostdoktorn.se/limit-login-attempts
  Description: Limit rate of login attempts, including by way of cookies, for each IP.
  Author: Johan Eenfeldt
  Author URI: http://devel.kostdoktorn.se
  Version: 1.1

  Copyright 2008 Johan Eenfeldt

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
 * Variables
 *
 * Assignments are for default value -- change in admin page.
 */

/* Lock out after this many tries */
$limit_login_allowed_retries = 4;

/* Lock out for this many seconds */
$limit_login_lockout_duration = 1200; // 20 minutes

/* Long lock out after this many lockouts */
$limit_login_allowed_lockouts = 4;

/* Long lock out for this many seconds */
$limit_login_long_duration = 86400; // 24 hours

/* Reset failed attempts after this many seconds */
$limit_login_valid_duration = 86400; // 24 hours

/* Also limit malformed/forged cookies?
 *
 * NOTE1: Only works in WP 2.7+, as necessary actions were added then.
 *
 * NOTE2: Overrides the pluggable function wp_get_current_user(). Will not
 *        co-exist peacefully with anyone doing the same (know any such?).
 */
$limit_login_cookies = true;

/* Notify on lockout. Values: '', 'log', 'email', 'log,email' */
$limit_login_lockout_notify = 'log';

/* Notify value checked against these in limit_login_sanitize_variables() */
$limit_login_lockout_notify_allowed = 'log,email';

/* If notify by email, do so after this number of lockouts */
$limit_login_notify_email_after = 4;

$limit_login_my_error_shown = false; /* have we shown our stuff? */
$limit_login_error_fn_exist = false; /* error replacing function */


/*
 * Startup
 */

limit_login_setup();

/* Replace wp_get_current_user() to handle login cookie lockout */
if ($limit_login_cookies && !function_exists('wp_get_current_user') ) {
	/*
	 * NOTE: overrides wp_get_current_user() when activated
	 * 
	 * Unfortunately there is no nice filter like wp_authenticate_user when
	 * handling the auth cookies.
	 */
	function wp_get_current_user() {
		global $current_user;

		if (is_limit_login_ok()) {
			get_currentuserinfo();
		} else {
			if ($current_user > 0) {
				wp_set_current_user(0);
			}
		}

		return $current_user;
	}
}


/*
 * Functions start here
 */

/* Get options and setup filters & actions */
function limit_login_setup() {
	global $limit_login_cookies;

	load_plugin_textdomain('limit-login-attempts'
						   , PLUGINDIR.'/'.dirname(plugin_basename(__FILE__)));

	limit_login_setup_options();

	if ($limit_login_cookies && function_exists('wp_get_current_user') ) {
		add_action('admin_notices', 'limit_login_pluggable_warning');
		$limit_login_cookies = false;
		$limit_login_error_fn_exist = true;
	}

	/* Filters and actions */
	add_action('wp_login_failed', 'limit_login_failed');
	if ($limit_login_cookies) {
		/* These are WP2.7+ */
		add_action('auth_cookie_bad_hash', 'limit_login_failed_cookie');
		add_action('auth_cookie_bad_username', 'limit_login_failed_cookie');
	}
	add_filter('wp_authenticate_user', 'limit_login_wp_authenticate_user', 99999, 2);
	add_action('login_head', 'limit_login_add_error_message');
	add_action('admin_menu', 'limit_login_admin_menu');
}


/* Check if it is ok to login */
function is_limit_login_ok() {
	$index = $_SERVER['REMOTE_ADDR'];

	/* lockout active? */
	$lockouts = get_option('limit_login_lockouts');
	return (!is_array($lockouts) || !isset($lockouts[$index]) || time() >= $lockouts[$index]);
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
	global $limit_login_allowed_retries, $limit_login_valid_duration, $limit_login_last_user, $limit_login_allowed_lockouts, $limit_login_long_duration;

	$index = $_SERVER['REMOTE_ADDR'];

	/* if currently locked-out, do not add to retries */
	$lockouts = get_option('limit_login_lockouts');
	if(is_array($lockouts) && isset($lockouts[$index]) && time() < $lockouts[$index]) {
		return;
	} elseif (!is_array($lockouts)) {
		$lockouts = array();
	}

	/* Get the arrays with retries and retries-valid information */
	$retries = get_option('limit_login_retries');
	$valid = get_option('limit_login_retries_valid');
	if ($retries === false) {
		$retries = array();
		add_option('limit_login_retries', $retries, '', 'no');
	}
	if ($valid === false) {
		$valid = array();
		add_option('limit_login_retries_valid', $valid, '', 'no');
	}

	/* Check validity and add one to retries */
	if (isset($retries[$index]) && isset($valid[$index]) && time() < $valid[$index]) {
		$retries[$index] ++;
	} else {
		$retries[$index] = 1;
	}
	$valid[$index] = time() + $limit_login_valid_duration;

	/* lockout? */
	if($retries[$index] % $limit_login_allowed_retries == 0) {
		global $limit_login_lockout_duration;

		/* setup lockout, reset retries as needed */
		if ($retries[$index] >= $limit_login_allowed_retries * $limit_login_allowed_lockouts) {
			/* long lockout */
			$lockouts[$index] = time() + $limit_login_long_duration;
			unset($retries[$index]);
			unset($valid[$index]);
		} else {
			/* normal lockout */
			$lockouts[$index] = time() + $limit_login_lockout_duration;
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
		$total = get_option('limit_login_lockouts_total');
		if ($total === false) {
			add_option('limit_login_lockouts_total', 1, '', 'no');
		} else {
			update_option('limit_login_lockouts_total', $total + 1);
		}
	} else {
		/* do not lockout (yet!) */
		update_option('limit_login_retries', $retries);
		update_option('limit_login_retries_valid', $valid);
	}
}


/* Clean up any old lockouts and old retries */
function limit_login_cleanup($retries = null, $lockouts = null, $valid = null) {
	global $limit_login_lockout_duration, $limit_login_allowed_retries, $limit_login_valid_duration;

	$now = time();

	$lockouts = !is_null($lockouts) ? $lockouts : get_option('limit_login_lockouts');

	/* remove old lockouts */
	if (is_array($lockouts)) {
		foreach ($lockouts as $ip => $lockout) {
			if ($lockout < $now) {
				unset($lockouts[$ip]);
			}
		}
		update_option('limit_login_lockouts', $lockouts);
	}

	/* remove retries that are no longer valid */
	$valid = !is_null($valid) ? $valid : get_option('limit_login_retries_valid');
	$retries = !is_null($retries) ? $retries : get_option('limit_login_retries');
	if (is_array($valid) && is_array($retries)) {
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

		update_option('limit_login_retries', $retries);
		update_option('limit_login_retries_valid', $valid);
	}
}


/* Email notification of lockout to admin (if configured) */
function limit_login_notify_email($user) {
	global $limit_login_allowed_retries, $limit_login_allowed_lockouts, $limit_login_lockout_duration, $limit_login_notify_email_after, $limit_login_long_duration;

	$index = $_SERVER['REMOTE_ADDR'];
	$retries = get_option('limit_login_retries');

	if (!is_array($retries)) {
		$retries = array();
	}

	/* check if we are at the right nr to do notification */
	if ( isset($retries[$index])
		 && ( ($retries[$index] / $limit_login_allowed_retries)
			  % $limit_login_notify_email_after ) != 0 ) {
		return;
	}

	if (!isset($retries[$index])) {
		$count = $limit_login_allowed_retries * $limit_login_allowed_lockouts;
		$lockouts = $limit_login_allowed_lockouts;
		$time = round($limit_login_long_duration / 3600);
		$when = sprintf(__ngettext('%d hour', '%d hours', $time, 'limit-login-attempts'), $time);
	} else {
		$count = $retries[$index];
		$lockouts = floor($count / $limit_login_allowed_retries);
		$time = round($limit_login_lockout_duration / 60);
		$when = sprintf(__ngettext('%d minute', '%d minutes', $time, 'limit-login-attempts'), $time);
	}

	$subject = sprintf(__("[%s] Too many failed login attempts", 'limit-login-attempts')
					   , get_option('blogname'));
	$message = sprintf(__("%d failed login attempts (%d lockout(s)) from IP: %s\r\n\r\n"
						  , 'limit-login-attempts')
					   , $count, $lockouts, $index);
	if ($user != '') {
		$message .= sprintf(__("Last user attempted: %s\r\n\r\n", 'limit-login-attempts')
							, $user);
	}
	$message .= sprintf(__("IP was blocked for %s", 'limit-login-attempts'), $when);

	@wp_mail(get_option('admin_email'), $subject, $message);
}


/* Logging of lockout (if configured) */
function limit_login_notify_log($user) {
	$log = get_option('limit_login_logged');
	if ($log === false) {
		$log = array($_SERVER['REMOTE_ADDR'] => array($user => 1));
		add_option('limit_login_logged', $log, '', 'no'); /* no autoload */
	} else {
		if (isset($log[$_SERVER['REMOTE_ADDR']])) {
			if (isset($log[$_SERVER['REMOTE_ADDR']][$user])) {	
				$log[$_SERVER['REMOTE_ADDR']][$user]++;
			} else {
				$log[$_SERVER['REMOTE_ADDR']][$user] = 1;
			}
		} else {
			$log[$_SERVER['REMOTE_ADDR']] = array($user => 1);
		}
		update_option('limit_login_logged', $log);
	}
}


/* Handle notification in event of lockout */
function limit_login_notify($user) {
	global $limit_login_lockout_notify;

	$args = explode(',', $limit_login_lockout_notify);

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


/* Construct informative error message */
function limit_login_error_msg() {
	$index = $_SERVER['REMOTE_ADDR'];

	$lockouts = get_option('limit_login_lockouts');


	$msg = __('<strong>ERROR</strong>: Too many failed login attempts.', 'limit-login-attempts') . ' ';

	if (!is_array($lockouts) || !isset($lockouts[$index]) || time() >= $lockouts[$index]) {
		/* Huh? No timeout active? */
		$msg .=  __('Please try again later.', 'limit-login-attempts');
		return $msg;
	}

	$when = ceil(($lockouts[$index] - time()) / 60);
	if ($when > 60) {
		$when = ceil($when / 60);
		$msg .= sprintf(__ngettext('Please try again in %d hour.', 'Please try again in %d hours.', $when, 'limit-login-attempts'), $when);
	} else {
		$msg .= sprintf(__ngettext('Please try again in %d minute.', 'Please try again in %d minutes.', $when, 'limit-login-attempts'), $when);
	}

	return $msg;
}


/* Add a message to login page when necessary */
function limit_login_add_error_message() {
	global $error, $limit_login_my_error_shown, $limit_login_allowed_retries;

	if ($limit_login_my_error_shown) {
		return;
	}

	if (!is_limit_login_ok()) {
		$error .= limit_login_error_msg();
		return;
	}

	$index = $_SERVER['REMOTE_ADDR'];

	$retries = get_option('limit_login_retries');
	$valid = get_option('limit_login_retries_valid');

	if (!is_array($retries) || !is_array($valid)) {
		return;
	}
	if (!isset($retries[$index]) || !isset($valid[$index]) || time() > $valid[$index]) {
		/* no valid retries */
		return;
	}
	if (($retries[$index] % $limit_login_allowed_retries) == 0 ) {
		/* already been locked out for these retries */
		return;
	}

	$remaining = max(($limit_login_allowed_retries - ($retries[$index] % $limit_login_allowed_retries)), 0);
	$error .= sprintf(__ngettext("<strong>%d</strong> attempt remaining.", "<strong>%d</strong> attempts remaining.", $remaining, 'limit-login-attempts'), $remaining);
}


/*
 * Admin stuff
 */

/* Does wordpress version support cookie option? */
function limit_login_support_cookie_option() {
	global $wp_version;
	return (version_compare($wp_version, '2.7', '>='));
}


/* Only change var if option exists */
function limit_login_get_option($option, &$var) {
	$a = get_option($option);

	if ($a !== false) {
		$var = $a;
	}
}


/* Setup global variables from options */
function limit_login_setup_options() {
	global $limit_login_allowed_retries, $limit_login_lockout_duration, $limit_login_valid_duration, $limit_login_cookies, $limit_login_lockout_notify, $limit_login_allowed_lockouts, $limit_login_long_duration, $limit_login_notify_email_after;

	limit_login_get_option('limit_login_allowed_retries', $limit_login_allowed_retries);
	limit_login_get_option('limit_login_lockout_duration', $limit_login_lockout_duration);
	limit_login_get_option('limit_login_valid_duration', $limit_login_valid_duration);
	limit_login_get_option('limit_login_cookies', $limit_login_cookies);
	limit_login_get_option('limit_login_lockout_notify', $limit_login_lockout_notify);
	limit_login_get_option('limit_login_allowed_lockouts', $limit_login_allowed_lockouts);
	limit_login_get_option('limit_login_long_duration', $limit_login_long_duration);
	limit_login_get_option('limit_login_notify_email_after', $limit_login_notify_email_after);

	limit_login_sanitize_variables();
}


/* Update options in db from global variables */
function limit_login_update_options() {
	global $limit_login_allowed_retries, $limit_login_lockout_duration, $limit_login_valid_duration, $limit_login_cookies, $limit_login_lockout_notify, $limit_login_allowed_lockouts, $limit_login_long_duration, $limit_login_notify_email_after;

	update_option('limit_login_allowed_retries', $limit_login_allowed_retries);
	update_option('limit_login_lockout_duration', $limit_login_lockout_duration);
	update_option('limit_login_allowed_lockouts', $limit_login_allowed_lockouts);
	update_option('limit_login_long_duration', $limit_login_long_duration);
	update_option('limit_login_valid_duration', $limit_login_valid_duration);
	update_option('limit_login_lockout_notify', $limit_login_lockout_notify);
	update_option('limit_login_notify_email_after', $limit_login_notify_email_after);
	update_option('limit_login_cookies', $limit_login_cookies ? '1' : '0');
}


/* Make sure the variables make sense */
function limit_login_sanitize_variables() {
	global $limit_login_allowed_retries, $limit_login_lockout_duration, $limit_login_valid_duration, $limit_login_cookies, $limit_login_lockout_notify, $limit_login_allowed_lockouts, $limit_login_long_duration, $limit_login_lockout_notify_allowed, $limit_login_notify_email_after;

	$limit_login_allowed_retries = max(1, intval($limit_login_allowed_retries));
	$limit_login_lockout_duration = max(1, intval($limit_login_lockout_duration));
	$limit_login_valid_duration = max(1, intval($limit_login_valid_duration));
	$limit_login_allowed_lockouts = max(1, intval($limit_login_allowed_lockouts));
	$limit_login_long_duration = max(1, intval($limit_login_long_duration));

	$limit_login_notify_email_after = max(1, intval($limit_login_notify_email_after));
	$limit_login_notify_email_after = min($limit_login_allowed_lockouts, $limit_login_notify_email_after);

	$args = explode(',', $limit_login_lockout_notify);
	$args_allowed = explode(',', $limit_login_lockout_notify_allowed);
	$new_args = array();
	foreach ($args as $a) {
		if (in_array($a, $args_allowed)) {
			$new_args[] = $a;
		}
	}
	$limit_login_lockout_notify = implode(',', $new_args);

	$limit_login_cookies = $limit_login_cookies && limit_login_support_cookie_option() ? true : false;
}


/* Warning msg if unable to replace pluggable function (used by another plugin?) */
function limit_login_pluggable_warning() {
	$msg = '<div id="message" class="error fade"><p>';
	$msg .= sprintf(__('%s is unable to replace function wp_get_current_user(). Disable plugin cookie login handling, or competing plugin.','limit-login-attempts'), '<a href=\"options-general.php?page=limit-login-attempts\">Limit Login Attempts</a> ');
	$msg .= '</p></div>';

	echo($msg);
}


/* Add admin options page */
function limit_login_admin_menu() {
	add_options_page('Limit Login Attempts', 'Limit Login Attempts', 8, 'limit-login-attempts', 'limit_login_option_page');
}


/* Show log on admin page */
function limit_login_show_log($log) {
	if (!is_array($log) || count($log) == 0) {
		return;
	}

	echo('<tr><th scope="col">' . _c("IP|Internet address", 'limit-login-attempts') . '</th><th scope="col">' . __('Tried to log in as', 'limit-login-attempts') . '</th></tr>');
	foreach ($log as $ip => $arr) {
		echo('<tr><td class="limit-login-ip">' . $ip . '</td><td class="limit-login-max">');
		$first = true;
		foreach($arr as $user => $count) {
			$count_desc = sprintf(__ngettext('%d lockout', '%d lockouts', $count, 'limit-login-attempts'), $count);
			if (!$first) {
				echo(', ' . $user . ' (' .  $count_desc . ')');
			} else {
				echo($user . ' (' .  $count_desc . ')');
			}
			$first = false;
		}
		echo('</td></tr>');
	}
}

/* Actual admin page */
function limit_login_option_page()	{	
	global $limit_login_allowed_retries, $limit_login_lockout_duration, $limit_login_valid_duration, $limit_login_cookies, $limit_login_lockout_notify, $limit_login_allowed_lockouts, $limit_login_long_duration, $limit_login_lockout_notify_allowed, $limit_login_notify_email_after;

	limit_login_cleanup();

	if (!current_user_can('manage_options')) {
		wp_die('Sorry, but you do not have permissions to change settings.');
	}
		
	/* Should we clear log? */
	if (isset($_POST['clear_log'])) {
		update_option('limit_login_logged', '');
		echo '<div id="message" class="updated fade"><p>'
			. __('Cleared IP log', 'limit-login-attempts')
			. '</p></div>';
	}
		
	/* Should we reset counter? */
	if (isset($_POST['reset_total'])) {
		update_option('limit_login_lockouts_total', 0);
		echo '<div id="message" class="updated fade"><p>'
			. __('Reset lockout count', 'limit-login-attempts')
			. '</p></div>';
	}
		
	/* Should we restore current lockouts? */
	if (isset($_POST['reset_current'])) {
		update_option('limit_login_lockouts', array());
		echo '<div id="message" class="updated fade"><p>'
			. __('Cleared current lockouts', 'limit-login-attempts')
			. '</p></div>';
	}

	/* Should we update options */
	if (isset($_POST['update_options'])) {
		$limit_login_allowed_retries = $_POST['allowed_retries'];
		$limit_login_lockout_duration = $_POST['lockout_duration'] * 60;
		$limit_login_valid_duration = $_POST['valid_duration'] * 3600;
		$limit_login_allowed_lockouts = $_POST['allowed_lockouts'];
		$limit_login_long_duration = $_POST['long_duration'] * 3600;
		$limit_login_notify_email_after = $_POST['email_after'];

		$limit_login_cookies = (isset($_POST['cookies']) && $_POST['cookies'] == '1');

		$v = array();
		if (isset($_POST['lockout_notify_log'])) {
			$v[] = 'log';
		}
		if (isset($_POST['lockout_notify_email'])) {
			$v[] = 'email';
		}
		$limit_login_lockout_notify = implode(',', $v);

		limit_login_sanitize_variables();
		limit_login_update_options();
		echo '<div id="message" class="updated fade"><p>'
			. __('Options changed', 'limit-login-attempts')
			. '</p></div>';
	}

	$lockouts_total = get_option('limit_login_lockouts_total', 0);
	$lockouts = get_option('limit_login_lockouts');
	$lockouts_now = is_array($lockouts) ? count($lockouts) : 0;

	if (!limit_login_support_cookie_option()) {
		$cookies_disabled = ' DISABLED ';
		$cookies_note = ' <br /> '
			. __('<strong>NOTE:</strong> Only works on Wordpress 2.7 or later', 'limit-login-attempts');
	} else {
		$cookies_disabled = '';
		$cookies_note = '';
	}
	$cookies_yes = $limit_login_cookies ? ' checked ' : '';
	$cookies_no = $limit_login_cookies ? '' : ' checked ';

	$v = explode(',', $limit_login_lockout_notify); 
	$log_checked = in_array('log', $v) ? ' checked ' : '';
	$email_checked = in_array('email', $v) ? ' checked ' : '';
	?>
	<div class="wrap">
	  <h2><?php echo __('Limit Login Attempts Settings','limit-login-attempts'); ?></h2>
	  <h3><?php echo __('Statistics','limit-login-attempts'); ?></h3>
	  <form action="options-general.php?page=limit-login-attempts" method="post">
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top">Total lockouts</th>
			<td>
			  <?php if ($lockouts_total > 0) { ?>
			  <input name="reset_total" value="<?php echo __('Reset Counter','limit-login-attempts'); ?>" type="submit" />
			  <?php echo sprintf(__ngettext('%d lockout since last reset', '%d lockouts since last reset', $lockouts_total, 'limit-login-attempts'), $lockouts_total); ?>
			  <?php } else { echo __('No lockouts yet','limit-login-attempts'); } ?>
			</td>
		  </tr>
		  <?php if ($lockouts_now > 0) { ?>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Active lockouts','limit-login-attempts'); ?></th>
			<td>
			  <input name="reset_current" value="<?php echo __('Restore Lockouts','limit-login-attempts'); ?>" type="submit" />
			  <?php echo sprintf(__('%d IP is currently blocked from trying to log in','limit-login-attempts'), $lockouts_now); ?> 
			</td>
		  </tr>
		  <?php } ?>
		</table>
	  </form>
	  <h3>Options</h3>
	  <form action="options-general.php?page=limit-login-attempts" method="post">
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><?php echo __('Lockout','limit-login-attempts'); ?></th>
			<td>
			  <input type="text" size="3" maxlength="4" value="<?php echo($limit_login_allowed_retries); ?>" name="allowed_retries" /> <?php echo __('allowed retries','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo($limit_login_lockout_duration/60); ?>" name="lockout_duration" /> <?php echo __('minutes lockout','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo($limit_login_allowed_lockouts); ?>" name="allowed_lockouts" /> <?php echo __('lockouts increase lockout time to','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo($limit_login_long_duration/3600); ?>" name="long_duration" /> <?php echo __('hours','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo($limit_login_valid_duration/3600); ?>" name="valid_duration" /> <?php echo __('hours until retries are reset','limit-login-attempts'); ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Handle cookie login','limit-login-attempts'); ?></th>
			<td>
			  <input type="radio" name="cookies" <?php echo $cookies_disabled . $cookies_yes; ?> value="1" /> <?php echo __('Yes','limit-login-attempts'); ?> <input type="radio" name="cookies" <?php echo $cookies_disabled . $cookies_no; ?> value="0" /> <?php echo __('No','limit-login-attempts'); ?>
			  <?php echo $cookies_note ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Notify on lockout','limit-login-attempts'); ?></th>
			<td>
			  <input type="checkbox" name="lockout_notify_log" <?php echo $log_checked; ?> value="log" /> <?php echo __('Log IP','limit-login-attempts'); ?><br />
			  <input type="checkbox" name="lockout_notify_email" <?php echo $email_checked; ?> value="email" /> <?php echo __('Email to admin after','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo($limit_login_notify_email_after); ?>" name="email_after" /> <?php echo __('lockouts','limit-login-attempts'); ?>
			</td>
		  </tr>
		</table>
		<p class="submit">
		  <input name="update_options" value="<?php echo __('Change Options','limit-login-attempts'); ?>" type="submit" />
		</p>
	  </form>
	  <?php
		$log = get_option('limit_login_logged');

		if (is_array($log) && count($log) > 0) {
	  ?>
	  <h3><?php echo __('Lockout log','limit-login-attempts'); ?></h3>
	  <form action="options-general.php?page=limit-login-attempts" method="post">
		<input type="hidden" value="true" name="clear_log" />
		<p class="submit">
		  <input name="submit" value="<?php echo __('Clear Log','limit-login-attempts'); ?>" type="submit" />
		</p>
	  </form>
	  <style type="text/css" media="screen">
		.limit-login-log th {
			font-weight: bold;
		}
		.limit-login-log td, .limit-login-log th {
			padding: 1px 5px 1px 5px;
		}
		td.limit-login-ip {
			font-family:  "Courier New", Courier, monospace;
			vertical-align: top;
		}
		td.limit-login-max {
			width: 100%;
		}
	  </style>
	  <div class="limit-login-log">
		<table class="form-table">
		  <?php limit_login_show_log($log); ?>
		</table>
	  </div>
	  <?php
		} /* if showing $log */
	  ?>

	</div>	
	<?php		
}	
?>
