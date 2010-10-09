<?php
/*
  Limit Login Attempts: admin functions
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
 * Variables
 *
 * This file is included in function context. This means that global variables
 * have to be defined with $GLOBALS.
 */

/* Options page name */
$GLOBALS['limit_login_option_page'] = admin_url('options-general.php?page=limit-login-attempts');

/* Level of the different roles. Used for descriptive purposes only */
$GLOBALS['limit_login_level_role'] =
	array(0 => __('Subscriber','limit-login-attempts')
	      , 1 => __('Contributor','limit-login-attempts')
	      , 2 => __('Author','limit-login-attempts')
	      , 7 => __('Editor','limit-login-attempts')
	      , 10 => __('Administrator','limit-login-attempts'));


/*
 * Admin functions
 */

/* Add admin options page */
function limit_login_admin_menu() {
	add_options_page('Limit Login Attempts', 'Limit Login Attempts', 8, 'limit-login-attempts', 'limit_login_option_page');

	if ( isset($_GET['page'])
		 && 	$_GET['page'] == "limit-login-attempts" ) {	
		wp_enqueue_script('jquery');
	}
}


/* Add settings to plugin action links */
function limit_login_filter_plugin_actions($links, $file) {
	global $limit_login_option_page;
	static $this_plugin;

	if(!isset($this_plugin))
		$this_plugin = str_replace('-admin', '', plugin_basename(__FILE__));

	if($file == $this_plugin) {
		$settings_link = '<a href="' . $limit_login_option_page . '">'
			. __('Settings', 'limit-login-attempts') . '</a>';
		array_unshift( $links, $settings_link ); // before other links
	}

	return $links;
}


/* Display information on dashboard */
function limit_login_dashboard_info() {
	global $limit_login_option_page;

	$plugin_link = '<a href="' . $limit_login_option_page . '">'
		. __('Limit Login Attempts', 'limit-login-attempts')
		. '</a> ';
	$msg = sprintf(__('%s lockouts:', 'limit-login-attempts'), $plugin_link);
	$msg .= ' ' . limit_login_format_statistic_info(limit_login_statistic_get_info('lockouts_total'));

	echo '<p>' . $msg . '</p>';
}



/* Are we behind a proxy or not? Make a guess! */
function limit_login_guess_proxy() {
	return isset($_SERVER[LIMIT_LOGIN_PROXY_ADDR])
		? LIMIT_LOGIN_PROXY_ADDR : LIMIT_LOGIN_DIRECT_ADDR;
}


/* Format time value as date (with 0 being undefined) */
function limit_login_format_date($time, $format = 'long', $undefined = '-') {
	switch ($format)  {
	case 'long':
		$format = 'Y-m-d H:i:s';
		break;
	case 'short':
		$format = 'Y-m-d';
		break;
	default:
		// keep $format as format string
	}

	return $time > 0 ? date($format, $time) : $undefined;
}


/* Show log on admin page */
function limit_login_show_log($log) {
	if (!is_array($log) || count($log) == 0) {
		return;
	}

	echo('<tr><th scope="col">' . _c("IP|Internet address", 'limit-login-attempts') . '</th>'
	     . '<th scope="col">' . __('Last lockout', 'limit-login-attempts') . '</th>'
	     . '<th scope="col">' . __('Tried to log in as', 'limit-login-attempts') . '</th></tr>');
	foreach ($log as $ip => $iplog) {
		/*
		 * Look at limit_login_notify_log() for more details on format
		 */
		$last_attempt = limit_login_format_date($iplog[0]);
		$arr = $iplog[1];

		echo('<tr><td class="limit-login-ip">' . $ip . '</td>'
		     . '<td class="limit-login-date">' . $last_attempt .'</td>'
		     . '<td class="limit-login-max">');
		$first = true;
		foreach($arr as $user => $count) {
			$count_desc = sprintf(__ngettext('%d lockout', '%d lockouts', $count, 'limit-login-attempts'), $count);
			if (!$first)
				echo(', ' . $user . ' (' .  $count_desc . ')');
			else
				echo($user . ' (' .  $count_desc . ')');

			$first = false;
		}
		echo('</td></tr>');
	}
}


/*
 * Fuzzy compare of strings:
 * Remove space and - characters before comparing (because of how user_nicename
 * is constructed from user_login)
 */
function limit_login_fuzzy_cmp($s1, $s2) {
	$remove = array(' ', '-');

	return strcasecmp(str_replace($remove, '', $s1), str_replace($remove, '', $s2));
}


/* Show privileged users various names, and warn if equal to login name */
function limit_login_show_users() {
	global $wpdb;

	/*
	 * Scary-looking query! We want to get the various user names of all users
	 * that have privileges: !subsciber & !unapproved
	 *
	 * We join the users table twice with the usermeta table. This is so we
	 * can filter against capabilities while getting nickname.
	 */
	$sql = "SELECT u.ID, u.user_login, u.user_nicename, u.display_name"
		. " , um.meta_value AS role, um2.meta_value AS nickname"
		. " FROM $wpdb->users u"
		. " INNER JOIN $wpdb->usermeta um ON u.ID = um.user_id"
		. " LEFT JOIN $wpdb->usermeta um2 ON u.ID = um2.user_id"
		. " WHERE um.meta_key = '{$wpdb->prefix}capabilities'"
		. " AND NOT (um.meta_value LIKE '%subscriber%'"
		. "          OR um.meta_value LIKE '%unapproved%')"
		. " AND um2.meta_key = 'nickname'";

	$users = $wpdb->get_results($sql);

	if (!$users || count($users) == 0) {
		return;
	}

	$r = '';
	$bad_count = 0;
	foreach ($users as $user) {
		/*
		 * We'll warn if:
		 * - user login name is 'admin' (WordPress default value)
		 * - any visible user name is the same as user login name
		 */
		$login_ok = limit_login_fuzzy_cmp($user->user_login, 'admin');
		$display_ok = limit_login_fuzzy_cmp($user->user_login, $user->display_name);
		$nicename_ok = limit_login_fuzzy_cmp($user->user_login, $user->user_nicename);
		$nickname_ok = limit_login_fuzzy_cmp($user->user_login, $user->nickname);

		if (!($login_ok && $display_ok && $nicename_ok && $nickname_ok))
			$bad_count++;

		$edit = "user-edit.php?user_id={$user->ID}";
		$nicename_input = '<input type="text" size="20" maxlength="45"'
			. " value=\"{$user->user_nicename}\" name=\"nicename-{$user->ID}\""
			. ' class="warning-disabled" disabled="true" />';

		$role = implode(',', array_keys(maybe_unserialize($user->role)));
		$login = limit_login_show_maybe_warning(!$login_ok, $user->user_login, $edit
					, __("Account named admin should not have privileges", 'limit-login-attempts'));
		$display = limit_login_show_maybe_warning(!$display_ok, $user->display_name, $edit
					, __("Make display name different from login name", 'limit-login-attempts'));
		$nicename = limit_login_show_maybe_warning(!$nicename_ok, $nicename_input, ''
					, __("Make url name different from login name", 'limit-login-attempts'));
		$nickname = limit_login_show_maybe_warning(!$nickname_ok, $user->nickname, $edit
					, __("Make nickname different from login name", 'limit-login-attempts'));

		$r .= '<tr><td>' . $edit_link . $login . '</a></td>'
			. '<td>' . $role . '</td>'
			. '<td>' . $display . '</td>'
			. '<td>' . $nicename . '</td>'
			. '<td>' . $nickname . '</td>'
			. '</tr>';
	}

	if (!$bad_count) {
		echo(sprintf('<p><i>%s</i></p>'
			     , __("Privileged usernames, display names, url names and nicknames are ok", 'limit-login-attempts')));
	}

	echo('<table class="widefat"><thead><tr class="thead">' 
		 . '<th scope="col">'
		 . __("User Login", 'limit-login-attempts')
		 . '</th><th scope="col">'
		 . __('Role', 'limit-login-attempts')
		 . '</th><th scope="col">'
		 . __('Display Name', 'limit-login-attempts')
		 . '</th><th scope="col">'
		 . __('URL Name <small>("nicename")</small>', 'limit-login-attempts')
		 . ' <a href="http://wordpress.org/extend/plugins/limit-login-attempts/faq/"'
		 . ' title="' . __('What is this?', 'limit-login-attempts') . '">?</a>'
		 . '</th><th scope="col">'
		 . __('Nickname', 'limit-login-attempts')
		 . '</th></tr></thead>'
		 . $r
		 . '</table>');
}


/* Format username in list (in limit_login_show_users()) */
function limit_login_show_maybe_warning($is_warn, $name, $edit_url, $title) {
	static $alt, $bad_img_url;

	if (!$is_warn) {
		return $name;
	}

	if (empty($alt)) {
		$alt = __("bad name", 'limit-login-attempts');
	}

	if (empty($bad_img_url)) {
		if ( !defined('WP_PLUGIN_URL') )
			$plugin_url = get_option('siteurl') . '/wp-content/plugins';
		else
			$plugin_url = WP_PLUGIN_URL;

		$plugin_url .= '/' . dirname(plugin_basename(__FILE__));

		$bad_img_url = $plugin_url . '/images/icon_bad.gif';
	}

	$s = "<img src=\"$bad_img_url\" alt=\"$alt\" title=\"$title\" />";
	if (!empty($edit_url))
		$s .= "<a href=\"$edit_url\" title=\"$title\">";
	$s .= $name;
	if (!empty($edit_url))
		$s .= '</a>';

	return $s;
}


/*
 * Update user nicenames from _POST values. Dangerous stuff! Make sure to check
 * privileges and security before calling function.
 */
function limit_login_nicenames_from_post() {
	static $match = 'nicename-'; /* followed by user id */
	$changed = '';

	foreach ($_POST as $name => $val) {
		if (strncmp($name, $match, strlen($match)))
			continue;

		/* Get user ID */
		$a = explode('-', $name);
		$id = intval($a[1]);
		if (!$id)
			continue;

		/*
		 * To be safe we use the same functions as when an original nicename is
		 * constructed from user login name.
		 */
		$nicename = sanitize_title(sanitize_user($val, true));

		if (empty($nicename))
			continue;

		/* Check against original user */
		$user = get_userdata($id);

		if (!$user)
			continue;

		/* nicename changed? */
		if (!strcmp($nicename, $user->user_nicename))
			continue;

		$userdata = array('ID' => $id, 'user_nicename' => $nicename);
		wp_update_user($userdata);

		wp_cache_delete($user->user_nicename, 'userlugs');

		if (!empty($changed))
			$changed .= ', ';
		$changed .= "'{$user->user_login}' nicename {$user->user_nicename} => $nicename";
	}

	if (!empty($changed))
		$msg = __('URL names changed', 'limit-login-attempts') . '<br />' . $changed;
	else
		$msg = __('No names changed', 'limit-login-attempts');

	limit_login_admin_message($msg);
}


/* Count ip currently locked out from registering new users */
function limit_login_count_reg_lockouts() {
	$valid = limit_login_get_array('registrations_valid');
	$regs = limit_login_get_array('registrations');
	$allowed = limit_login_option('register_allowed');

	$now = time();
	$total = 0;

	foreach ($valid as $ip => $until) {
		if ($until >= $now && isset($regs[$ip]) && $regs[$ip] >= $allowed)
			$total++;
	}

	return $total;
}


/* Show all role levels <select> */
function limit_login_select_level($current) {
	global $limit_login_level_role;

	for ($i = 0; $i <= 10; $i++) {
		$selected = ($i == $current) ? ' SELECTED ' : '';
		$name = (array_key_exists($i, $limit_login_level_role)) ? ' - ' . $limit_login_level_role[$i] : '';
		echo("<option value=\"$i\" $selected>$i$name</option>");
	}
}


/* Format statistic info for display */
function limit_login_format_statistic_info($info) {
	if ($info['value'] > 0 && $info['reset'] > 0 && $info['set'] > 0)
		return sprintf(__('%d since %s (latest %s)', 'limit-login-attempts')
			       , $info['value'], limit_login_format_date($info['reset'], 'short')
			       , limit_login_format_date($info['set']));
	if ($info['reset'] > 0)
		return sprintf(__('%d since %s', 'limit-login-attempts')
			       , $info['value'], limit_login_format_date($info['reset']));
}


/* Show admin page message */
function limit_login_admin_message($msg) {
	echo '<div id="message" class="updated fade"><p>' . $msg . '</p></div>';
}


/* Actual admin page */
function limit_login_option_page() {
	global $limit_login_option_page;

	limit_login_cleanup();

	if (!current_user_can('manage_options'))
		wp_die('Sorry, but you do not have permissions to change settings.');

	/* Make sure post was from this page */
	if (count($_POST) > 0)
		check_admin_referer('limit-login-attempts-options');
		
	/* Should we clear log? */
	if (isset($_POST['clear_log'])) {
		update_option('limit_login_logged', array());
		limit_login_admin_message(__('Cleared IP log', 'limit-login-attempts'));
	}
		
	/* Should we reset login lockout counter? */
	if (isset($_POST['reset_total'])) {
		limit_login_statistic_set('lockouts_total', 0, true);
		limit_login_admin_message(__('Reset lockout count', 'limit-login-attempts'));
	}

	/* Should we restore current login lockouts? */
	if (isset($_POST['reset_current'])) {
		limit_login_store_array('lockouts', array());
		limit_login_admin_message(__('Cleared current lockouts', 'limit-login-attempts'));
	}
		
	/* Should we reset registration counter? */
	if (isset($_POST['reset_reg_total'])) {
		limit_login_statistic_set('reg_lockouts_total', 0, true);
		limit_login_admin_message(__('Reset registration lockout count', 'limit-login-attempts'));
	}

	/* Should we restore current registration lockouts? */
	if (isset($_POST['reset_reg_current'])) {
		limit_login_store_array('registrations', array());
		limit_login_store_array('registrations_valid', array());
		limit_login_admin_message(__('Cleared current registration lockouts', 'limit-login-attempts'));
	}

	/* Should we update options? */
	if (isset($_POST['update_options'])) {
		limit_login_get_options_from_post();
		limit_login_admin_message(__('Options changed', 'limit-login-attempts'));
	}

	/* Should we change user nicenames?? */
	if (isset($_POST['users_submit']))
		limit_login_nicenames_from_post();

	/*
	 * Setup to show admin page
	 */

	$lockouts_info = limit_login_statistic_get_info('lockouts_total');
	$lockouts_total = $lockouts_info['value'];
	$lockouts_now = count(limit_login_get_array('lockouts'));
	$reg_lockouts_info = limit_login_statistic_get_info('reg_lockouts_total');
	$reg_lockouts_total = $reg_lockouts_info['value'];
	$reg_lockouts_now = limit_login_count_reg_lockouts();

	$client_type = limit_login_option('client_type');
	$client_type_direct = $client_type == LIMIT_LOGIN_DIRECT_ADDR ? ' checked ' : '';
	$client_type_proxy = $client_type == LIMIT_LOGIN_PROXY_ADDR ? ' checked ' : '';

	$client_type_guess = limit_login_guess_proxy();

	if ($client_type_guess == LIMIT_LOGIN_DIRECT_ADDR) {
		$client_type_message = sprintf(__('It appears the site is reached directly (from your IP: %s)','limit-login-attempts'), limit_login_get_address(LIMIT_LOGIN_DIRECT_ADDR));
	} else {
		$client_type_message = sprintf(__('It appears the site is reached through a proxy server (proxy IP: %s, your IP: %s)','limit-login-attempts'), limit_login_get_address(LIMIT_LOGIN_DIRECT_ADDR), limit_login_get_address(LIMIT_LOGIN_PROXY_ADDR));
	}
	$client_type_message .= '<br />';

	$client_type_warning = '';
	if ($client_type != $client_type_guess) {
		$faq = 'http://wordpress.org/extend/plugins/limit-login-attempts/faq/';

		$client_type_warning = '<br /><br />' . sprintf(__('<strong>Current setting appears to be invalid</strong>. Please make sure it is correct. Further information can be found <a href="%s" title="FAQ">here</a>','limit-login-attempts'), $faq);
	}

	$cookies_yes = limit_login_option('cookies') ? ' checked ' : '';

	$v = explode(',', limit_login_option('lockout_notify')); 
	$log_checked = in_array('log', $v) ? ' checked ' : '';
	$email_checked = in_array('email', $v) ? ' checked ' : '';

	$disable_pwd_reset_username_yes = limit_login_option('disable_pwd_reset_username') ? ' checked ' : '';
	$disable_pwd_reset_yes = limit_login_option('disable_pwd_reset') ? ' checked ' : '';

	$register_enforce_yes = limit_login_option('register_enforce') ? ' checked ' : '';

	?>
    <script type="text/javascript">
		 jQuery(document).ready(function(){
				 jQuery("#warning_checkbox").click(function(event){
						 if (jQuery(this).attr("checked")) {
							 jQuery("input.warning-disabled").removeAttr("disabled");
						 } else {
							 jQuery("input.warning-disabled").attr("disabled", "disabled");
						 }
					 });
			 });
    </script>
	<style type="text/css" media="screen">
		table.limit-login {
			width: 100%;
			border-collapse: collapse;
		}
		.limit-login th {
			font-size: 12px;
			font-weight: bold;
			text-align: left;
			padding: 0 5px 0 0;
		}
		.limit-login td {
			font-size: 11px;
			line-height: 12px;
			padding: 1px 5px 1px 0;
			vertical-align: top;
		}
		td.limit-login-ip {
			font-family:  "Courier New", Courier, monospace;
		}
		td.limit-login-max {
			width: 80%;
		}
	</style>
	<div class="wrap">
	  <h2><?php _e('Limit Login Attempts Settings','limit-login-attempts'); ?></h2>
	  <h3><?php _e('Statistics','limit-login-attempts'); ?></h3>
	  <form action="<?php echo $limit_login_option_page; ?>" method="post">
		<?php wp_nonce_field('limit-login-attempts-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><?php _e('Total lockouts','limit-login-attempts'); ?></th>
			<td>
			  <?php if ($lockouts_total > 0) { ?>
			  <input name="reset_total" value="<?php _e('Reset Counter','limit-login-attempts'); ?>" type="submit" />
			  <?php echo limit_login_format_statistic_info($lockouts_info); ?>
			  <?php } else { _e('No lockouts yet','limit-login-attempts'); } ?>
			</td>
		  </tr>
		  <?php if ($lockouts_now > 0) { ?>
		  <tr>
			<th scope="row" valign="top"><?php _e('Active lockouts','limit-login-attempts'); ?></th>
			<td>
			  <input name="reset_current" value="<?php _e('Restore Lockouts','limit-login-attempts'); ?>" type="submit" />
			  <?php echo sprintf(__('%d IP is currently blocked from trying to log in','limit-login-attempts'), $lockouts_now); ?> 
			</td>
		  </tr>
		  <?php } ?>
		  <?php if ($reg_lockouts_total > 0) { ?>
		  <tr>
			<th scope="row" valign="top"><?php _e('Total registration lockouts','limit-login-attempts'); ?></th>
			<td>
			  <input name="reset_reg_total" value="<?php _e('Reset Counter','limit-login-attempts'); ?>" type="submit" />
			  <?php echo limit_login_format_statistic_info($reg_lockouts_info); ?>
			</td>
		  </tr>
		  <?php } ?>
		  <?php if ($reg_lockouts_now > 0) { ?>
		  <tr>
			<th scope="row" valign="top"><?php _e('Active registration lockouts','limit-login-attempts'); ?></th>
			<td>
			  <input name="reset_reg_current" value="<?php _e('Restore Lockouts','limit-login-attempts'); ?>" type="submit" />
			  <?php echo sprintf(__('%d IP is currently blocked from registering new users','limit-login-attempts'), $reg_lockouts_now); ?> 
			</td>
		  </tr>
		  <?php } ?>
		</table>
	  </form>
	  <h3><?php _e('Options','limit-login-attempts'); ?></h3>
	  <form action="<?php echo $limit_login_option_page; ?>" method="post">
		<?php wp_nonce_field('limit-login-attempts-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><?php _e('Lockout','limit-login-attempts'); ?></th>
			<td>
			  <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('allowed_retries')); ?>" name="allowed_retries" /> <?php _e('allowed retries','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('lockout_duration')/60); ?>" name="lockout_duration" /> <?php _e('minutes lockout','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('allowed_lockouts')); ?>" name="allowed_lockouts" /> <?php _e('lockouts increase lockout time to','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('long_duration')/3600); ?>" name="long_duration" /> <?php _e('hours','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('valid_duration')/3600); ?>" name="valid_duration" /> <?php _e('hours until retries are reset','limit-login-attempts'); ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php _e('Site connection','limit-login-attempts'); ?></th>
			<td>
			  <?php echo $client_type_message; ?>
			  <label>
				<input type="radio" name="client_type" 
					   <?php echo $client_type_direct; ?> value="<?php echo LIMIT_LOGIN_DIRECT_ADDR; ?>" /> 
					   <?php _e('Direct connection','limit-login-attempts'); ?> 
			  </label>
			  <label>
				<input type="radio" name="client_type" 
					   <?php echo $client_type_proxy; ?> value="<?php echo LIMIT_LOGIN_PROXY_ADDR; ?>" /> 
				  <?php _e('From behind a reversy proxy','limit-login-attempts'); ?>
			  </label>
			  <?php echo $client_type_warning; ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"></th>
			<td>
			  <label><input type="checkbox" name="cookies" <?php echo $cookies_yes; ?> value="1" /> <?php _e('Handle cookie login','limit-login-attempts'); ?></label>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php _e('Notify on lockout','limit-login-attempts'); ?></th>
			<td>
			  <input type="checkbox" name="lockout_notify_log" <?php echo $log_checked; ?> value="log" /> <?php _e('Log IP','limit-login-attempts'); ?><br />
			  <input type="checkbox" name="lockout_notify_email" <?php echo $email_checked; ?> value="email" /> <?php _e('Email to admin after','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('notify_email_after')); ?>" name="email_after" /> <?php _e('lockouts','limit-login-attempts'); ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php _e('Password reset','limit-login-attempts'); ?></th>
			<td>						
			  <label><input type="checkbox" name="disable_pwd_reset_username" <?php echo $disable_pwd_reset_username_yes; ?> value="1" /> <?php _e('Disable password reset using login name for user this level or higher','limit-login-attempts'); ?></label> <select name="pwd_reset_username_limit"><?php limit_login_select_level(limit_login_option('pwd_reset_username_limit')); ?></select>
			  <br />
			  <label><input type="checkbox" name="disable_pwd_reset" <?php echo $disable_pwd_reset_yes; ?> value="1" /> <?php _e('Disable password reset for users this level or higher','limit-login-attempts'); ?></label> <select name="pwd_reset_limit"><?php limit_login_select_level(limit_login_option('pwd_reset_limit')); ?></select>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php _e('New user registration','limit-login-attempts'); ?></th>
			<td>
			  <input type="checkbox" name="register_enforce" <?php echo $register_enforce_yes; ?> value="1" /> <?php _e('Only allow','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('register_allowed')); ?>" name="register_allowed" /> <?php _e('new user registrations every','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('register_duration')/3600); ?>" name="register_duration" /> <?php _e('hours','limit-login-attempts'); ?>
			</td>
		  </tr>
		</table>
		<p class="submit">
		  <input name="update_options" class="button-primary" value="<?php _e('Change Options','limit-login-attempts'); ?>" type="submit" />
		</p>
	  </form>
	  <h3><?php _e('Privileged users','limit-login-attempts'); ?></h3>
	  <form action="<?php echo $limit_login_option_page; ?>" method="post" name="form_users">
		<?php wp_nonce_field('limit-login-attempts-options'); ?>

		<?php limit_login_show_users(); ?>
		<div class="tablenav actions">
		  <input type="checkbox" id="warning_checkbox" name="warning_danger" value="1" name="users_warning_check" /> <?php echo sprintf(__('I <a href="%s">understand</a> the problems involved', 'limit-login-attempts'), 'http://wordpress.org/extend/plugins/limit-login-attempts/faq/'); ?></a> <input type="submit" class="button-secondary action warning-disabled" value="<?php _e('Change Names', 'limit-login-attempts'); ?>" name="users_submit" disabled="true" />
		</div>
	  </form>
	  <?php
		$log = limit_login_get_array('logged');

		if (is_array($log) && count($log) > 0) {
	  ?>
	  <h3><?php _e('Lockout log','limit-login-attempts'); ?></h3>
	  <div class="limit-login">
		<table>
		  <?php limit_login_show_log($log); ?>
		</table>
	  </div>
	  <form action="<?php echo $limit_login_option_page; ?>" method="post">
		<?php wp_nonce_field('limit-login-attempts-options'); ?>
		<input type="hidden" value="true" name="clear_log" />
		<p class="submit">
		  <input name="submit" value="<?php _e('Clear Log','limit-login-attempts'); ?>" type="submit" />
		</p>
	  </form>
	  <?php
		} /* if showing $log */
	  ?>
	</div>	
	<?php		
}
?>