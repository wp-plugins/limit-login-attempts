<?php
/*
  Limit Login Attempts: admin functions
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

define('LIMIT_LOGIN_OPTION_PAGE', 'options-general.php?page=limit-login-attempts');

/* Check if we need to warn about upgrading */
if (!limit_login_v2x_options_exists()) {
}

/* Add settings to plugin action links */
function limit_login_filter_plugin_actions($links, $file) {
	static $this_plugin;

	if(!isset($this_plugin))
		$this_plugin = str_replace('-admin', '', plugin_basename(__FILE__));

	if($file == $this_plugin) {
		$settings_link = '<a href="' . LIMIT_LOGIN_OPTION_PAGE . '">'
			. __('Settings', 'limit-login-attempts') . '</a>';
		array_unshift( $links, $settings_link ); // before other links
	}

	return $links;
}

/*
 * Admin functions
 */

/* Check if 2.x style options exists */
function limit_login_v2x_options_exists() {
	return !(get_option('limit_login_options') === false);
}



/* Add admin options page */
function limit_login_admin_menu() {
	add_options_page('Limit Login Attempts', 'Limit Login Attempts', 8, 'limit-login-attempts', 'limit_login_option_page');

	if ( $_GET['page'] == "limit-login-attempts" ) {	
		wp_enqueue_script('jquery');
	}
}


/* Make a guess if we are behind a proxy or not */
function limit_login_guess_proxy() {
	return isset($_SERVER[LIMIT_LOGIN_PROXY_ADDR])
		? LIMIT_LOGIN_PROXY_ADDR : LIMIT_LOGIN_DIRECT_ADDR;
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


/* Remove space and - characters before comparing (because of how user_nicename
 * is constructed from user_login) */
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

		if (!($login_ok && $display_ok && $nicename_ok && $nickname_ok)) {
			$bad_count++;
		}

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


/* Update user nicenames from _POST values. Dangerous stuff! Make sure to check
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

	if (!empty($changed)) {
		echo '<div id="message" class="updated fade"><p>'
			. __('URL names changed', 'limit-login-attempts')
			. '<br />' . $changed
			. '</p></div>';
	} else {
		echo '<div id="message" class="updated fade"><p>'
			. __('No names changed', 'limit-login-attempts')
			. '</p></div>';
	}
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


/* Get options from $_POST[] and update global options variable */
function limit_login_get_options_from_post() {
	global $limit_login_options;

	$option_multiple =
		array('lockout_duration' => 60, 'valid_duration' => 3600
			  , 'long_duration' => 3600, 'register_duration' => 3600);

	foreach ($limit_login_options as $name => $oldvalue) {
		if (is_bool($oldvalue)) {
			$value = isset($_POST[$name]) && $_POST[$name] == '1';
		} else {
			if (!isset($_POST[$name])) {
				continue;
			}

			$value = $_POST[$name];
			if (is_numeric($oldvalue)) {
				$value = intval($value);
			}
			if (array_key_exists($name, $option_multiple)) {
				$value = $value * $option_multiple[$name];
			}
		}

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
}


/* Actual admin page */
function limit_login_option_page()	{	
	limit_login_cleanup();

	if (!current_user_can('manage_options')) {
		wp_die('Sorry, but you do not have permissions to change settings.');
	}

	/* Make sure post was from this page */
	if (count($_POST) > 0) {
		check_admin_referer('limit-login-attempts-options');
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
		
	/* Should we reset registration counter? */
	if (isset($_POST['reset_reg_total'])) {
		update_option('limit_login_reg_lockouts_total', 0);
		echo '<div id="message" class="updated fade"><p>'
			. __('Reset registration lockout count', 'limit-login-attempts')
			. '</p></div>';
	}

	/* Should we restore current registration lockouts? */
	if (isset($_POST['reset_reg_current'])) {
		update_option('limit_login_registrations', array());
		update_option('limit_login_registrations_valid', array());
		echo '<div id="message" class="updated fade"><p>'
			. __('Cleared current registration lockouts', 'limit-login-attempts')
			. '</p></div>';
	}

	/* Should we update options? */
	if (isset($_POST['update_options'])) {
		limit_login_get_options_from_post();
		limit_login_sanitize_options();
		limit_login_update_options();
		echo '<div id="message" class="updated fade"><p>'
			. __('Options changed', 'limit-login-attempts')
			. '</p></div>';
	}

	/* Should we change user nicenames?? */
	if (isset($_POST['users_submit'])) {
		limit_login_nicenames_from_post();
	}

	$lockouts_total = limit_login_statistic_get('lockouts_total');
	$lockouts_now = count(limit_login_get_array('lockouts'));
	$reg_lockouts_total = limit_login_statistic_get('reg_lockouts_total');
	$reg_lockouts_now = limit_login_count_reg_lockouts();

	if (!limit_login_support_cookie_option()) {
		$cookies_disabled = ' DISABLED ';
		$cookies_note = ' <br /> '
			. sprintf(__('<strong>NOTE:</strong> Only works in Wordpress %s or later'
						 , 'limit-login-attempts'), '2.7');
	} else {
		$cookies_disabled = '';
		$cookies_note = '';
	}
	$cookies_yes = limit_login_option('cookies') ? ' checked ' : '';

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

	$v = explode(',', limit_login_option('lockout_notify')); 
	$log_checked = in_array('log', $v) ? ' checked ' : '';
	$email_checked = in_array('email', $v) ? ' checked ' : '';


	if (!limit_login_support_pwd_reset_options()) {
		$pwd_reset_options_disabled = ' DISABLED ';
		$pwd_reset_options_note = ' <br /> '
			. sprintf(__('<strong>NOTE:</strong> Only works in Wordpress %s or later'
						 , 'limit-login-attempts'), '2.6.5');
	} else {
		$pwd_reset_options_disabled = '';
		$pwd_reset_options_note = '';
	}

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
			padding: 0;
		}
		.limit-login td {
			font-size: 11px;
			line-height: 12px;
			padding: 1px 5px 1px 0;
		}
		td.limit-login-ip {
			font-family:  "Courier New", Courier, monospace;
			vertical-align: top;
		}
		td.limit-login-max {
			width: 100%;
		}
	</style>
	<div class="wrap">
	  <h2><?php echo __('Limit Login Attempts Settings','limit-login-attempts'); ?></h2>
	  <h3><?php echo __('Statistics','limit-login-attempts'); ?></h3>
	  <form action="<?php echo LIMIT_LOGIN_OPTION_PAGE; ?>" method="post">
		<?php wp_nonce_field('limit-login-attempts-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><?php echo __('Total lockouts','limit-login-attempts'); ?></th>
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
		  <?php if ($reg_lockouts_total > 0) { ?>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Total registration lockouts','limit-login-attempts'); ?></th>
			<td>
			  <input name="reset_reg_total" value="<?php echo __('Reset Counter','limit-login-attempts'); ?>" type="submit" />
			  <?php echo sprintf(__ngettext('%d registration lockout since last reset', '%d registration lockouts since last reset', $reg_lockouts_total, 'limit-login-attempts'), $reg_lockouts_total); ?>
			</td>
		  </tr>
		  <?php } ?>
		  <?php if ($reg_lockouts_now > 0) { ?>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Active registration lockouts','limit-login-attempts'); ?></th>
			<td>
			  <input name="reset_reg_current" value="<?php echo __('Restore Lockouts','limit-login-attempts'); ?>" type="submit" />
			  <?php echo sprintf(__('%d IP is currently blocked from registering new users','limit-login-attempts'), $reg_lockouts_now); ?> 
			</td>
		  </tr>
		  <?php } ?>
		</table>
	  </form>
	  <h3><?php echo __('Options','limit-login-attempts'); ?></h3>
	  <form action="<?php echo LIMIT_LOGIN_OPTION_PAGE; ?>" method="post">
		<?php wp_nonce_field('limit-login-attempts-options'); ?>
	    <table class="form-table">
		  <tr>
			<th scope="row" valign="top"><?php echo __('Lockout','limit-login-attempts'); ?></th>
			<td>
			  <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('allowed_retries')); ?>" name="allowed_retries" /> <?php echo __('allowed retries','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('lockout_duration')/60); ?>" name="lockout_duration" /> <?php echo __('minutes lockout','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('allowed_lockouts')); ?>" name="allowed_lockouts" /> <?php echo __('lockouts increase lockout time to','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('long_duration')/3600); ?>" name="long_duration" /> <?php echo __('hours','limit-login-attempts'); ?> <br />
			  <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('valid_duration')/3600); ?>" name="valid_duration" /> <?php echo __('hours until retries are reset','limit-login-attempts'); ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('User cookie login','limit-login-attempts'); ?></th>
			<td>
			  <label><input type="checkbox" name="cookies" <?php echo $cookies_disabled . $cookies_yes; ?> value="1" /> <?php echo __('Handle cookie login','limit-login-attempts'); ?></label>
			  <?php echo $cookies_note ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Site connection','limit-login-attempts'); ?></th>
			<td>
			  <?php echo $client_type_message; ?>
			  <label>
				<input type="radio" name="client_type" 
					   <?php echo $client_type_direct; ?> value="<?php echo LIMIT_LOGIN_DIRECT_ADDR; ?>" /> 
					   <?php echo __('Direct connection','limit-login-attempts'); ?> 
			  </label>
			  <label>
				<input type="radio" name="client_type" 
					   <?php echo $client_type_proxy; ?> value="<?php echo LIMIT_LOGIN_PROXY_ADDR; ?>" /> 
				  <?php echo __('From behind a reversy proxy','limit-login-attempts'); ?>
			  </label>
			  <?php echo $client_type_warning; ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Notify on lockout','limit-login-attempts'); ?></th>
			<td>
			  <input type="checkbox" name="lockout_notify_log" <?php echo $log_checked; ?> value="log" /> <?php echo __('Log IP','limit-login-attempts'); ?><br />
			  <input type="checkbox" name="lockout_notify_email" <?php echo $email_checked; ?> value="email" /> <?php echo __('Email to admin after','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('notify_email_after')); ?>" name="email_after" /> <?php echo __('lockouts','limit-login-attempts'); ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('Password reset','limit-login-attempts'); ?></th>
			<td>						
			  <label><input type="checkbox" name="disable_pwd_reset_username" <?php echo $pwd_reset_options_disabled . $disable_pwd_reset_username_yes; ?> value="1" /> <?php echo __('Disable password reset using login name for user this level or higher','limit-login-attempts'); ?></label> <select name="pwd_reset_username_limit" <?php echo $pwd_reset_options_disabled; ?> ><?php limit_login_select_level(limit_login_option('pwd_reset_username_limit')); ?></select>
			  <br />
			  <label><input type="checkbox" name="disable_pwd_reset" <?php echo $pwd_reset_options_disabled . $disable_pwd_reset_yes; ?> value="1" /> <?php echo __('Disable password reset for users this level or higher','limit-login-attempts'); ?></label> <select name="pwd_reset_limit" <?php echo $pwd_reset_options_disabled; ?> ><?php limit_login_select_level(limit_login_option('pwd_reset_limit')); ?></select>
			  <?php echo $pwd_reset_options_note; ?>
			</td>
		  </tr>
		  <tr>
			<th scope="row" valign="top"><?php echo __('New user registration','limit-login-attempts'); ?></th>
			<td>
			  <input type="checkbox" name="register_enforce" <?php echo $register_enforce_yes; ?> value="1" /> <?php echo __('Only allow','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('register_allowed')); ?>" name="register_allowed" /> <?php echo __('new user registrations every','limit-login-attempts'); ?> <input type="text" size="3" maxlength="4" value="<?php echo(limit_login_option('register_duration')/3600); ?>" name="register_duration" /> <?php echo __('hours','limit-login-attempts'); ?>
			</td>
		  </tr>
		</table>
		<p class="submit">
		  <input name="update_options" value="<?php echo __('Change Options','limit-login-attempts'); ?>" type="submit" />
		</p>
	  </form>
	  <h3><?php echo __('Privileged users','limit-login-attempts'); ?></h3>
	  <form action="<?php echo LIMIT_LOGIN_OPTION_PAGE; ?>" method="post" name="form_users">
		<?php wp_nonce_field('limit-login-attempts-options'); ?>

		<?php limit_login_show_users(); ?>
		<div class="tablenav actions">
		  <input type="checkbox" id="warning_checkbox" name="warning_danger" value="1" name="users_warning_check" /> <?php echo sprintf(__('I <a href="%s">understand</a> the problems involved', 'limit-login-attempts'), 'http://wordpress.org/extend/plugins/limit-login-attempts/faq/'); ?></a> <input type="submit" class="button-secondary action warning-disabled" value="<?php echo __('Change Names', 'limit-login-attempts'); ?>" name="users_submit" disabled="true" />
		</div>
	  </form>
	  <?php
		$log = limit_login_get_array('logged');

		if (is_array($log) && count($log) > 0) {
	  ?>
	  <h3><?php echo __('Lockout log','limit-login-attempts'); ?></h3>
	  <div class="limit-login">
		<table>
		  <?php limit_login_show_log($log); ?>
		</table>
	  </div>
	  <form action="<?php echo LIMIT_LOGIN_OPTION_PAGE; ?>" method="post">
		<?php wp_nonce_field('limit-login-attempts-options'); ?>
		<input type="hidden" value="true" name="clear_log" />
		<p class="submit">
		  <input name="submit" value="<?php echo __('Clear Log','limit-login-attempts'); ?>" type="submit" />
		</p>
	  </form>
	  <?php
		} /* if showing $log */
	  ?>
	</div>	
	<?php		
}
?>