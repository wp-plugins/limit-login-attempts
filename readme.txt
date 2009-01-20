=== Limit Login Attempts ===
Contributors: johanee
Tags: login, security, authentication
Requires at least: 2.5
Tested up to: 2.7
Stable tag: 1.1

Limit rate of login attempts, including by way of cookies, for each IP.

== Description ==

Limit the number of login attempts possible both through normal login as well as (WordPress 2.7+) using auth cookies.

By default WordPress allows unlimited login attempts either through the login page or by sending special cookies. This allows passwords (or hashes) to be brute-force cracked with relative ease.

Limit Login Attempts blocks an Internet address from making further attempts after a specified limit on retries is reached, making a brute-force attack difficult or impossible.

Features

* Limit the number of retry attempts when logging in (for each IP). Fully customizable
* (WordPress 2.7+) Limit the number of attempts to log in using auth cookies in same way
* Informs user about remaining retries or lockout time on login page
* Optional logging, optional email notification

Of possible note: when cookie login handling is activated plugin overrides the pluggable function wp_get_current_user, which might collide with others wanting to do the same. If you know of any such plugins please contact me.

== Installation ==

1. Download and extract plugin files to a folder in your wp-content/plugin directory.
2. Activate the plugin through the WordPress admin interface.
3. Customize the settings from the options page, if desired.

== Frequently Asked Questions ==

= What do I do if I get a notice that it was unable to replace wp_get_current_user()? =

This means another plugin or modification is already replacing this pluggable function (I do not yet know of any that do). Mail me with details about your plugins and we'll sort it out.

== Screenshots ==

1. Loginscreen after failed login with retries remaining
2. Loginscreen after failed login during lockout
3. Administration interface in WordPress 2.7
4. Administration interface in WordPress 2.5


== Version History ==

* Version 1.1
	* Added translation support
	* Added Swedish translation
	* During lockout, filter out all other login errors.
	* Minor cleanups
* Version 1.0
	* Initial version
