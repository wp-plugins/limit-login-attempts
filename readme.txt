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

Note: Cookie handling reimplemented without replacing pluggable function. Plugin now using standard actions and filters only.

== Installation ==

1. Download and extract plugin files to a folder in your wp-content/plugin directory.
2. Activate the plugin through the WordPress admin interface.
3. Customize the settings from the options page, if desired.

If you have any questions or problems please make a post here: http://wordpress.org/tags/limit-login-attempts

== Screenshots ==

1. Loginscreen after failed login with retries remaining
2. Loginscreen during lockout
3. Administration interface in WordPress 2.7
4. Administration interface in WordPress 2.5

== Version History ==

* Version 1.2
	* No longer replaces pluggable function when cookie handling active. Re-implemented using available actions and filters
	* Filter error messages during login to avoid information leak regarding available usernames
	* Do not show retries or lockout messages except for login (registration, lost password pages). No change in actual enforcement
	* Slightly more aggressive in trimming old retries data
* Version 1.1
	* Added translation support
	* Added Swedish translation
	* During lockout, filter out all other login errors
	* Minor cleanups
* Version 1.0
	* Initial version
