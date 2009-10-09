=== Limit Login Attempts ===
Contributors: johanee
Tags: login, security, authentication
Requires at least: 2.5
Tested up to: 2.8.4
Stable tag: 1.4.1

Limit rate of login attempts, including by way of cookies, for each IP. (BETA VERSION)

== Description ==

THIS IS A BETA VERSION!

Limit the number of login attempts possible both through normal login as well as (WordPress 2.7+) using auth cookies.

By default WordPress allows unlimited login attempts either through the login page or by sending special cookies. This allows passwords (or hashes) to be brute-force cracked with relative ease.

Limit Login Attempts blocks an Internet address from making further attempts after a specified limit on retries is reached, making a brute-force attack difficult or impossible.

Features

* Limit the number of retry attempts when logging in (for each IP). Fully customizable
* Informs user about remaining retries or lockout time on login page
* Optional logging, optional email notification
* Handles server behind reverse proxy
* (WordPress 2.7+) Also handles attempts to log in using auth cookies
* Helps hide user login names
* Optional restriction on password reset attempts for privileged users, and rate limit new user registration

Translations: Bulgarian, Catalan, Czech, German, Norwegian, Persian, Romanian, Russian, Spanish, Swedish, Turkish

Plugin uses standard actions and filters only.

== Installation ==

1. Download and extract plugin files to a folder in your wp-content/plugin directory.
2. Activate the plugin through the WordPress admin interface.
3. Customize the settings from the options page, if desired. If your server is located behind a reverse proxy make sure to change this setting.

If you have any questions or problems please make a post here: http://wordpress.org/tags/limit-login-attempts

== Todo ==

* There is no built in way to change user login name or nicename -- split to separate plugin?
* Translations
* Test vs. 2.5
* Look through readme.txt

== Frequently Asked Questions ==

= What is this option about site connection and reverse proxy? =

A reverse proxy is a server in between the site and the Internet (perhaps handling caching or load-balancing). This makes getting the correct client IP to block slightly more complicated.

The option default to NOT being behind a proxy -- which should be by far the common case.

= How do I know if my site is behind a reverse proxy? =

You probably are not or you would know. We show a pretty good guess on the option page. Set the option using this unless you are sure you know better.

= I locked myself out testing this thing, what do I do? =

Either wait, or:

If you have ftp / ssh access to the site rename the file "wp-content/plugins/limit-login-attempts/limit-login-attempts.php" to deactivate the plugin.

If you have access to the database (for example through phpMyAdmin) you can clear the limit_login_lockouts option in the wordpress options table. In a default setup this would work: "UPDATE wp_options SET option_value = '' WHERE option_name = 'limit_login_lockouts'"

= Why the privileged users list? Why are some names marked? =

These are the various names WordPress has for each user. To increase security the login name should not be the same as any of the others.

= What is URL Name / "nicename"? =

"Nicename" is what WordPress calls it (internally). It is constructed directly from the login name and is used in the public author url (among other things).

= I disabled password reset for administrators and forgot my password, what do I do? =

If you have ftp / ssh access look at the answer regarding being locked out above.

If you have access to the database (for example through phpMyAdmin) you can clear the limit_login_reset_min_role option in the wordpress options table. In a default setup this would work: "UPDATE wp_options SET option_value = '' WHERE option_name = 'limit_login_reset_min_role'"

== Screenshots ==

1. Loginscreen after failed login with retries remaining
2. Loginscreen during lockout
3. Administration interface in WordPress 2.7
4. Administration interface in WordPress 2.5

== Version History ==

* Version 2.0beta3
	* Checkpoint release for translations
	* Added basic functionality to edit user names
	* Added Wordpress version dependency for password reset functionality
	* Code clean-ups
* Version 2.0beta2
	* Various fixes
* Version 2.0beta1
	* Added a number of options that when activated make it harder to find login names of users
		* disable password reset using username (accept user email only) for users with a specified role or higher
		* disable password reset for users with a specified role or higher
		* restrict rate of new user registrations
		* filter registration error messages to avoid possible way to brute force find user login name
		* list of privileged users show which login names can be discovered from user displayname, nickname or "url name"/nicename
* Version 1.4.1
	* Added Turkish translation, thanks to Yazan Canarkadas
* Version 1.4
	* Protect admin page update using wp_nonce
	* Added Czech translation, thanks to Jakub Jedelsky
* Version 1.3.2
	* Added Bulgarian translation, thanks to Hristo Chakarov
	* Added Norwegian translation, thanks to Rune Gulbrandsøy
	* Added Spanish translation, thanks to Marcelo Pedra
	* Added Persian translation, thanks to Mostafa Soufi
	* Added Russian translation, thanks to Jack Leonid (http://studio-xl.com)
* Version 1.3.1
	* Added Catalan translation, thanks to Robert Buj
	* Added Romanian translation, thanks to Robert Tudor
* Version 1.3
	* Support for getting the correct IP for clients while server is behind reverse proxy, thanks to Michael Skerwiderski
	* Added German translation, thanks to Michael Skerwiderski
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
