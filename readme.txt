=== Limit Login Attempts ===
Contributors: johanee
Tags: login, security, authentication
Requires at least: 2.5
Tested up to: 3.0.1
Stable tag: 1.5.1

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
* Handles server behind reverse proxy

Translations: Bulgarian, Catalan, Chinese (Traditional), Czech, Dutch, French, German, Hungarian, Norwegian, Persian, Romanian, Russian, Spanish, Swedish, Turkish

Plugin uses standard actions and filters only.

== Installation ==

1. Download and extract plugin files to a folder in your wp-content/plugin directory.
2. Activate the plugin through the WordPress admin interface.
3. Customize the settings from the options page, if desired. If your server is located behind a reverse proxy make sure to change this setting.

If you have any questions or problems please make a post here: http://wordpress.org/tags/limit-login-attempts

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

== Screenshots ==

1. Loginscreen after failed login with retries remaining
2. Loginscreen during lockout
3. Administration interface in WordPress 2.7
4. Administration interface in WordPress 2.5

== Changelog ==

= 1.5.1 =
* Further multisite & WPMU support (again thanks to <erik@erikshosting.com>)
* Better error handling if option variables are damaged
* Added Traditional Chinese translation, thanks to Denny Huang <bigexplorations@bigexplorations.com.tw>

= 1.5 =
* Tested against WordPress 3.0
* Handle 3.0 login page failure "shake"
* Basic multisite support (parts thanks to <erik@erikshosting.com>)
* Added Dutch translation, thanks to Bjorn Wijers <burobjorn@burobjorn.nl>
* Added Hungarian translation, thanks to Bálint Vereskuti <balint@vereskuti.info>
* Added French translation, thanks to oVa <ova13lastar@gmail.com>

= 1.4.1 =
* Added Turkish translation, thanks to Yazan Canarkadas

= 1.4 =
* Protect admin page update using wp_nonce
* Added Czech translation, thanks to Jakub Jedelsky

= 1.3.2 =
* Added Bulgarian translation, thanks to Hristo Chakarov
* Added Norwegian translation, thanks to Rune Gulbrandsøy
* Added Spanish translation, thanks to Marcelo Pedra
* Added Persian translation, thanks to Mostafa Soufi
* Added Russian translation, thanks to Jack Leonid (http://studio-xl.com)

= 1.3.1 =
* Added Catalan translation, thanks to Robert Buj
* Added Romanian translation, thanks to Robert Tudor

= 1.3 =
* Support for getting the correct IP for clients while server is behind reverse proxy, thanks to Michael Skerwiderski
* Added German translation, thanks to Michael Skerwiderski

= 1.2 =
* No longer replaces pluggable function when cookie handling active. Re-implemented using available actions and filters
* Filter error messages during login to avoid information leak regarding available usernames
* Do not show retries or lockout messages except for login (registration, lost password pages). No change in actual enforcement
* Slightly more aggressive in trimming old retries data

= 1.1 =
* Added translation support
* Added Swedish translation
* During lockout, filter out all other login errors
* Minor cleanups

= 1.0 =
* Initial version
