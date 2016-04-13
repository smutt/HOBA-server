<?php
/*
 * @file globals.php
 * @brief PHP HOBA global constants, vars and functions 
 */
/* 
 * HOBA - No Password HTTP Authentication
 *
 * Copyright (C) 2015, Andrew McConachie
 *
 * Andrew McConachie <smutt@depht.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 *
 */

global $chalTimeout; $chalTimeout = 200; // How many seconds are our challenges valid?
global $sig_replay_width; $sig_replay_width = $chalTimeout * 2; // This is used in challenge.php:checkChal()
global $realm; $realm = ""; // For now we don't use this
global $cookieSalt; $cookieSalt = '$5$hd93kb7wdqlkd38h'; // $5$ means use SHA-256
global $sessionTimeout; $sessionTimeout = 60*60; // seconds a session cookie is valid for
global $db; $db = Null; // Our database connection
?>

