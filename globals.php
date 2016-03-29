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

global $db; $db = Null; // Our global database connection instance
global $chalTimeout; $chalTimeout = 200; // How many seconds are our challenges valid?
global $sig_replay_width; $sig_replay_width = $chalTimeout * 2; // This is used in challenge.php:checkChal()
global $realm; $realm = ""; // For now we don't use this
?>

