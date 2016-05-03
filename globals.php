<?php
/*
  The file is part of the HOBA server.
  
  HOBA server is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  HOBA server is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.
  Copyright (C) 2016, Andrew McConachie, <andrew@depht.com>
*/
/*
 * @file globals.php
 * @brief PHP HOBA global constants, vars and functions 
 */

// Die if connection not using TLS
if(strlen($_SERVER['HTTPS']) == 0){
  error_log("HOBA: Connection not using HTTPS. Connection terminated.");
  exit(1);
}

global $chalTimeout; $chalTimeout = 200; // How many seconds are our challenges valid?
global $sig_replay_width; $sig_replay_width = $chalTimeout * 2; // This is used in crypto.php:checkChal()
global $realm; $realm = ""; // For now we don't use this
global $cookieSalt; $cookieSalt = '$5$hd93kb7wdqlkd38h'; // $5$ means use SHA-256
global $sessionTimeout; $sessionTimeout = 60*5; // seconds a session cookie is valid for
global $db; $db = Null; // Our database connection
global $alg; $alg = "0"; // We only support RSA-SHA256
global $didType; $didType = "0"; // We only support device Type ID 0
?>

