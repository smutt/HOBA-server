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

include_once 'globals.php';
include_once 'db.php';
include_once 'crypto.php';
include_once 'printers.php';

dbLogin();

// Test for cookie
if(isset($_COOKIE['HOBA'])){
  error_log("Goot cookie for " . $_COOKIE['HOBA']);
  $dev = dbGetDeviceByCookie($_COOKIE['HOBA']);
  if($dev){
    error_log("Got devID for " . $dev['did']);
    printHeader();
    print "Welcome user " . $dev['uName'] . " on device " . $dev['dName'];
    printFooter();
  }else{
    printRefresher();
  }
}else{
  printRefresher();
}
dbLogout();
?>