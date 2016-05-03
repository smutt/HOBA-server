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

// Prints our HTML refresher, sends HOBA headers, then exits
function printRefresher(){
  $chal = getChal(getPeer());
  
  header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $GLOBALS['chalTimeout']);
  header('HTTP/1.0 401 Unauthorized');

  print "<html>";
  print "<head>";
  print "  <meta http-equiv=\"refresh\" content=\"1;URL=index.php\"/>";
  print "  <title>";
  print "    Redirecting...";
  print "  </title>";
  print "</head>";
  print "<body>";
  print "  If you are not redirected please click <a href=\"index.php\">here</a>.";
  print "</body>";
  print "</html>";

  exit(0);
}

dbLogin();

// Test for cookie
if(isset($_COOKIE['HOBA'])){
  $dev = dbGetDeviceByCookie($_COOKIE['HOBA']);
  if($dev){
    print "Welcome user " . $dev['uName'] . " on device " . $dev['dName'];
  }else{
    printRefresher();
  }
}else{
  printRefresher();
}
dbLogout();
?>