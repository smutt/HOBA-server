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

function printHeader(){
  print "\n<html>";
  print "\n<head>";
  print "\n  <title>";
  print "\n    HOBA Test ";
  print "\n  </title>";
  print "\n</head>";
  print "\n<body>";
  print "\n  <center>";
}

function printFooter(){
  print "\n  </center>";
  print "\n</body>";
  print "\n</html>";
}

// Sends HOBA headers, prints our HTML refresher, then exits
function printRefresher(){
  setcookie("HOBA_LOGIN", "attempt", time() + $GLOBALS['retryTimeout'], "/hoba/", $_SERVER['SERVER_NAME'], true, false);

  $chal = getChal(getPeer());
  header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $GLOBALS['chalTimeout']);
  header('HTTP/1.0 401 Unauthorized');

  print "\n<html>";
  print "\n<head>";
  print "\n  <meta http-equiv=\"refresh\" content=\"3;URL=index.php\"/>";
  print "\n  <title>";
  print "\n    Redirecting...";
  print "\n  </title>";
  print "\n</head>";
  print "\n<body>";
  print "\n  Processing...";
  print "\n</body>";
  print "\n</html>";

  exit(0);
}

// Takes msgs as assoc array
function printMeat($msgs){
  return false;
}

// What users see if they fail to login
function printLoginFailure(){
  printHeader();
  print "\nHOBA Login Failed: Your browser does not support HOBA, or something else broke";
  printFooter();
}
?>
