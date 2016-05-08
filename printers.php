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

include_once "db.php";

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

// Takes msgs as assoc array
function printMeat($dev){
  $msgs = dbGetMsgs($GLOBALS['numMsgs']);

  // Build our side column
  $side = array();
  array_push($side, "\n<td></td>");
  array_push($side, "\n<td><center>" . $dev['uName'] . "</center></td>");
  array_push($side, "\n<td></td>");
  array_push($side, "\n<td></td>");
  array_push($side, "\n<td rowspan='3'><center><form action='index.php' method='POST'><input type='text' name='uName'><br/>\n
             <input type='submit' name='changeUser' value='Change User Name'></center></td>");

  print "\n<table>";
  print "\n<tr><td><img src='hoba-stamp.jpg' height='150' width='200'></td>";
  print "\n<td><center><h4>Leave a Message</h4></center></td>";
  print "\n<td colspan='2'><center><h4>Bond You Devices</h4></center></td></tr>";
  
  for($ii=0; $ii < $GLOBALS['numMsgs']; $ii++){
    if(isset($side[$ii]) || isset($msgs[$ii])){
      print "\n<tr>";
    }
    
    if(isset($side[$ii])){
      print $side[$ii];
    }
        
    if(isset($msgs[$ii])){
      print "\n<td>" . $msgs[$ii]['message'] . "</td>";
      print "\n<td>" . $msgs[$ii]['uName'] . "</td>";
      if($dev['uid'] != $msgs[$ii]['uid']){
        print "\n<td><form action='index.php' method='POST'><input type='submit' name='bondUser' value='Bond " . $msgs[$ii]['uName'] . "'></td>";
      }
      print "\n</tr>";
    }
  }
  print "\n</table>";

}

// What users see if they fail to login
function printLoginFailure(){
  printHeader();
  print "\nHOBA Login Failed: Your browser does not support HOBA, or something else broke";
  printFooter();
}
?>
