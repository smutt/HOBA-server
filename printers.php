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

include_once "globals.php";
include_once "db.php";
include_once "crypto.php";

// Sets cookie and sends challenge headers
function sendChallenge(){
  $chal = getChal(getPeer());
  header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $GLOBALS['chalTimeout']);
  header('HTTP/1.0 401 Unauthorized');
}

// Sends HOBA headers, prints our HTML refresher, then exits
function printRefresher(){
  sendChallenge(); // Sends challenge
  
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
  print "\n  <link rel=\"stylesheet\" type=\"text/css\" href=\"hoba.css\" />";
  print "\n</head>";
  print "\n<body>";
}

function printFooter(){
  print "\n</body>";
  print "\n</html>";
}

// Takes uid, did, and an error string
// Either uName or did MUST be valid, while the other MUST be set to false
function printMeat($uName, $did, $errStr){
  if($uName === false){
    $dev = dbGetDeviceByDid($did);
    $uName = $dev['uName'];
  }else{
    $dev = false;
  }

  $msgs = dbGetMsgs($GLOBALS['numMsgs']);
  
  // Our top table
  print "\n<div align='center'><table width='100%'>";
  print "\n<tr><td align='left' valign='top' rowspan='3'><a href='main.php'><img src='hoba-stamp.jpg' height='150' width='200'></a></td>";
  
  if(strlen($errStr) != 0){
    print "\n<td class='err'>Error: " . $errStr . "</td>";
  }else{
    if($dev){
      $attempt = dbGetBondAttempt($dev['uid']);
      if($attempt !== false){  // Print out Bond confirm form
        print "\n<td class='err'><form action='main.php' method='POST'>";
        print "\n<input type='hidden' name='bondConfirmSource' value='" . $attempt['did'] . "'>";
        print "\n<input type='hidden' name='bondMe' value='true'>";
        print "\n<input type='submit' name='bondConfirm' value='Device " . $attempt['dName'] . " belongs to you'></form>";
        
        print "\n<form action='main.php' method='POST'>";
        print "\n<input type='hidden' name='bondConfirmSource' value='" . $attempt['did'] . "'>";
        print "\n<input type='hidden' name='bondMe' value='false'>";
        print "\n<input type='submit' name='bondConfirm' value='Device " . $attempt['dName'] . " does NOT belong to you'></form>";
        print "\n</td>";
      }else{
        print "\n<td class='err'></td>";
      }
    }else{
      print "\n<td class='err'></td>";
    }
  }

  print "\n<td></td><td class='user'><h4>" . $uName . "</h4></td></tr>";

  if($dev){
    print "\n<tr><td></td><td></td><td class='user'><form action='main.php' method='POST'><input type='text' name='uName'><br/>
             <input type='submit' name='changeUser' value='Change User Name'></form></td></tr>";
  }else{
    print "\n<tr><td></td><td></td><td class='user'><br/></td></tr>";
  }

  print "\n<tr><td></td><td></td><td class='user'><form action='main.php' method='POST'><input type='text' name='uPass'><br/>
             <input type='submit' name='changePass' value='Change Password'></form></td></tr>";
  print "\n</table></div>";
 
  // Our big message table
  print "\n<div class='meat'><center>";
  print "\n<table>";
  print "\n<tr><td></td>";
  print "\n<td colspan='2'><center><h4></h4></center></td>";
  print "\n<td><center><h4></h4></center></td></tr>";
  
  for($ii=0; $ii < count($msgs); $ii++){
    $message = trim(htmlspecialchars($msgs[$ii]['message']));

    print "\n<tr><td></td>";
    print "\n<td class='large'>" . $message . "</td>";
    print "\n<td>" . $msgs[$ii]['uName'] . "</td>";
    if($dev && ($dev['uid'] != $msgs[$ii]['uid'])){
      print "\n<td><form action='main.php' method='POST'><input type='hidden' name='bondAttemptTarget' value='" . $msgs[$ii]['uid'] . "'>";
      print "\n<input type='submit' name='bondAttempt' value=\"This is me\"/></form></td>";
    }
    print "\n</tr>";
  }

  print "\n<tr></tr>";
  print "\n<tr><td class='small'><h4>Say Something</h4></td><td class='large'><form id='leaveMsg' method='POST' action='main.php'>\n
             <textarea form='leaveMsg' name='msg' maxlength='1000' onfocus=\"this.value='';\" required>Something...</textarea></td>";
  print "\n<td class='small'><input type='submit' name='msgButton' value='Post Message'></td></form></tr>";
  
  print "\n</table>";
  print "\n</center></div>";
}

// What users see if they fail to login
function printLoginFailure($str=""){
  printHeader();
  if(strlen($str) > 0){
    print "\n" . $str;
  }else{
    print "\nHOBA Login Failed: Session expired or something else broke.";
  }
  printFooter();
}

// Prints out our YeOlde Login for HOBA users
function printHOBAYeOldePrompt(){
print <<<END
<html>
<head>
<link rel="stylesheet" type="text/css" href="hoba.css"/>
<title>
HOBA Ye Olde Password Authentication
</title>
</head>

<body onload="pollLogin()">

<center>
<div class='ye'>Ye Olde Password Authentication for HOBA Devices</div>
<div class="login">
<table>
  <form action="main.php" method="POST">
  <tr>
    <td>Username</td>
    <td><input type="text" name="HOBAYeOldeUser"></td>
    <td rowspan="2" class="login_button"><input type="submit" name="HOBAYeOldeSubmit" value="Login"></td>
  </tr>
  <tr>
    <td>Password</td>
    <td><input type="text" name="HOBAYeOldePassword"></td>
  </tr>
  <input type="hidden" name="HOBAYeOldeLogin"/>
  </form>
</table>
</div>
</center>
</body>
</html>
END;
}


?>
