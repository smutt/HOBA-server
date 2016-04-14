<?php

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
  if(dbGetDeviceByCookie($_COOKIE['HOBA'])){
    print "Your cookie is valid. Welcome to HOBA land.";
  }else{
    printRefresher();
  }
}else{
  printRefresher();
}
dbLogout();
?>