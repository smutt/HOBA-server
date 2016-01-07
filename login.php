<?php
if(strlen($_POST['user']) < 3){
  print "Username too short or non-existant";
  exit(1);
}

include_once 'db.php';
include_once 'challenge.php';

dbLogin();
$chal = getChal(getPeer());
dbAddChal($chal);

//$realm = $_SERVER['SERVER_NAME'];
//header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $chalTimeout . ",realm=" . $realm);
header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $chalTimeout);
header('HTTP/1.0 401 Unauthorized');

$user = $_POST['user'];
if($_POST['button'] == "Create New User"){
  print "\nNew user:" . $user;
}elseif($_POST['button'] == "Login"){
  print "\nLogin user:" . $user;
}elseif($_POST['button'] == "Delete User"){
  print "\nDelete user:" . $user;
}

dbLogout();
?>