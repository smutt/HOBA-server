<?php
include_once 'globals.php';
include_once 'challenge.php';
include_once 'db.php';

dbLogin();
$chal = getChal(getPeer());
while(! dbAddChal($chal)){
  $chal = getChal(getPeer());
}
dbLogout();

//$realm = $_SERVER['SERVER_NAME'];
//header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $chalTimeout . ",realm=" . $realm);
header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $GLOBALS['chalTimeout']);
?>
