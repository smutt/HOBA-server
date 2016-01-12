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

header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $GLOBALS['chalTimeout']);
?>
