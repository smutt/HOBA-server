<?php
include_once 'globals.php';
include_once 'challenge.php';

/* We no longer both with the DB for challenges
include_once 'db.php';
dbLogin();
$chal = getChal(getPeer());
while(! dbAddChal($chal)){
  $chal = getChal(getPeer());
}
dbLogout();
*/

$chal = getChal(getPeer());
header('WWW-Authenticate: HOBA: challenge=' . $chal . ",expires=" . $GLOBALS['chalTimeout']);
?>
