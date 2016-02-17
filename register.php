<?php
include_once 'globals.php';
include_once 'challenge.php';
include_once 'db.php';

dbLogin();
$did = $_POST["did"];
$didType = $_POST["didtype"];
$kid = $_POST["kid"];
$kidType = $_POST["kidtype"];
$pub = $_POST["pub"];

$postData = "did:" . $did . " didType:" . $didType . " kid:" . $kid . " kidType:" . $kidType . " pub:" . $pub;

error_log($postData, 0);

dbLogout();
?>
