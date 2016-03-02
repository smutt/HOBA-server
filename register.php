<?php
include_once 'globals.php';
include_once 'challenge.php';
include_once 'db.php';

dbLogin();
$did = $_POST["did"];
$didType = $_POST["didtype"];
$kidType = $_POST["kidtype"];
$kid = base64_decode(urldecode($_POST["kid"]));
$pub = base64_decode(urldecode($_POST["pub"]));


$postData = "did:" . $did . " didType:" . $didType . " kid:" . $kid . " kidType:" . $kidType . " pub:" . $pub;

error_log($postData, 0);

dbLogout();
?>
