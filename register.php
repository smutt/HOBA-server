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

foreach (getallheaders() as $name => $value) {
  //error_log("Header:" . $name . " " . $value);
  if($name == "Authorization" && (stripos($value, "hoba") > -1)){
    list($junk, $authStr) = explode("result=", $value);
    $kid = base64_decode(strtok($authStr, "."));
    $chalB64 = strtok(".");
    $nonce = base64_decode(strtok("."));
    $sig = urldecode(base64_decode(strtok(".")));
  }
}

error_log("kid:" . $kid . " chalB64:" . $chalB64 . " nonce:" . $nonce ." sig:" . $sig);

if(checkChal($chalB64, getPeer())){
  error_log("HOBA Challenge accepted");
}else{
  error_log("HOBA Challenge failed");
}

dbLogout();
?>
