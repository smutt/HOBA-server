<?php
include_once 'globals.php';
include_once 'challenge.php';
include_once 'db.php';
include_once 'lib/BigInteger.php';
include_once 'lib/phpseclib1.0.1/Crypt/RSA.php';

// Die if connection not using TLS
if(strlen($_SERVER['HTTPS']) == 0){
  exit(1);
}

dbLogin();
$did = $_POST["did"];
$didType = $_POST["didtype"];
$kidType = $_POST["kidtype"];
$alg = $_POST["alg"];
$kid = base64url_decode($_POST["kid"]);
$pub = base64url_decode($_POST["pub"]);
$pubKey = array();
$pubKey = json_decode($pub, true);

error_log("HOBA: Starting New Registration");
//$postData = "did:" . $did . " didType:" . $didType . " alg:" . $alg . " kid:" . $kid . " kidType:" . $kidType . " pub:" . $pub;
//error_log("postData:" . $postData);
if($pubKey['kty'] != "RSA" || $pubKey['alg'] != "RS256" ){
  error_log("Unsupported algorithm for public key");
  exit(1);
}
// TODO: Check to make sure kid === RSA256(pubKey)

foreach (getallheaders() as $name => $value){
  //error_log("Header:" . $name . " " . $value);
  if($name == "Authorization" && (stripos($value, "hoba") > -1)){
    list($junk, $authStr) = explode("result=", $value);
    $kidB64 = strtok($authStr, ".");
    $chalB64 = strtok(".");
    $nonceB64 = strtok(".");
    $sig = base64url_decode(strtok("."));

    if($kid != base64url_decode($kidB64)){
      error_log("kid in POST different from kid in Auth Header");
      exit(1);
    }
  }
}
//error_log("kidB64:" . $kidB64 . " chalB64:" . $chalB64 . " nonceB64:" . $nonceB64 ." sig:" . $sig);

if(checkChal($chalB64, getPeer())){
  error_log("HOBA: Challenge accepted");
}else{
  error_log("HOBA: Challenge failed");
}

$tbsOrigin = "https://" . $_SERVER['SERVER_NAME'] . ":" . $_SERVER['SERVER_PORT'];
$sigText = genTbsBlob($nonceB64, $alg, $tbsOrigin, $kidB64, $chalB64);
//error_log("sigText:" . $sigText);
$pem = jwkToPem($pubKey);
$verified = openssl_verify($sigText, $sig, $pem, OPENSSL_ALGO_SHA256);

if($verified){
  error_log("HOBA: Key Verification Successful");
  $newUser = dbRegisterKey($kid, $pubKey, $did);
  if(! $newUser){
    error_log("HOBA: Register failed, verification passed but kid already registered to did");
    exit(1);
  }
  $chocolate = getCookieVal($kid, $did);
  dbAddSession($kid, $did, $chocolate);
  setcookie("HOBA", $chocolate, time() + $GLOBALS['sessionTimeout'], "/hoba/", $_SERVER['SERVER_NAME'], true, false);
  header("Hobareg: regok", true, 200);
  error_log("HOBA: Registration Successful");
}else{
  error_log("HOBA: Register failed, Verification failure");
  exit(1);
}
dbLogout();
?>
