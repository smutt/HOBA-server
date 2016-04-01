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

// These 2 functions taken from http://php.net/manual/en/function.base64-encode.php
function base64url_encode($data) {
  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function base64url_decode($data) {
  return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}

function genTbsBlobField($str){
  $len = strlen($str);
  return $len . ":" . $str;
}

function genTbsBlob($nonceB64, $alg, $origin, $kidB64, $chalB64){
  $tbsStr = genTbsBlobField($nonceB64);
  $tbsStr .= genTbsBlobField($alg);
  $tbsStr .= genTbsBlobField($origin);
  $tbsStr .= genTbsBlobField($GLOBALS['realm']);
  $tbsStr .= genTbsBlobField($kidB64);
  $tbsStr .= genTbsBlobField($chalB64);
  return $tbsStr;
}

// Takes a JWK and returns a PEM
// Magic taken from here http://stackoverflow.com/questions/16993838/openssl-how-can-i-get-public-key-from-modulus
function jwkToPem($jwk){
  $modulus = new Math_BigInteger(base64url_decode($jwk['n']), 256);
  $exponent = new Math_BigInteger(base64_decode($jwk['e']), 256);
  $rsa = new Crypt_RSA();
  $rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
  $rsa->setPublicKey();
  return str_replace("\r", "", $rsa->getPublicKey()); // This shit is written for DOS
}

////////////////////
// BEGIN EXECUTION
////////////////////

dbLogin();
$did = $_POST["did"];
$didType = $_POST["didtype"];
$kidType = $_POST["kidtype"];
$alg = $_POST["alg"];
$kid = base64url_decode($_POST["kid"]);
$pub = base64url_decode($_POST["pub"]);
$pubKey = array();
$pubKey = json_decode($pub, true);


error_log("STARTING NEW REGISTRATION");
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
  error_log("HOBA Challenge accepted");
}else{
  error_log("HOBA Challenge failed");
}

$tbsOrigin = "https://" . $_SERVER['SERVER_NAME'] . ":" . $_SERVER['SERVER_PORT'];
$sigText = genTbsBlob($nonceB64, $alg, $tbsOrigin, $kidB64, $chalB64);
//error_log("sigText:" . $sigText);
$pem = jwkToPem($pubKey);
$verified = openssl_verify($sigText, $sig, $pem, OPENSSL_ALGO_SHA256);

if($verified){
  $newUser = dbRegisterKey($kid, $pubKey, $did);
  if(! $newUser){
    error_log("Register failed: Verification passed but kid already registered to did");
    exit(1);
  }
  $chocolate = getCookieVal($kid);
  dbAddSession($kid, $did, $chocolate);
  setcookie("HOBA", $chocolate, time() + $GLOBALS['sessionTimeout'], "/hoba/", $_SERVER['SERVER_NAME'], true, false);
  header("Hobareg: regok", true, 200);
}else{
  error_log("Register failed: Verification failure");
  exit(1);
}
dbLogout();
?>
