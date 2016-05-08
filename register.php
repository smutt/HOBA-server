<?php
/*
  The file is part of the HOBA server.
  
  HOBA server is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  HOBA server is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program. If not, see <http://www.gnu.org/licenses/>.
  Copyright (C) 2016, Andrew McConachie, <andrew@depht.com>
*/

include_once 'globals.php';
include_once 'crypto.php';
include_once 'db.php';
include_once 'lib/BigInteger.php';
include_once 'lib/phpseclib1.0.1/Crypt/RSA.php';

$did = $_POST["did"];
$didType = $_POST["didtype"];
$kidType = $_POST["kidtype"];
$alg = $_POST["alg"];
$kid = base64url_decode($_POST["kid"]);
$pub = base64url_decode($_POST["pub"]);
$pubKey = array();
$pubKey = json_decode($pub, true);

dump("HOBA: Starting New Registration");
//$postData = "did:" . $did . " didType:" . $didType . " alg:" . $alg . " kid:" . $kid . " kidType:" . $kidType . " pub:" . $pub;
//dump("postData:" . $postData);
if($pubKey['kty'] != "RSA" || $pubKey['alg'] != "RS256"  || $alg != $GLOBALS['alg']){
  dump("HOBA: Unsupported algorithm for public key");
  setFailCookie();
  exit(1);
}
if($didType != $GLOBALS['didType']){
  dump("HOBA: Unsupported device ID type");
  setFailCookie();
  exit(1);
}
// TODO: Check to make sure kid === RSA256(pubKey)

foreach (getallheaders() as $name => $value){
  //dump("Header:" . $name . " " . $value);
  if($name == "Authorization" && (stripos($value, "hoba") > -1)){
    list($junk, $authStr) = explode("result=", $value);
    $kidB64 = strtok($authStr, ".");
    $chalB64 = strtok(".");
    $nonceB64 = strtok(".");
    $sig = base64url_decode(strtok("."));

    if($kid != base64url_decode($kidB64)){
      dump("HOBA: kid in POST different from kid in Auth Header");
      setFailCookie();
      exit(1);
    }
  }
}
//dump("kidB64:" . $kidB64 . " chalB64:" . $chalB64 . " nonceB64:" . $nonceB64 ." sig:" . $sig);

if(checkChal($chalB64, getPeer())){
  dump("HOBA: Challenge accepted");
}else{
  dump("HOBA: Challenge failed");
  setFailCookie();
  exit(1);
}

$tbsOrigin = "https://" . $_SERVER['SERVER_NAME'] . ":" . $_SERVER['SERVER_PORT'];
$sigText = genTbsBlob($nonceB64, $GLOBALS['alg'], $tbsOrigin, $kidB64, $chalB64);
$pem = jwkToPem($pubKey);
$verified = openssl_verify($sigText, $sig, $pem, OPENSSL_ALGO_SHA256);

dbLogin();
if($verified){
  dump("HOBA: Key Verification Successful");
  $newUser = dbRegisterKey($kid, $pubKey, $did);
  if(! $newUser){
    dump("HOBA: Register failed, verification passed but kid already registered");
    exit(1);
  }

  $t = time() + $GLOBALS['sessionTimeout'];
  $chocolate = getCookieVal($kid, $did);
  dbAddSession($kid, $did, $chocolate, $t);
  setSuccessCookie($chocolate, $t);
  header("Hobareg: regok", true, 200);
  dump("HOBA: Registration Successful");
}else{
  setFailCookie();
  dump("HOBA: Register failed, Verification failure");
}
dbLogout();
?>
