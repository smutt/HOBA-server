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

error_log("HOBA: Starting New Login");
foreach (getallheaders() as $name => $value){
  //error_log("Header:" . $name . " " . $value);
  if($name == "Authorization" && (stripos($value, "hoba") > -1)){
    list($junk, $authStr) = explode("result=", $value);
    $kidB64 = strtok($authStr, ".");
    $chalB64 = strtok(".");
    $nonceB64 = strtok(".");
    $sig = base64url_decode(strtok("."));
  }
}
//error_log("kidB64:" . $kidB64 . " chalB64:" . $chalB64 . " nonceB64:" . $nonceB64 ." sig:" . $sig);

if(checkChal($chalB64, getPeer())){
  error_log("HOBA: Challenge accepted");
}else{
  error_log("HOBA: Challenge failed");
  exit(1);
}

$kid = base64url_decode($kidB64);
$tbsOrigin = "https://" . $_SERVER['SERVER_NAME'] . ":" . $_SERVER['SERVER_PORT'];
$sigText = genTbsBlob($nonceB64, $GLOBALS['alg'], $tbsOrigin, $kidB64, $chalB64);

dbLogin();
$device = dbGetDeviceByKid($kid);
if(! $device){
  error_log("HOBA: kid not found");
  dbLogout();
  exit(1);
}

$pem = jwkToPem($device['pubKey']);
$verified = openssl_verify($sigText, $sig, $pem, OPENSSL_ALGO_SHA256);

if($verified){
  error_log("HOBA: Key Verification Successful");
  $user = dbGetDeviceByKid($kid);
  
  $chocolate = getCookieVal($user['kid'], $user['did']);
  dbAddSession($user['kid'], $user['did'], $chocolate);
  setcookie("HOBA", $chocolate, time() + $GLOBALS['sessionTimeout'], "/hoba/", $_SERVER['SERVER_NAME'], true, false);
  header("Hobareg: regok", true, 200);
  error_log("HOBA: Login Successful");
}else{
  error_log("HOBA: Register failed, Verification failure");
}
dbLogout();
?>
