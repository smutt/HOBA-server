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

/*
 * This file implements challenge handling
 * Challenges are encrypted values with the plaintext
 * being the time and IP address to which the
 * challenge will be sent.

 * HOBA - No Password HTTP Authentication
 *
 * Copyright (C) 2013, Tolerant Networks Limited
 *
 * Stephen Farrell, <stephen@tolerantnetworks.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 *
*/

/// @brief figure out peer to challenge
/// @return is the peer's IP as seen by server
function getPeer(){
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
      $ip=$_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_FORWARDED_FOR'])) {
      $ip=$_SERVER['HTTP_FORWARDED_FOR'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
      $ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
      $ip=$_SERVER['REMOTE_ADDR'];
    }
    return $ip;
}

/// @brief get a new challenge
/// @param to is the source to whom we'll give the challenge
/// @return the challenge string
function getChal($to){
	/// @todo make challenge encryption better
	/// the master secret for challenge encryption
	$master="9823423khjfsdids8ufds808r98320r980fd980dsf8ds0f";
	$method='aes-128-cbc';
	$iv="afdsfdsdsd123233";
	/// time now
	$req_time=floor(microtime(true));
	$nonce=base64_encode(openssl_random_pseudo_bytes(4));
	$plain = $nonce.".".$req_time.".".$to;
	$challenge = openssl_encrypt($plain,$method,$master,0,$iv);
	return $challenge;
}

/// @brief check that a challenge is ok and recent enough
/// @param challenge is the challenge
/// @param from is the source that presented that
/// @return true if ok, false otherwise
function checkChal($challenge,$from)
{
	/// todo make challenge encryption better
	/// the master secret for challenge encryption
	$master="9823423khjfsdids8ufds808r98320r980fd980dsf8ds0f"; 
	$method='aes-128-cbc';
	$iv="afdsfdsdsd123233";
	$plain=openssl_decrypt($challenge,$method,$master,0,$iv);
	$nonce=strtok($plain,".");
	$timeval=strtok(".");
	$peer=strtok("");
	if ($peer!=$from) {
		return false;
	}
	$now=floor(microtime(true));
	/// todo establish how short a window we can use, with
	/// browser JS in debug mode signing can be slow
	/// (window is how old in seconds a challenge is allowed be - 1second)
	$window=$GLOBALS['sig_replay_width']/2;
	if (($now-$timeval)>$window) {
		return false;
	}
	return true;
}

// Generates a value for our session cookie
function getCookieVal($kid, $did){
  $nonce = openssl_random_pseudo_bytes(32);
  return base64url_encode(crypt($kid . $did . $nonce, $GLOBALS['cookieSalt']));
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

// Takes an array representation of a JWK and returns a PEM
// Magic taken from here http://stackoverflow.com/questions/16993838/openssl-how-can-i-get-public-key-from-modulus
function jwkToPem($jwk){
  $modulus = new Math_BigInteger(base64url_decode($jwk['n']), 256);
  $exponent = new Math_BigInteger(base64_decode($jwk['e']), 256);
  $rsa = new Crypt_RSA();
  $rsa->loadKey(array('n' => $modulus, 'e' => $exponent));
  $rsa->setPublicKey();
  return str_replace("\r", "", $rsa->getPublicKey()); // This shit is written for DOS
}

function test(){
	$peer="10.0.0.1";
	$otherpeer="10.0.0.2";
	$foo=getChal($peer);
	$bar=checkChal($foo,$peer);
	print $foo . " is a " . ($bar?"good":"bad") . " challenge from ". $peer . "\n";
	$bar=checkChal($foo,$otherpeer);
	print $foo . " is a " . ($bar?"good":"bad") . " challenge from ". $otherpeer . "\n";
	sleep(2);
	$bar=checkChal($foo,$peer);
	print $foo . " is (now) a " . ($bar?"good":"bad") . " challenge from ". $peer . "\n";
}

?>
