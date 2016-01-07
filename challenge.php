<?php

/*
 * @file challenge.php
 * @brief PHP HOBA scripts challenge handler
 * This script implements challenge handling
 * Challenges are encrypted values with the plaintext
 * being the time and IP address to which the
 * challenge will be sent.
 */
/* 
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
function getPeer() {
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
function getChal($to) {
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

function test() {
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
