<?php

/*
 * @file hoba_auth.php
 * @brief PHP HOBA scripts
 * This script implements the auth check flow
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

include_once 'globals.php';
include_once 'challenge.php';
include_once 'hoba_replay.php';
// hexdump only needed is you uncomment the dump call below
//include 'hexdump.php';

function hoba_check_auth() {

	// this branch probably should disappear
	if (!isset($_SERVER['HTTP_HOBA']) && !isset($_SERVER['HTTP_AUTHORIZATION'])) {
		// set challenge
		$from=getPeer();
		$challenge=getChal($from);
		$hv='HOBA: HOBA ' . $challenge;
	    header('HTTP/1.0 200 OK');
		header($hv);
		$GLOBALS['errstr']="issued challenge: ". $challenge;
		return $GLOBALS['chalerr'];
	} else {
		// see if there's a good looking header there
		// if both, prefer HOBA I guess, "Authorization" mebbe more likely to be mucked with
		$hv="";
		if (isset($_SERVER['HTTP_HOBA']) && !isset($_SERVER['HTTP_AUTHORIZATION'])) {
			$hv=$_SERVER['HTTP_HOBA'];
		} elseif (!isset($_SERVER['HTTP_HOBA']) && isset($_SERVER['HTTP_AUTHORIZATION'])) {
			$hv=$_SERVER['HTTP_AUTHORIZATION'];
		} elseif (isset($_SERVER['HTTP_HOBA']) && isset($_SERVER['HTTP_AUTHORIZATION'])) {
			$hv=$_SERVER['HTTP_HOBA'];
		} elseif (!isset($_SERVER['HTTP_HOBA']) && !isset($_SERVER['HTTP_AUTHORIZATION'])) {
			// confuse someone:-)
			$hv="result=\"A.load.of.bollocks\"";
		}
		
		$from=getPeer();
		
		$res=strtok($hv,'"');
		/// key identifier from HOBA header
		$kid=strtok(".");
		/// chal from HOBA header
		$chal=strtok(".");
		/// client nonce from HOBA header
		$nonce=strtok(".");
		/// signature from HOBA header
		$sig=strtok(".");
		// zap last char of sig which is " from end of header
		// $sig=rtrim($sig,'"');

		/// check challenge is ok
		$chalok=checkChal($chal,$from);
		if (!$chalok) {
			$GLOBALS['errstr']="bad challenge: ". $chal;
			return $GLOBALS['chalerr'];
		}

		// check for replay of signature
		if (hoba_check_replay($sig)) {
			$GLOBALS['errstr']="replayed signature: ". $sig;
			return $GLOBALS['chalerr'];
		}

		$kidtype=0;
		$kidval=$kid;
		/// the full name of the record that might be created
		$record_name=$GLOBALS['record_prefix'] . "/" . $kidtype . "/" . $kidval; 
		// look up kid now
		try {
			if ($GLOBALS['redis']->exists($record_name)) {
				$record=$GLOBALS['redis']->get($record_name);
				$dec_rec=json_decode($record);
			} else {
				$GLOBALS['errstr']="No record for " . $record_name;
				return $GLOBALS['recerr'];
			}
		} catch (Exception $e) {
			$GLOBALS['errstr']="db error reading record";
			return $GLOBALS['dberr'];
		}

		// do the un-urlencode bit for - to + and _ to /
		$pubforuse=str_replace("-","+",$dec_rec->pub);
		$pubforuse=str_replace("_","/",$pubforuse);
		// crappy PEM format has "-----" at start/end
		$pubforuse=str_replace("+++++","-----",$pubforuse);

		$pubkey=openssl_get_publickey($pubforuse);
		if ($pubkey == false ) {
			$GLOBALS['errstr']="bad public key";
			return $GLOBALS['keyerr'];
		} 

		# not used for now (would be an apache thing anyway)
		$realm="";

		// try for sha-1 first for now (will move later)
		$alg=1; 
		$plain = $nonce . $alg . $GLOBALS['sig_origin'] .  $realm . $kidval . $chal;

		// base64 decode sig to get binary value we need to verify
		// make it base64 from url
		$bin_sig=base64_decode(str_pad(strtr($sig, '-_', '+/'), strlen($sig) % 4, '=', STR_PAD_RIGHT));

		// print bin_sig for debugging
		//print "<pre>";
		//$dump=hexdump($bin_sig,false);
		//print "strlen(sig)=".strlen($sig); 
		//print "Hex dump sig:\n";
		//print $dump;
		//print "End of hex dump for sig\n";
		//print "Sig: " . $sig . "\n";
		//print "Plain: " . $plain . "\n";
		//print "Public" . $pubforuse . "\n";
		//print "</pre>";

		/// todo update hoba.ie to php5.4 (needs ubuntu beyond 12.04 or ppa)
		$sig_ok=openssl_verify($plain,$bin_sig,$pubkey); // default is rsa-sha1
		if ($sig_ok == true ) {
			$_SESSION['kid']=$kidval;
			return 0;
		} else {
		
			// tried for sha-1 first for now (will move later), now sha256
			$alg=0; 
			$plain = $nonce . $alg . $GLOBALS['sig_origin'] .  $realm . $kidval . $chal;
			// be liberal in what you accept:-)
			// for now:-) sha-1 will go away later
			/// todo maybe put sigalg into protocol
			$sig_ok=openssl_verify($plain,$bin_sig,$pubkey,'sha256');
			if ($sig_ok == true ) {
				$_SESSION['kid']=$kidval;
				return 0;
			} else {
				$GLOBALS['errstr']="bad signature";
				return $GLOBALS['sigerr'];
			}
		}
		$GLOBALS['errstr']="unexpected end";
		return $GLOBALS['generr'];
	}

}

?>
