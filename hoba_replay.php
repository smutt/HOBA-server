<?php

/*
 * @file hoba_replay.php
 * @brief PHP HOBA scripts
 * Replay buffer implementation
 */
/* 
 * HOBA - No Password HTTP Authentication
 *
 * Copyright (C) 2014, Tolerant Networks Limited
 *
 * Stephen Farrell, <stephen@tolerantnetworks.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 *
 */

include_once 'globals.php';

/// return true if this is a replay or too old
/// cache otherwise
/// Note that we depend here on the challenge
/// having being checked first and being rejected
/// if too old
function hoba_check_replay($sig)
{
	$now=floor(microtime(true)); // just for audit purposes not really needed
	$replay_width=$GLOBALS['sig_replay_width'];
	$replay_half=$replay_width/2;
	$res=false;
	if (!$res) {
		// check if a record for that key exists
		// if so then someone's being naughty
		try {
			$record_name="HOBA/REPLAY/".$sig;
			$curr_record=$GLOBALS['redis']->exists($record_name);
			if ($curr_record) {
				$res=true;
			} else {
				/// insert, but using setex so it expires itself after 
				/// replay-half(+1) seconds (What a *nice* feature!)
				$GLOBALS['redis']->setex($record_name,$replay_half+1,$now);
				$res=false;
			}
		} catch (Exception $e) {
			$GLOBALS['errstr']=$e->getMessage();
			$res=true;
		}
	} 

	return $res;
}

?>
