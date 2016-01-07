<?php
/*
 * @file msql.php
 * @brief PHP HOBA MariaDB php functions
 * Mainly lots of gets and sets
 */
/* 
 * HOBA - No Password HTTP Authentication
 *
 * Copyright (C) 2015, Andrew McConachie
 *
 * Andrew McConachie <smutt@depht.com>
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License
 *
 */

include_once 'globals.php';

// @brief login to our DB, sets our db object
// @return False on failure
function dbLogin(){
  $GLOBALS['db'] = new mysqli("localhost", "hoba", "RFC7486", "hoba"); // We just store our password here in plaintext because lazy
  if($GLOBALS['db']->connect_errno) return False;
}

// @brief logout of our DB
// @return False on failure
function dbLogout(){
  return mysqli_close($GLOBALS['db']);
}

// @brief Insert a challenge into the DB
// @return False on failure
function dbAddChal($chal){
  if(dbCheckChal($chal)) return False;
  $ts = time();
  if( !$GLOBALS['db']->query("INSERT into challenges(challenge, tStamp) values('" . $chal . "','" . $ts . "')")) return False;
}

// @brief Deletes a challenge from the DB if it exists
// @return False on failure 
function dbDelChal($chal){
  if( !$GLOBALS['db']->query("DELETE from challenges where challenge='" . $chal . "'")) return False;
}

// @brief Returns True if passed challenge exists and is still fresh
// @return False if challenge not found or if spoiled or on failure
function dbCheckChal($chal){
  $spoiled = time() - $GLOBALS['chalTimeout'];
  if( !$GLOBALS['db']->query("SELECT challenge from challenges where challenge='" . $chal . "' and tStamp > " . $spoiled)) return False;

  if($GLOBALS['db']->num_rows > 0) return True;
  else{
    return False;
  }
}
?>
