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

global $db; $db = Null; // Our database connection

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
  else{
    return True;
  }
}

// @brief Deletes a challenge from the DB if it exists
// @return False on failure 
function dbDelChal($chal){
  if( !$GLOBALS['db']->query("DELETE from challenges where challenge='" . $chal . "'")) return False;
  else{
    return True;
  }
}

// @brief Returns True if passed challenge exists and is still fresh
// @return False if challenge not found or if spoiled or on failure
function dbCheckChal($chal){
  $spoiled = time() - $GLOBALS['chalTimeout'];
  $q = "SELECT challenge from challenges where challenge='" . $chal . "' and tStamp > " . $spoiled;
  if( !$prep = $GLOBALS['db']->prepare($q)) return False;

  if($prep->num_rows > 0) return True;
  else{
    return False;
  }
}

// @brief Registers a new public key to a did
// @return true if new kid/did combo, otherwise returns false
function dbRegisterKey($kid, $pubKey, $dName){
  $pubKey = serialize($pubKey);
  $dName = mysql_real_escape_string($dName);

  $GLOBALS['db']->query("SELECT uid from pubKeys WHERE kid='" . $kid . "'");
  if($GLOBALS['db']->num_rows == 0){ // Do we know this key?
    $GLOBALS['db']->query("INSERT into users");
    $uid = $GLOBALS['db']->insert_id;

    $GLOBALS['db']->query("INSERT into pubKeys(uid, kid, pubKey) values(" . $uid . "'" . $kid . "', '" . $pubKey . "')");
    $GLOBALS['db']->query("INSERT into devices(uid, dName) values(" . $uid . ", '" . $dName . "')");
  }else{ // If we know the key add the device
    $r = $GLOBALS['db']->fetch_assoc();
    $GLOBALS['db']->query("SELECT did from devices WHERE uid=" . $r['uid'] . " AND dName='" . $dName . "'");
    if($GLOBALS['db']->num_rows == 0){
      $GLOBALS['db']->query("INSERT into devices(uid, dName) values(" . $r['uid'] . ", '" . $dName . "')");
    }else{
      return False; // kid/did combo already exists
    }
  }
  return True;
}

// @brief Adds new cookie value to a did, which is basically a session
// @return nothing
function dbAddSession($kid, $dName, $cookieVal){
  $dName = mysql_real_escape_string($dName);

  $GLOBALS['db']->query("SELECT uid from pubKeys WHERE kid='" . $kid . "'");
  $r = $GLOBALS['db']->fetch_assoc();
  
  $GLOBALS['db']->query("SELECT did from devices WHERE uid=" . $r['uid'] . " AND dName='" . $dName . "'");
  $r = $GLOBALS['db']->fetch_assoc();
  
  $tStamp = time();
  $GLOBALS['db']->query("INSERT into sessions(did, cookie, tStamp) values(" . $r['did'] . ", '" . $cookieVal . "', " . $tStamp);
}

// @brief checks if a session exists and is still valid
// @return returns assoc array(kid, did) if exists and valid, otherwise false
function dbCheckSession($cookieVal){
  $GLOBALS['db']->query("SELECT * from sessions WHERE cookie='" . $cookieVal . "'");

}

?>
