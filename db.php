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

// Because of PHP's stupid love affair with everything object oriented
// The sheer amount of lines we have to write to do simple things has increased by an absurd amount
// The PHP team is responsible for the absurd amount of boilerplate nonsense polluting this file
// They're also responsible for taking something that used to be relatively simple and making it completely obtuse
// Let us pray the scourge of object oriented programming does not ruin PHP any further
// I've been writing PHP since PHP3 and I think I might just use Python for my next project if it requires a DB interface
// Seriously guys, WTF were you thinking?

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
// Takes keyID, JWK as array, and a deviceName
// @return true if new kid/did combo, otherwise returns false
function dbRegisterKey($kid, $pubKey, $dName){
  $pubKey = trim(base64url_encode(json_encode($pubKey)));
  
  $dName = trim($GLOBALS['db']->real_escape_string($dName));
  $q = $GLOBALS['db']->query("SELECT uid from pubKeys WHERE kid='" . $kid . "'");
  if($q->num_rows == 0){ // Do we know this key?
    $q->close();

    $q = $GLOBALS['db']->prepare("INSERT into users(userNames) values(NULL)");
    $q->execute();
    $uid = $q->insert_id;
    $q->close();

    $q = $GLOBALS['db']->prepare("INSERT into pubKeys(uid, kid, pubKey) values(" . $uid . ", '" . $kid . "', '" . $pubKey . "')");
    $q->execute();
    $q->close();

    $q = $GLOBALS['db']->prepare("INSERT into devices(uid, dName) values(" . $uid . ", '" . $dName . "')");
    $q->execute();
    $q->close();
  }else{ // If we know the key add the device
    $r = $q->fetch_assoc();
    $q->close();

    $q = $GLOBALS['db']->query("SELECT did from devices WHERE uid=" . $r['uid'] . " AND dName='" . $dName . "'");
    if($q->num_rows == 0){
      $q->close();

      $q = $GLOBALS['db']->query("INSERT into devices(uid, dName) values(" . $r['uid'] . ", '" . $dName . "')");
      $q->close();
    }else{
      $q->close();
      return False; // kid/did combo already exists
    }
  }
  return True;
}

// @brief Adds new cookie value to a did, which is basically a session
// @return nothing
function dbAddSession($kid, $dName, $cookieVal){
  $dName = trim($GLOBALS['db']->real_escape_string($dName));
  $cookieVal = trim($cookieVal);

  $q = $GLOBALS['db']->query("SELECT uid from pubKeys WHERE kid='" . $kid . "'");
  $r = $q->fetch_assoc();
  $q->close();
        
  $q = $GLOBALS['db']->query("SELECT did from devices WHERE uid=" . $r['uid'] . " AND dName='" . $dName . "'");
  $r = $q->fetch_assoc();
  $q->close();
  
  $tStamp = time();
  $q = $GLOBALS['db']->prepare("INSERT into sessions(did, cookie, tStamp) values(" . $r['did'] . ", '" . $cookieVal . "', " . $tStamp . ")");
  $q->execute();
  $q->close();
}

// @brief Takes a cookie value
// @return true if value is valid and not expired, false otherwise
function dbCheckCookie($cookieVal){
  $cookieVal = trim($cookieVal);
  $tStamp = time();
  
  $q = $GLOBALS['db']->query("SELECT * from sessions where cookie='" . $cookieVal . "'");
  if($q->num_rows == 0){
    $q->close();
    return False;
  }else{
    $r = $q->fetch_assoc();
    $q->close();
    if($tStamp > $r['tStamp'] + $GLOBALS['sessionTimeout']){
      return False;
    }else{
      return True;
    }
  }
}



?>
