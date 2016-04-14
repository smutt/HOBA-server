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
  $q = $GLOBALS['db']->query("SELECT did from pubKeys WHERE kid='" . $kid . "'");
  if($q->num_rows == 0){ // Do we know this key?
    $q->close();

    $q = $GLOBALS['db']->prepare("INSERT into users(uName) values(NULL)");
    $q->execute();
    $uid = $q->insert_id;
    $q->close();

    $q = $GLOBALS['db']->prepare("INSERT into devices(uid, dName) values(" . $uid . ", '" . $dName . "')");
    $q->execute();
    $did = $q->insert_id;
    $q->close();
    
    $q = $GLOBALS['db']->prepare("INSERT into pubKeys(did, kid, pubKey) values(" . $did . ", '" . $kid . "', '" . $pubKey . "')");
    $q->execute();
    $q->close();
  }else{
    return False;
  }
  return True;
}

// @brief Adds new cookie value to a did, which is basically a session
// @return nothing
function dbAddSession($kid, $dName, $cookieVal){
  $dName = trim($GLOBALS['db']->real_escape_string($dName));
  $cookieVal = trim($cookieVal);

  $q = $GLOBALS['db']->query("SELECT did from pubKeys WHERE kid='" . $kid . "'");
  $r = $q->fetch_assoc();
  $q->close();
        
  $tStamp = time();
  $q = $GLOBALS['db']->prepare("INSERT into sessions(did, cookie, tStamp) values(" . $r['did'] . ", '" . $cookieVal . "', " . $tStamp . ")");
  $q->execute();
  $q->close();
}

// @brief Takes a device ID
// @return device array
function dbGetDeviceByDid($did){
  $rv = array();
  $rv['did'] = $did;

  $q = $GLOBALS['db']->query("SELECT uid,dName from devices where did=" . $did);
  $r = $q->fetch_assoc();
  $rv['uid'] = $r['uid'];
  $rv['dName'] = $r['dName'];
  $q->close();
  
  $q = $GLOBALS['db']->query("SELECT uName from users where uid=" . $rv['uid']);
  $r = $q->fetch_assoc();
  $rv['uName'] = $r['uName'];
  $q->close();

  $q = $GLOBALS['db']->query("SELECT pid,kid,pubKey from pubKeys where did=" . $did);
  $r = $q->fetch_assoc();
  $q->close();
  $rv['pid'] = $r['pid'];
  $rv['kid'] = $r['kid'];  
  $rv['pubKey'] = json_decode(base64url_decode($r['pubKey']), true);
  
  return $rv;
}

// @brief Takes a cookie value
// @return device array if cookie value is valid and not expired, false otherwise
function dbGetDeviceByCookie($cookieVal){
  $cookieVal = trim($cookieVal);
  $tStamp = time();
  
  $q = $GLOBALS['db']->query("SELECT did,tStamp from sessions where cookie='" . $cookieVal . "'");
  if($q){
    $r = $q->fetch_assoc();
    $q->close();
    if($tStamp > $r['tStamp'] + $GLOBALS['sessionTimeout']){
      return False;
    }else{
      return dbGetDeviceByDid($r['did']);
    }
  }else{
    return False;
  }
}

// @brief Takes a key-ID(kid)
// @return device array, returns False if kid not in DB
function dbGetDeviceByKid($kid){
  $kid = trim($kid);
  
  $q = $GLOBALS['db']->query("SELECT did from pubKeys where kid='" . $kid . "'");
  if($q){
    $r = $q->fetch_assoc();
    $q->close();
    return dbGetDeviceByDid($r['did']);
  }else{
    return False;
  }
}

?>
