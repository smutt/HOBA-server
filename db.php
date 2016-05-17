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
 * @file msql.php
 * @brief PHP HOBA MariaDB php functions
 * Mainly lots of gets and sets
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

    $name = dbRandName();
    $q = $GLOBALS['db']->prepare("INSERT into users(uName) values('" . $name . "')");
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
function dbAddSession($kid, $dName, $cookieVal, $t){
  $dName = trim($GLOBALS['db']->real_escape_string($dName));
  $cookieVal = trim($cookieVal);

  // Delete really old sessions, Otherwise they never get deleted
  $cutOff = time() - $GLOBALS['sessionTimeout'] * 10;
  $GLOBALS['db']->query("DELETE from sessions WHERE tStamp<" . $cutOff);

  $q = $GLOBALS['db']->query("SELECT did from pubKeys WHERE kid='" . $kid . "'");
  $r = $q->fetch_assoc();
  $q->close();
        
  $q = $GLOBALS['db']->prepare("INSERT into sessions(did, cookie, tStamp) values(" . $r['did'] . ", '" . $cookieVal . "', " . $t . ")");
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
  if(strlen(trim($r['uName'])) > 0) $rv['uName'] = $r['uName'];
  else{
    $rv['uName'] = false;
  }
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
  if(strtolower($cookieVal) == "failed" || strtolower($cookieVal) == "attempt" ) return False; // Defensive programming

  $tStamp = time();
  
  $q = $GLOBALS['db']->query("SELECT did,tStamp from sessions where cookie='" . $cookieVal . "'");
  if($q){
    $r = $q->fetch_assoc();
    $q->close();
    if($tStamp > $r['tStamp'] + $GLOBALS['sessionTimeout']){
      dump("Cookie timed out");
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
    if(strlen($r['did']) > 0){
      return dbGetDeviceByDid($r['did']);
    }else{
      return False;
    }
  }else{
    return False;
  }
}

// @brief Takes nothing
// @return a random name from our table of names
// TODO: Check if username is already in use
function dbRandName(){
  $q = $GLOBALS['db']->query("SELECT firstName from firstNames ORDER BY RAND() LIMIT 0,1");
  $r = $q->fetch_assoc();
  $fn = "Anon_" . $r['firstName'];
  $q->close();

  $q = $GLOBALS['db']->query("SELECT uid from users WHERE uName='" . $fn . "'");
  if(count($q->fetch_assoc()) == 0){
    return $fn;
  }else{
    dump("Recursing in dbRandName() because " . $fn);
    return dbRandName();
  }
}

// @brief Gets messages from messages table, takes most recent numMsgs to return
// @return mid,uid,messages as assoc array
function dbGetMsgs($num){
  $q = $GLOBALS['db']->query("SELECT mid,uid,message from messages ORDER BY mid DESC limit " . $num);
  $msgs = array();  
  while($row = $q->fetch_assoc()){
    array_push($msgs, $row);
  }
  $q->close();

  for($ii = 0; $ii < count($msgs); $ii++){
    $q = $GLOBALS['db']->query("SELECT uName from users WHERE uid=" . $msgs[$ii]['uid']);
    $tmp = $q->fetch_assoc();
    $msgs[$ii]['uName'] = $tmp['uName'];
    $q->close();
  }

  return $msgs;
}

// @brief takes user name
// @return true on success, otherwise string explaining failure
function dbSetUserName($uid, $str){
  $str = trim($str);

  if(preg_replace("/^[A-Z,a-z,0-9,-_]+$/", "", $str) !== ""){
    return "Username can only contain characters A-Z a-z 0-9 _ +";
  }
  if(strlen($str) >= $GLOBALS['userNameMaxLen'] || strlen($str) <= $GLOBALS['userNameMinLen']){
    return "Username must be between " . $GLOBALS['userNameMinLen'] . " and " .$GLOBALS['userNameMaxLen'] . " characters";
  }

  $q = $GLOBALS['db']->query("UPDATE users set uName='" . $str . "' where uid=" . $uid);
  return true;
}

// @brief Adds a message to the messages table, takes uid and msg
// @return true on success, otherwise string explaining failure
function dbAddMsg($uid, $msg){
  $msg = trim($GLOBALS['db']->real_escape_string($msg));
  $q = $GLOBALS['db']->query("INSERT into messages(uid,message) values('" . $uid . "','" . $msg . "')");
  return true;
}

// @brief Adds a bond attempt to mapping table
// @return true on success, otherwise string explaining failure
function dbRequestBond($srcDid, $trgUid){
  $q = $GLOBALS['db']->query("SELECT srcDid,trgUid from bondMap where srcDid=" . $srcDid . " AND trgUid=" . $trgUid);
  $bond = $q->fetch_assoc();
  if(count($bond) != 0){
    return "Bond attempt already in progress";
  }
  $q->close();

  $q = $GLOBALS['db']->query("INSERT into bondMap(srcDid,trgUid) values(" . $srcDid . "," . $trgUid . ")");
  return true;  
}

// @brief Deletes all bond attempts from mapping table that match passed values
// @return true on success, otherwise string explaining failure
function dbDeleteBond($srcDid, $trgUid){
  $q = $GLOBALS['db']->query("SELECT srcDid,trgUid from bondMap where srcDid=" . $srcDid . " AND trgUid=" . $trgUid);
  if($q === false){
    return "Bond attempt does not exist";
  }
  $q->close();

  $GLOBALS['db']->query("DELETE from bondMap where srcDid=" . $srcDid . " AND trgUid=" . $trgUid);
  return true;
}

// @brief Changes the uid of a device
// Changes all devices under the old 
// @return true on success, otherwise string explaining failure
function dbConfirmBond($srcDid, $trgUid){
  $q = $GLOBALS['db']->query("SELECT srcDid,trgUid from bondMap where srcDid=" . $srcDid . " AND trgUid=" . $trgUid);
  if($q === false){
    dump("Bond attempt does not exist" . $srcDid . " " . $trgUid); // This should never happen
    return "Bond attempt does not exist";
  }

  // Get the old uid
  $q = $GLOBALS['db']->query("SELECT uid from devices WHERE did=" . $srcDid);
  $old = $q->fetch_assoc();
  $q->close();
  $oldUid = $old['uid'];
  
  $GLOBALS['db']->query("UPDATE devices set uid=" . $trgUid . " WHERE uid=" . $oldUid);
  $GLOBALS['db']->query("UPDATE messages set uid=" . $trgUid . " WHERE uid=" . $oldUid);
  $GLOBALS['db']->query("delete from users where uid=" . $oldUid);
  
  return dbDeleteBond($srcDid, $trgUid);
}

// @brief fetches least recent bond attempt for passed user ID
// @return assoc array(targetUid, targetUserName), false if none present
function dbGetBondAttempt($trgUid){
  $q = $GLOBALS['db']->query("SELECT srcDid from bondMap where trgUid=" . $trgUid . " ORDER by bid ASC limit 1");
  $bond = $q->fetch_assoc();
  $q->close();

  if(count($bond) == 0){
    return false;
  }
  
  $q = $GLOBALS['db']->query("SELECT dName from devices where did=" . $bond['srcDid']);
  $dev = $q->fetch_assoc();
  $q->close();

  return array('did' => $bond['srcDid'], 'dName' => $dev['dName']);
}
?>
