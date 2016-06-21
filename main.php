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
include_once 'db.php';
include_once 'crypto.php';
include_once 'printers.php';

dbLogin();

// Test for cookies
if(isset($_COOKIE['HOBA'])){
  dump("HOBA: Got HOBA cookie for " . $_COOKIE['HOBA']);
  
  $err = true;
  $dev = dbGetDeviceByCookie($_COOKIE['HOBA']);
  if($dev){
    //TODO: Refresh session if it's old

    if($dev['pw'] && !$dev['passed']){ // Handle HOBA+YeOlde
      if(isset($_POST['HOBAYeOldeLogin']) && isset($_POST['HOBAYeOldeUser']) && isset($_POST['HOBAYeOldePassword'])){
        dump("HOBA: Handling HOBA+YeOlde Login Creds");
        $uid = dbCheckUserPass($_POST['HOBAYeOldeUser'], $_POST['HOBAYeOldePassword'], $dev['did']);
        if(! $uid === false){
          dbModSession($_COOKIE['HOBA'], false, false, false, 1);
          printHeader();
          printMeat(false, $dev['did'], "");
          printFooter();
        }else{
          printLoginFailure("HOBA: Bad Username / Password");
        }
      }else{
        dump("HOBA: Initiating HOBA+YeOlde Login");
        printHOBAYeOldePrompt();
      }

    }else{
      if(isset($_POST['uName'])){
        $err = dbSetUserName($dev['uid'], $_POST['uName']);
      }elseif(isset($_POST['uPass'])){
        $err = dbSetUserPass($dev['uid'], $_POST['uPass']);
      }elseif(isset($_POST['msg'])){
        $err = dbAddMsg($dev['uid'], $_POST['msg']);
      }elseif(isset($_POST['bondAttempt'])){
        $err = dbRequestBond($dev['did'], $_POST['bondAttemptTarget']);
      }elseif(isset($_POST['bondConfirm'])){
        if($_POST['bondMe'] === "false"){
          $err = dbDeleteBond($_POST['bondConfirmSource'], $dev['uid']);
        }elseif($_POST['bondMe'] === "true"){
          $err = dbConfirmBond($_POST['bondConfirmSource'], $dev['uid']);
        }
      }
      
      printHeader();
      if($err !== true){
        dump($err);
        printMeat(false, $dev['did'], $err);
      }else{
        printMeat(false, $dev['did'], "");
      }
      printFooter();
    }

  }else{
    dump("HOBA: No HOBA session found");
    printLoginFailure();
  }

}elseif(isset($_COOKIE['YEOLDE'])){
  dump("HOBA: Got YEOLDE cookie for " . $_COOKIE['YEOLDE']);
  
  $err = true;
  $user = dbGetUserByCookie($_COOKIE['YEOLDE']);
  if($user){
    //TODO: Refresh session if it's old
    
    if(isset($_POST['uPass'])){
      $err = dbSetUserPass($user['uid'], $_POST['uPass']);
    }elseif(isset($_POST['msg'])){
      $err = dbAddMsg($user['uid'], $_POST['msg']);
    }

    printHeader();
    if($err !== true){
      dump($err);
      printMeat($user['uName'], false, $err);
    }else{
      printMeat($user['uName'], false, "");
    }
    printFooter();
    
  }else{
    dump("HOBA: No YEOLDE session found");
    printLoginFailure();
  }
  
}else{
  dump("HOBA: No cookie set");
  if(isset($_POST['YeOldeLogin'])){ // Handle traditional logins
    dump("HOBA: Initiating YeOlde Login");
    if(isset($_POST['YeOldeUser']) && isset($_POST['YeOldePassword'])){
      $uid = dbCheckUserPass($_POST['YeOldeUser'], $_POST['YeOldePassword'], false);
      if(! $uid === false){
        $t = time() + $GLOBALS['sessionTimeout'];
        $chocolate = getCookieVal($uid, $uid);
        dbAddUserSession($uid, $chocolate, $t);
        setUserCookie($chocolate, $t);
        dump("HOBA: YeOlde Login Successful");

        $user = dbGetUserByCookie($chocolate);
        printHeader();
        printMeat($user['uName'], false, "");
        printFooter();

      }else{
        printLoginFailure("YeOlde Bad Username/Password");
      }
    }else{
      printLoginFailure("YeOlde Missing Username/Password");
    }
  }
}
dbLogout();
?>
