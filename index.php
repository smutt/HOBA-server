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

if(isset($_COOKIE['HOBA_LOGIN'])){
  if($_COOKIE['HOBA_LOGIN'] == "failed"){
    dump("Got cookie login failed");
    printLoginFailure();
    exit(1);
  }
}

dbLogin();

// Test for cookies
if(isset($_COOKIE['HOBA'])){
  dump("Got cookie for " . $_COOKIE['HOBA']);
  
  $dev = dbGetDeviceByCookie($_COOKIE['HOBA']);
  if($dev){
    if(isset($_POST['uName'])){
      $err = dbSetUserName($dev['uid'], $_POST['uName']);
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
    if(isset($err)){
      if($err !== true){
        dump($err);
        printMeat($dev['did'], $err);
      }else{
        printMeat($dev['did'], "");
      }
    }else{
      printMeat($dev['did'], "");
    }
    printFooter();

  }else{
    printRefresher();
  }
}else{
  if(isset($_COOKIE['HOBA_LOGIN'])){
    if($_COOKIE['HOBA_LOGIN'] == "attempt"){
      printLoginFailure();
      dbLogout();
      exit(1);
    }
  }
  printRefresher();
}
dbLogout();
?>
