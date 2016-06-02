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

function pollLogin(){
  $.ajax({
    url: "login_status.php",
    dataType: "text",
    success: function(res){
      //$("div.debug").html(result);
      if(res.trim() == "1"){
	window.location.assign("https://hoba.name/main.php");
      }else{
	setTimeout(pollLogin(), 3000);
      }
    }
  });
}
