/*
    Security Extensions for Mozilla Thunderbird
    Copyright (C) 2015 by Ilker Temir (@ilkertemir) and Tim Sammut (@t1msammut)

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; version 2
    of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

function updateDetails() {
   var RBLNotes = window.arguments[0].notes;
   var ip;
   var code;
   var ipLink;
   var codeLink;

   var html = "<div style='text-align: center; padding: 20px; -moz-user-select: text;'>";
   html = html + "IP addresses found in RBL databases";
   html = html + "<table style='width: 400px; padding-top: 10px;'>";
   html = html + "<tr><td style='font-weight: bold;'>IP Address</td><td style='font-weight: bold;'>Return Code</td><td style='font-weight: bold;'>Service</td></tr>";
   for (var i in RBLNotes) {
       ip = RBLNotes[i].ip;
       code = RBLNotes[i].code;
       service = RBLNotes[i].service;
       html = html + "<tr><td>" + ip + "</td><td>" + code + "</td><td>" + service + "</td></tr>";
   }   
   html = html + "</table>";
   html = html + "</div>";

   var container = document.getElementById("containerBox");
   var divHTML = document.createElementNS("http://www.w3.org/1999/xhtml","div");

   divHTML.innerHTML = html;

   container.appendChild(divHTML);
}
