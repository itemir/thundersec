/*
    DNSBL/RBL Add-on for Mozilla Thunderbird
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

// Clear input on click if it is the same value
function clearInput() {
   var textField = document.getElementById("string.custom_rbl");
   if (textField.value == "dnsbl.example.com") {
       alert ('You can enter your DNSBL servers of choice.\n\n' +
              'If you want to add multiple sources, separate them with comma or space.\n\n' +
              'Example: dnsbl.domain1.com, rbl.domain2.com');
       document.getElementById("string.custom_rbl").value = "";
   }
}

// Enables and disables RBL entry box based on checkbox
function enableCustomRBL(item) {
   var textField = document.getElementById("string.custom_rbl");
   // .checked is updated after this event fires, so actions are pro-active
   if (item.checked) {
       document.getElementById("string.custom_rbl").setAttribute("disabled", true);
   }
   else {
       document.getElementById("string.custom_rbl").removeAttribute("disabled");
   } 
}
