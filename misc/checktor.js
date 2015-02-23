/*
  Copyright 2015 - Hermes Center - GlobaLeaks project
  Author <giovanni.pellerano@evilaliv3.org>

  Javascript CheckTor library
*/

function redirectIfOnTor(url, test_url) {
  // Test if the user is using Tor and in that case
  // redirects the user to provided url
  try {
    if (typeof(test_url) === 'undefined') {
      var test_url = 'https://antani.tor2web.org/checktor';
    }
    if (window.XMLHttpRequest) {
      var xmlhttp = new XMLHttpRequest();

      xmlhttp.onreadystatechange=function() {
        if (xmlhttp.readyState==4 && xmlhttp.status==200) {
          if (xmlhttp.getResponseHeader("x-check-tor")) {
            window.location.href = url;
          }
        }
      }

      xmlhttp.open("GET", test_url, true);
      xmlhttp.send();

    }
  } catch(err) {

  }
}
