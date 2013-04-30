/** This is a cookie handling library from: http://code.google.com/p/cookies/wiki/License **/
(function(global){"use strict";var document=global.document,Object=global.Object,JSON=global.JSON,jaaulde=global.jaaulde=(global.jaaulde||{});jaaulde.utils=jaaulde.utils||{};jaaulde.utils.cookies=(function(){var defaultOptions,resolveOptions,assembleOptionsString,isNaN,trim,parseCookies,Constructor;defaultOptions={expiresAt:null,path:'/',domain:null,secure:false};resolveOptions=function(options){var returnValue,expireDate;if(typeof options!=='object'||options===null){returnValue=defaultOptions}else{returnValue={expiresAt:defaultOptions.expiresAt,path:defaultOptions.path,domain:defaultOptions.domain,secure:defaultOptions.secure};if(typeof options.expiresAt==='object'&&options.expiresAt instanceof Date){returnValue.expiresAt=options.expiresAt}else if(typeof options.hoursToLive==='number'&&options.hoursToLive!==0){expireDate=new global.Date();expireDate.setTime(expireDate.getTime()+(options.hoursToLive*60*60*1000));returnValue.expiresAt=expireDate}if(typeof options.path==='string'&&options.path!==''){returnValue.path=options.path}if(typeof options.domain==='string'&&options.domain!==''){returnValue.domain=options.domain}if(options.secure===true){returnValue.secure=options.secure}}return returnValue};assembleOptionsString=function(options){options=resolveOptions(options);return((typeof options.expiresAt==='object'&&options.expiresAt instanceof Date?'; expires='+options.expiresAt.toGMTString():'')+'; path='+options.path+(typeof options.domain==='string'?'; domain='+options.domain:'')+(options.secure===true?'; secure':''))};trim=global.String.prototype.trim?function(data){return global.String.prototype.trim.call(data)}:(function(){var trimLeft,trimRight;trimLeft=/^\s+/;trimRight=/\s+$/;return function(data){return data.replace(trimLeft,'').replace(trimRight,'')}}());isNaN=(function(){var rdigit=/\d/,isNaN=global.isNaN;return function(obj){return(obj===null||!rdigit.test(obj)||isNaN(obj))}}());parseCookies=(function(){var parseJSON,rbrace;parseJSON=JSON&&JSON.parse?function(data){var returnValue=null;if(typeof data==='string'&&data!==''){data=trim(data);if(data!==''){try{returnValue=JSON.parse(data)}catch(e1){returnValue=null}}}return returnValue}:function(){return null};rbrace=/^(?:\{.*\}|\[.*\])$/;return function(){var cookies,splitOnSemiColons,cookieCount,i,splitOnEquals,name,rawValue,value;cookies={};splitOnSemiColons=document.cookie.split(';');cookieCount=splitOnSemiColons.length;for(i=0;i<cookieCount;i=i+1){splitOnEquals=splitOnSemiColons[i].split('=');name=trim(splitOnEquals.shift());if(splitOnEquals.length>=1){rawValue=splitOnEquals.join('=')}else{rawValue=''}try{value=decodeURIComponent(rawValue)}catch(e2){value=rawValue}try{value=value==='true'?true:value==='false'?false:!isNaN(value)?parseFloat(value):rbrace.test(value)?parseJSON(value):value}catch(e3){}cookies[name]=value}return cookies}}());Constructor=function(){};Constructor.prototype.get=function(cookieName){var returnValue,item,cookies;cookies=parseCookies();if(typeof cookieName==='string'){returnValue=(typeof cookies[cookieName]!=='undefined')?cookies[cookieName]:null}else if(typeof cookieName==='object'&&cookieName!==null){returnValue={};for(item in cookieName){if(Object.prototype.hasOwnProperty.call(cookieName,item)){if(typeof cookies[cookieName[item]]!=='undefined'){returnValue[cookieName[item]]=cookies[cookieName[item]]}else{returnValue[cookieName[item]]=null}}}}else{returnValue=cookies}return returnValue};Constructor.prototype.filter=function(cookieNameRegExp){var cookieName,returnValue,cookies;returnValue={};cookies=parseCookies();if(typeof cookieNameRegExp==='string'){cookieNameRegExp=new RegExp(cookieNameRegExp)}for(cookieName in cookies){if(Object.prototype.hasOwnProperty.call(cookies,cookieName)&&cookieName.match(cookieNameRegExp)){returnValue[cookieName]=cookies[cookieName]}}return returnValue};Constructor.prototype.set=function(cookieName,value,options){if(typeof options!=='object'||options===null){options={}}if(typeof value==='undefined'||value===null){value='';options.hoursToLive=-8760}else{value=value===true?'true':value===false?'false':!isNaN(value)?''+value:value;if(typeof value!=='string'){if(typeof JSON==='object'&&JSON!==null&&typeof JSON.stringify==='function'){value=JSON.stringify(value)}else{throw new Error('cookies.set() received value which could not be serialized.');}}}var optionsString=assembleOptionsString(options);document.cookie=cookieName+'='+encodeURIComponent(value)+optionsString};Constructor.prototype.del=function(cookieName,options){var allCookies,name;allCookies={};if(typeof options!=='object'||options===null){options={}}if(typeof cookieName==='boolean'&&cookieName===true){allCookies=this.get()}else if(typeof cookieName==='string'){allCookies[cookieName]=true}for(name in allCookies){if(Object.prototype.hasOwnProperty.call(allCookies,name)&&typeof name==='string'&&name!==''){this.set(name,null,options)}}};Constructor.prototype.test=function(){var returnValue,testName,testValue;testName='cookiesCT';testValue='data';this.set(testName,testValue);if(this.get(testName)===testValue){this.del(testName);returnValue=true}return returnValue};Constructor.prototype.setOptions=function(options){if(typeof options!=='object'){options=null}defaultOptions=resolveOptions(options)};return new Constructor()}())}(window));

function getHTTPObject() {
  var http = false;
  if (XMLHttpRequest) {
    try {http = new XMLHttpRequest();}
    catch (e) {http = false;}
  } else if(typeof ActiveXObject != 'undefined') {
    try {http = new ActiveXObject("Msxml2.tplHTTP");}
    catch (e) {
      try {http = new ActiveXObject("Microsoft.tplHTTP");}
      catch (E) {http = false;}
    }
  }
  return http;
}

function handler() {
  if(http.readyState == 4 && http.status == 200) {
    show_hide_notification_form()
  }
}

function sendNotification() {
  var by = document.getElementById('by').value;
  var url = document.getElementById('url').value;
  var comment = document.getElementById('comment').value;
  var params = "by="+by+"&url="+url+"&comment="+comment;

  http.open("POST", "/antanistaticmap/notification", true);
	
  http.setRequestHeader("Content-type", "application/x-www-form-urlencoded");

  http.onreadystatechange = handler;
  
  http.send(params);
}

function show_hide_tor2web_header(status) {
  if(status == true) {
    document.getElementById("tor2web-visible").style.display = 'none';
    document.getElementById("tor2web-hidden").style.display = 'block';
    jaaulde.utils.cookies.set('tor2web_header_hidden', 'true');
  } else {
    document.getElementById("tor2web-hidden").style.display = 'none';
    document.getElementById("tor2web-visible").style.display = 'block';
    jaaulde.utils.cookies.set('tor2web_header_hidden', 'false');
  }
}

function show_hide_notification_form() {
  if(tor2web_notification_form_visible == true) {
    tor2web_notification_form_visible = false;
    document.getElementById("tor2web_notification_form").style.display = 'block';
  } else {
    tor2web_notification_form_visible = true;
    document.getElementById("tor2web_notification_form").style.display = 'none';
  }
}

var tor2web_notification_form_visible = true;
var http = getHTTPObject();

window.onload = function() {
  if(jaaulde.utils.cookies.get('tor2web_header_hidden') && jaaulde.utils.cookies.get('tor2web_header_hidden') == true) {
    show_hide_tor2web_header(true);
  }
  if(document.getElementById('tor2web-header') != null) {
    document.getElementById('url').value = document.location;
  }
}
