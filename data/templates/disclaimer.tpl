<html xmlns:t="http://twistedmatrix.com/ns/twisted.web.template/0.1">
  <head>
    <title>Tor2web</title>
    <meta http-equiv="content-type" content="text/html;charset=utf-8" />
    <meta http-equiv="content-language" content="en" />
    <meta name="robots" content="noindex" />
    <script type="text/javascript" src="/antanistaticmap/tor2web.js"></script>
    <style type="text/css">
      @import url(/antanistaticmap/tor2web.css);
    </style>
  </head>
  <body>
    <div id="tor2web">
      <div id="header">
        <h1><a href="https://www.tor2web.org"><img src="/antanistaticmap/tor2web.png" alt="tor2web logo" /></a></h1>
      </div>
      <div id="tor2web_disclaimer">
        <div><b>tor2web.org does not host this content</b>; the service is simply a proxy connecting Internet users to content hosted inside the <a href="https://www.torproject.org/docs/hidden-services.html.en">Tor network.</a></div>
<div>Please be aware that when you access this site through a Tor2web proxy you are not anonymous. To obtain anonymity, you are strongly advised to <a href="https://www.torproject.org/download/">download the Tor Browser Bundle</a> and access this content over Tor.</div>
        <div>Please send us your <a href="javascript:show_hide_notification_form()">feedback</a> and if you have concerns with this content, send us an <a href="javascript:show_hide_notification_form()">abuse notice</a>.</div>
        <div id="tor2web_notification_form">
          <fieldset>
            <legend>Notification:</legend>
            BY:
            <div><input type="text" id="by" name="by" /></div>
            URL:
            <div><input type="text" id="url" name="url" /></div>
            COMMENT:
            <div><textarea type="text" id="comment" name="comment" rows="10" cols="20"></textarea></div>
            <div><input type="button" value="Send" onclick="sendNotification()" /></div>
          </fieldset>
        </div>
        <div><t:transparent t:render="mirror" /></div>
      </div>
      <div id="tor2web_disclaimer_acceptance">
        <div>By accessing this site you acknowledge that you have understood:</div>
        <ul>
          <li>What Tor Hidden Services are and how they works;</li>
          <li>What Tor2web is and how it works;</li>
          <li>That Tor2web operator running cannot block this site in any way;</li>
          <li>The content of the <t:transparent t:render="t2wvar-onion" />.onion website is responsibility of it's editor.</li>
        </ul>
        <br />
        <div>By the way, just to be clear:</div>
        <br /><br />
        <center><b>THIS SERVER IS A PROXY AND IT’S NOT HOSTING THE TOR HIDDEN SERVICE SITE <t:transparent t:render="t2wvar-onion" />.onion</b></center>
        <br/><br />
        <input id="tor2web_disclaimer_button" type="button" value="I agree with the terms, let me access the content" onclick="t2w()" />
      </div>
      <div id="tor2web_footer">
        Tor2Web has been originally developed by <a href="http://en.wikipedia.org/wiki/Aaron_Swartz">Aaron Swartz</a> and <a href="http://en.wikipedia.org/wiki/Virgil_Griffith">Virgil Griffith</a>.<br />
        It is currently being actively developed and maintained by the<br />
        <a href="http://logioshermes.org/">HERMES Center for Transparency and Digital Human Rights</a>
      </div>
    </div>
  </body>
</html>
