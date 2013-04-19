<div xmlns:t="http://twistedmatrix.com/ns/twisted.web.template/0.1">
<script type="text/javascript" src="/antanistaticmap/tor2web.js"></script>
<style type="text/css">
@import url(/antanistaticmap/tor2web.css);
</style>

<div id="tor2web-header">
  <div id="tor2web-visible">
    <div id="tor2web_logo">
      <a href="https://www.tor2web.org"><img src="/antanistaticmap/tor2web-small.png" alt="tor2web logo" /></a>
    </div>
    <div id="tor2web_disclaimer">
    <div><b>tor2web.org does not host this content</b>; we are simply a conduit connecting Internet users to content hosted inside <a href="https://www.torproject.org/docs/hidden-services.html.en">the Tor network.</a></div>
<div>To obtain anonymity, you are strongly advised to <a href="https://www.torproject.org/download/">download the Tor Browser Bundle</a> and access this content over Tor.</div>
      <div>Please send us your <a href="javascript:show_hide_notification_form()">feedback</a> and if you have concerns with this content, send us an <a href="javascript:show_hide_notification_form()">abuse notice</a>.</div>
      <div>For more informations please refer to <a href="/antanistaticmap/tos.html">Tor2Web Terms of Services.</a></div>
      <div><t:transparent t:render="mirror" /></div>
      <div>Software Version: <a href="https://github.com/globaleaks/Tor2web-3.0"><t:transparent t:render="t2wvar-version" /></a></div>
    </div>
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
    <div style="clear:both"></div>
    <div class="tor2web_showhide">
      <a href="javascript:show_hide_tor2web_header(true)">hide Tor2web header</a>
    </div>
  </div>
  <div id="tor2web-hidden">
    <div class="tor2web_showhide">
      <a href="javascript:show_hide_tor2web_header(false)">show Tor2web header</a>
    </div>
  </div>
</div>
</div>
