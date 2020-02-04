window.addEventListener("message", receiveMessage, false);

function receiveMessage(e) {
  if (!e.data || typeof e.data != 'string' || e.data == 'error') {
    return;
  }

  var status;
  try {
    var clientId = e.data.split(' ')[0];
    var sessionState = e.data.split(' ')[1];
    var salt = sessionState.split('.')[1];

    var browserState = getOpBrowserState();

    var sessionStateCalculated = sha256(clientId + ' ' + e.origin + ' ' + browserState + ' ' + salt) + '.' + salt;

    if (sessionState == sessionStateCalculated) {
      status = 'unchanged';
    } else {
      status = 'changed';
    }
  } catch (err) {
    status = 'error';
  }
  e.source.postMessage(status, e.origin);
};

function getOpBrowserState() {
  var theName = 'op_browser_state=';
  var theCookie = document.cookie + ';';
  var start = theCookie.indexOf(theName);
  if (start != -1) {
    var end = theCookie.indexOf(';', start);
    return unescape(theCookie.substring(start + theName.length, end));
  }
  throw new Error('We couldn\'t find the "op_browser_state" cookie.');
}
