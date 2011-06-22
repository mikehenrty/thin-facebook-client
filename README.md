# Thin Facebook Client

A simple PHP client for the Facebook Graph API and oAuth 2.0. Useful for canvas apps.


## Examples

### Authorization
```
  $fb = new ThinFacebookClient(
    CONFIG::FACEBOOK_APP_ID, 
    CONFIG::FACEBOOK_APP_SECRET, 
    CONFIG::FACEBOOK_APP_URL, 
    CONFIG::CANVAS_URL, 
    CONFIG::CANVAS_DOMAIN
  );
  if (!$fb->isAuthorized()) {
    $fb->redirectAuthorize($_GET);
  }
```

### Restoring last request
If a user's Facebook session expires, the thin client can restore the user's last http request
after re-authenticating through Facebook automatically (so user's experience isn't interrupted).
```
  $old_get_request = $fb->getAuthPassback();
  if (!empty($old_get_request)) {
    foreach($old_get_request as $key => $value) {
      $_GET[$key] = $value;
    }
  }
```

### Query Graph API for user's basic info
```
  $fb_user = $fb->getUserInfo($fbuid);
```

