var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var InternalOAuthError = require('passport-oauth2').InternalOAuthError;

// use the new userinfo endpoint
var profileUrl = 'https://api.linkedin.com/v2/userinfo';

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL =
    options.authorizationURL ||
    'https://www.linkedin.com/oauth/v2/authorization';
  options.tokenURL =
    options.tokenURL || 'https://www.linkedin.com/oauth/v2/accessToken';
  options.scope = options.scope || ['openid', 'profile', 'email'];

  // JSON output
  options.customHeaders = options.customHeaders || { 'x-li-format': 'json' };

  OAuth2Strategy.call(this, options, verify);
  this.name = 'linkedin';
  this.profileUrl = profileUrl;
}

util.inherits(Strategy, OAuth2Strategy);

// fetch userinfo
Strategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.setAccessTokenName('oauth2_access_token');
  this._oauth2.get(this.profileUrl, accessToken, function (err, body) {
    if (err) {
      return done(new InternalOAuthError('failed to fetch user profile', err));
    }
    try {
      var profile = parseProfile(body);
      done(null, profile);
    } catch (e) {
      done(new InternalOAuthError('failed to parse profile response', e));
    }
  });
};

function parseProfile(body) {
  var json = JSON.parse(body);

  return {
    provider: 'linkedin',
    id: json.sub,
    emails: [{
      value: json.email,
      verified: json.email_verified
    }],
    name: {
      givenName: json.given_name,
      familyName: json.family_name
    },
    displayName: json.given_name + ' ' + json.family_name,
    photos: json.picture ? [{ value: json.picture }] : [],
    _raw: body,
    _json: json
  };
}

module.exports = Strategy;
