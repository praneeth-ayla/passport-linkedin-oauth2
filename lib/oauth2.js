var util = require('util')
var OAuth2Strategy = require('passport-oauth2')
var InternalOAuthError = require('passport-oauth2').InternalOAuthError

// endpoints
var USERINFO_URL   = 'https://api.linkedin.com/v2/userinfo'
var LEGACY_ME_URL  = 'https://api.linkedin.com/v2/me'
var EMAIL_URL      = 'https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))'

function Strategy(options, verify) {
  options = options || {}
  options.authorizationURL = options.authorizationURL ||
    'https://www.linkedin.com/oauth/v2/authorization'
  options.tokenURL = options.tokenURL ||
    'https://www.linkedin.com/oauth/v2/accessToken'

  // default scopes for OIDC
  options.scope = options.scope || ['openid','r_liteprofile','r_emailaddress']
  options.customHeaders = options.customHeaders || { 'x-li-format': 'json' }

  OAuth2Strategy.call(this, options, verify)
  this.name = 'linkedin'
  this._profileUrl = options.scope.includes('r_basicprofile')
    ? LEGACY_ME_URL
    : USERINFO_URL
}

util.inherits(Strategy, OAuth2Strategy)

Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.setAccessTokenName('oauth2_access_token')

  // 1) get profile
  this._oauth2.get(this._profileUrl, accessToken, (err, body) => {
    if (err) return done(new InternalOAuthError('failed to fetch user profile', err))

    let profile
    try {
      profile = parseProfile(body, this._profileUrl)
    } catch (e) {
      return done(new InternalOAuthError('failed to parse profile', e))
    }

    // 2) optionally fetch email
    if (this.options.scope.includes('r_emailaddress')) {
      this._oauth2.get(EMAIL_URL, accessToken, (err2, emailBody) => {
        if (err2) {
          // give back profile without email rather than error out
          return done(null, profile)
        }
        try {
          profile.emails = extractEmails(emailBody)
        } catch (e) {
          // ignore parse errors
        }
        done(null, profile)
      })
    } else {
      done(null, profile)
    }
  })
}

function parseProfile(body, url) {
  var json = JSON.parse(body)
  var p = { provider: 'linkedin', _raw: body, _json: json }

  if (url === USERINFO_URL) {
    // OIDC response shape
    p.id = json.sub
    p.name = { givenName: json.given_name, familyName: json.family_name }
    p.displayName = `${json.given_name} ${json.family_name}`
    p.photos = json.picture ? [{ value: json.picture }] : []
  } else {
    // legacy /v2/me shape
    p.id = json.id
    p.name = {
      givenName: (json.localizedFirstName||''),
      familyName: (json.localizedLastName||'')
    }
    p.displayName = `${p.name.givenName} ${p.name.familyName}`
    // extract first profilePicture element if available
    try {
      let picEl = json.profilePicture['displayImage~'].elements[0].identifiers[0]
      p.photos = [{ value: picEl.identifier }]
    } catch (_) {
      p.photos = []
    }
  }

  return p
}

function extractEmails(body) {
  var json = JSON.parse(body)
  var elements = json.elements||[]
  return elements
    .map(el => el['handle~'] && el['handle~'].emailAddress)
    .filter(Boolean)
    .map(email => ({ value: email }))
}

module.exports = Strategy
