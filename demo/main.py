#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import logging
import urllib

from google.appengine.ext import db
from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from google.appengine.ext.webapp import util
from aeoid import middleware, users


class LoginRecord(db.Model):
  user = users.UserProperty(auto_current_user_add=True, required=True)
  timestamp = db.DateTimeProperty(auto_now_add=True)


class LoginHandler(webapp.RequestHandler):
  def get(self):
    if users.get_current_user():
      login = LoginRecord()
      logging.warn(login.user)
      login.put()
    self.redirect('/')


class AppsFederationHandler(webapp.RequestHandler):
  """Handles openid login for federated Google Apps Marketplace apps."""
  def get(self):
    domain = self.request.get("domain")
    if not domain:
      self.redirect("/login")
    else:
      openid_url = "https://www.google.com/accounts/o8/site-xrds?hd=" + domain
      self.redirect("%s?openid_url=%s" %
                    (users.OPENID_LOGIN_PATH, urllib.quote(openid_url)))


class MainHandler(webapp.RequestHandler):
  def render_template(self, file, template_vals):
    path = os.path.join(os.path.dirname(__file__), 'templates', file)
    self.response.out.write(template.render(path, template_vals))
    
  def get(self):
    user = users.get_current_user()
    logins = LoginRecord.all().order('-timestamp').fetch(20)
    logging.warn([x.user for x in logins])
    self.render_template("index.html", {
        'login_url': users.create_login_url('/login'),
        'logout_url': users.create_logout_url('/'),
        'user': user,
        'logins': logins,
    })


application = webapp.WSGIApplication([
    ('/', MainHandler),
    ('/login', LoginHandler),
    ('/apps_login', AppsFederationHandler),
], debug=True)
application = middleware.AeoidMiddleware(application)

def main():
  util.run_wsgi_app(application)


if __name__ == '__main__':
  main()
