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
import sys
sys.path.append(os.path.dirname(__file__))

from beaker.middleware import SessionMiddleware
from google.appengine.ext import webapp

from aeoid import handlers
from aeoid import users


class _MiddlewareImpl(object):
  def __init__(self, application, debug=False):
    self.application = application
    self.oid_app = webapp.WSGIApplication(handlers.handler_map, debug=debug)

  def __call__(self, environ, start_response):
    session = environ['aeoid.beaker.session']
    if 'aeoid.user' in session:
      os.environ['aeoid.user'] = environ['aeoid.user'] = session['aeoid.user']
    try:
      if environ['PATH_INFO'].startswith(users.OPENID_PATH_PREFIX):
        return self.oid_app(environ, start_response)
      else:
        return self.application(environ, start_response)
    finally:
      users._current_user = None


def AeoidMiddleware(application, session_opts=None, debug=False):
  """WSGI middleware that adds support for OpenID user authentication."""

  beaker_opts = {
      'session.type': 'ext:google',
      'session.key': 'aeoid.beaker.session.id',
  }
  if session_opts:
    beaker_opts.update(session_opts)
  application = _MiddlewareImpl(application, debug)
  application = SessionMiddleware(wrap_app=application, config=beaker_opts, environ_key='aeoid.beaker.session')
  return application
