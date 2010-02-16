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

import logging
import os

from google.appengine.ext import webapp
from google.appengine.ext.webapp import template
from openid.consumer.consumer import Consumer
from openid.consumer.discover import DiscoveryFailure
from openid.extensions import sreg
from openid.extensions import ax

from aeoid import store
from aeoid import users


class BaseHandler(webapp.RequestHandler):
  def initialize(self, request, response):
    super(BaseHandler, self).initialize(request, response)
    self.session = self.request.environ.get('aeoid.beaker.session')

  def render_template(self, filename, template_args=None):
    if not template_args:
      template_args = {}
    path = os.path.join(os.path.dirname(__file__), 'templates', filename)
    self.response.out.write(template.render(path, template_args))

  def get_consumer(self):
    return Consumer(self.session, store.AppEngineStore())


class BeginLoginHandler(BaseHandler):
  def get(self):
    openid_url = self.request.get('openid_url')
    if not openid_url:
      self.render_template('login.html', {
          'login_url': users.OPENID_LOGIN_PATH,
          'continue': self.request.get('continue', '/')
      })
      return

    try:
      consumer = self.get_consumer()
      request = consumer.begin(openid_url)
			
      # TODO: Support custom specification of extensions
      # TODO: Don't ask for data we already have, perhaps?
      request.addExtension(sreg.SRegRequest(required=['nickname', 'email']))    
      ax_req = ax.FetchRequest()
      ax_req.add(ax.AttrInfo('http://axschema.org/contact/email', alias='email',required=True))
      ax_req.add(ax.AttrInfo('http://axschema.org/namePerson/first', alias='firstname',required=True))
      request.addExtension(ax_req)
      
      continue_url = self.request.get('continue', '/')
      return_to = "%s%s?continue=%s" % (self.request.host_url,
                                        users.OPENID_FINISH_PATH, continue_url)
      self.redirect(request.redirectURL(self.request.host_url, return_to))
      self.session.save()
    except DiscoveryFailure, ex:
      logging.error("Unexpected error in OpenID authentication: %s" % ex)
      self.render_template('error.html', {'identity_url': openid_url})


  def post(self):
    self.get()


class FinishLoginHandler(BaseHandler):
  def finish_login(self, response):
    sreg_data = sreg.SRegResponse.fromSuccessResponse(response) or {}
    #ax_fetch = ax.FetchResponse.fromSuccessResponse(response)
    #if ax_fetch:
    #  ax_data = ax_fetch.getExtensionArgs();
    #else:
    #  ax_data = {}
      
    #for k, v in ax_data.items():
    #  logging.info("key: " + k + ", value: " + v)
    
    #user_info = users.UserInfo.update_or_insert(
    #    response.endpoint.claimed_id,
    #    server_url=response.endpoint.server_url,
    #    **dict(sreg_data))

    ax_data = {}
    ax_fetch = ax.FetchResponse.fromSuccessResponse(response)
    if ax_fetch:
      args = ax_fetch.getExtensionArgs()
      i = 0
      while "type.ext%i" % i in args:
        t = args["type.ext%i" % i]
        logging.info("type: %s" % t)
        if t == "http://axschema.org/namePerson/first":
          p = "nickname"
        elif t == "http://axschema.org/contact/email":
          p = "email"
        else:
          p = "unknown"
        ax_data[p] = args["value.ext%i.1" % i]
        i = i + 1

    res_data = {}
    res_data.update(sreg_data)
    res_data.update(ax_data)
    
    user_info = users.UserInfo.update_or_insert(
        response.endpoint.claimed_id,
        server_url=response.endpoint.server_url,
        **dict(res_data))
    
    self.session['aeoid.user'] = str(user_info.key())
    self.session.save()
    users._current_user = users.User(None, _from_model_key=user_info.key(),
                                     _from_model=user_info)
    self.redirect(self.request.get('continue', '/'))

  def get(self):
    consumer = self.get_consumer()
    response = consumer.complete(self.request.GET, self.request.url)
    if response.status == 'success':
      self.finish_login(response)
    elif response.status in ('failure', 'cancel'):
      self.render_template('failure.html', {
          'response': response,
          'login_url': users.OPENID_LOGIN_PATH,
          'continue': self.request.get('continue', '/')
      })
    else:
      logging.error("Unexpected error in OpenID authentication: %s", response)
      self.render_template('error.html', {'identity_url': response.identity_url()})


class LogoutHandler(BaseHandler):
  def get(self):
    # TODO: Handle the possibility of XSRF forcing a user to log out
    if 'aeoid.user' in self.session:
      del self.session['aeoid.user']
    self.session.save()
    self.redirect(self.request.get('continue', '/'))


# highly modified from example at:
# http://www.ipsojobs.com/blog/2008/06/17/how-to-create-a-simple-but-powerful-cdn-with-google-app-engine-gae/
class StaticHandler(webapp.RequestHandler):
  allowed_exts = { 'js': 'application/x-javascript', 'css': 'text/css', 'png': 'image/png' }
  
  def get(self, filepath, fileext):
    # build full system path to requested file
    resourcepath = os.path.join( os.path.dirname(__file__), 'resources', filepath + '.' + fileext )
    
    # only allow specified file extensions
    if not self.allowed_exts.has_key(fileext):
      logging.error("Not an allowed file extension: %s" % fileext)
      self.error(404)
      return
    
    # file must exist before we can return it
    if not os.path.isfile(resourcepath):
      logging.error("Not an existing file: '%s'" % resourcepath)
      self.error(404)
      return
    
    # only allow absolute paths (no symlinks or up-level references, for example)
    testpath = os.path.normcase(resourcepath)
    if testpath != os.path.abspath(testpath):
      logging.error("Not an absolute path to file: '%s' != '%s'" % (testpath, os.path.abspath(testpath)) )
      self.error(403)
      return
    
    # set appropriate content-type
    self.response.headers['Content-Type'] = self.allowed_exts[fileext]
    
    # serve file (supporting client-side caching)
    try:
      import datetime
      fileinfo = os.stat(resourcepath)
      lastmod = datetime.datetime.fromtimestamp(fileinfo[8])
      if self.request.headers.has_key('If-Modified-Since'):
        dt = self.request.headers.get('If-Modified-Since').split(';')[0]
        modsince = datetime.datetime.strptime(dt, "%a, %d %b %Y %H:%M:%S %Z")
        if modsince >= lastmod:
        # The file is older than the cached copy (or exactly the same)
          self.error(304)
          return
        else:
        # The file is newer
          self.output_file(resourcepath, lastmod)
      else:
        self.output_file(resourcepath, lastmod)
    except Exception, e:
      logging.error("Failed to serve file: %s" % e)
      self.error(404)
      return

  def output_file(self, resourcepath, lastmod):
    import datetime
    try:
      self.response.headers['Cache-Control']='public, max-age=31536000'
      self.response.headers['Last-Modified'] = lastmod.strftime("%a, %d %b %Y %H:%M:%S GMT")
      expires=lastmod+datetime.timedelta(days=365)
      self.response.headers['Expires'] = expires.strftime("%a, %d %b %Y %H:%M:%S GMT")
      self.response.out.write( file(resourcepath, 'rb').read() )
      return
    except IOError, e:
      logging.error("Failed to output file: %s" % e)
      self.error(404)
      return


handler_map = [
    (users.OPENID_LOGIN_PATH, BeginLoginHandler),
    (users.OPENID_FINISH_PATH, FinishLoginHandler),
    (users.OPENID_LOGOUT_PATH, LogoutHandler),
    (users.OPENID_STATIC_PATH, StaticHandler),
]
