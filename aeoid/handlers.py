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

# list of attributes to request via Simple Registration
OPENID_SREG_ATTRS = ['nickname', 'email']

# dict of uris => attributes to request via Attribute Exchange
OPENID_AX_ATTRS = {
    'http://axschema.org/contact/email':        'email',
    'http://axschema.org/namePerson/friendly':  'nickname',
    'http://axschema.org/namePerson/first':     'firstname',
    'http://axschema.org/namePerson/last':      'lastname',
}

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

    consumer = self.get_consumer()
    # if consumer discovery or authentication fails, show error page
    try:
      request = consumer.begin(openid_url)
    except Exception, e:
      logging.error("Unexpected error in OpenID discovery/authentication: %s", e)
      self.render_template('error.html')
      return
    
    # TODO: Support custom specification of extensions
    # TODO: Don't ask for data we already have, perhaps?
    # use Simple Registration if available
    request.addExtension(sreg.SRegRequest(required=OPENID_SREG_ATTRS))
    # or Atribute Exchange if available
    ax_request = ax.FetchRequest()
    for attruri in OPENID_AX_ATTRS:
        ax_request.add(ax.AttrInfo(attruri, required=True, alias=OPENID_AX_ATTRS[attruri]))
    request.addExtension(ax_request)
    # assemble and send redirect
    continue_url = self.request.get('continue', '/')
    return_to = "%s%s?continue=%s" % (self.request.host_url,
                                      users.OPENID_FINISH_PATH, continue_url)
    self.redirect(request.redirectURL(self.request.host_url, return_to))
    self.session.save()

  def post(self):
    self.get()


class FinishLoginHandler(BaseHandler):
  def finish_login(self, response):
    # get sreg data if available
    id_res_data = sreg.SRegResponse.fromSuccessResponse(response)
    if not id_res_data is None:
      id_res_data = dict(id_res_data)
    
    # otherwise get ax data if available
    if id_res_data is None:
      id_res_data = {}
      try:
        ax_data = ax.FetchResponse.fromSuccessResponse(response)
        for attruri in OPENID_AX_ATTRS:
          try:
            attrvalue = ax_data.get(attruri)
            id_res_data[ OPENID_AX_ATTRS[attruri] ] = attrvalue.pop(0)
          except (AttributeError,IndexError,KeyError):
            pass
        # try to ensure we have a nickname (even if we fall back to email)
        if not id_res_data.has_key('nickname'):
          if id_res_data.has_key('firstname') or id_res_data.has_key('lastname'):
            id_res_data['nickname'] = id_res_data.get('firstname', '') + ' ' + id_res_data.get('lastname', '')
          elif id_res_data.has_key('email'):
            id_res_data['nickname'] = id_res_data['email']
      except ax.AXError:
        pass

    user_info = users.UserInfo.update_or_insert(
        response.endpoint.claimed_id,
        server_url=response.endpoint.server_url,
        **id_res_data)

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
    # before logging user out, check that http referer contains the current hostname
    httphost = str(self.request.environ.get('HTTP_HOST'))
    httprefer = str(self.request.environ.get('HTTP_REFERER'))
    # if it does, log them out as expected
    if httprefer.startswith(('http://'+httphost,'https://'+httphost)):
      if 'aeoid.user' in self.session:
        del self.session['aeoid.user']
      self.session.save()
      self.redirect(self.request.get('continue', '/'))
    # if it doesn't, prompt them via an interstitial page
    else:
      self.render_template('logout.html', {
          'confirmurl': '?continue='+self.request.get('continue', '/'),
          'cancelurl': self.request.get('continue', '/')
      })


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
