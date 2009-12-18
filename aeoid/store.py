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

from google.appengine.api import memcache
from openid.association import Association as OpenIDAssociation
from openid.store import interface
from openid.store import nonce


MEMCACHE_NAMESPACE = "aeoid"


class AppEngineStore(interface.OpenIDStore):
  def getAssociationKeys(self, server_url, handle):
    return ("assoc:%s" % (server_url,),
            "assoc:%s:%s" % (server_url, handle))

  def storeAssociation(self, server_url, association):
    data = association.serialize()
    key1, key2 = self.getAssociationKeys(server_url, association.handle)
    memcache.set_multi({key1: data, key2: data},
                       namespace=MEMCACHE_NAMESPACE)

  def getAssociation(self, server_url, handle=None):
    key1, key2 = self.getAssociationKeys(server_url, handle)
    if handle:
      results = memcache.get_multi([key1, key2], namespace=MEMCACHE_NAMESPACE)
    else:
      results = {key1: memcache.get(key1, namespace=MEMCACHE_NAMESPACE)}
    data = results.get(key2) or results.get(key1)
    if data:
      return OpenIDAssociation.deserialize(data)
    else:
      return None

  def removeAssociation(self, server_url, handle):
    key1, key2 = self.getAssociationKeys(server_url, handle)
    return memcache.delete(key2) == 2

  def useNonce(self, server_url, timestamp, salt):
    nonce_key = "nonce:%s:%s" % (server_url, salt)
    expires_at = timestamp + nonce.SKEW
    return memcache.add(nonce_key, None, time=expires_at,
                        namespace=MEMCACHE_NAMESPACE)
