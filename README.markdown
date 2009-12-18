AEoid - An easy OpenID library for App Engine
=

What's this?
-

AEoid is a library for App Engine that makes it quick and easy to handle user
authentication with OpenID. It follows the mantra of "convention over configuration",
allowing you to get started as quickly as possible, and its interface is as close
to the App Engine [Users API](http://code.google.com/appengine/docs/python/users/)
as possible, allowing you to leverage your existing knowledge.

No knowledge of OpenID workings are expected. To see how easy it is, read on...


Status
-

AEoid is currently in an alpha 'first look' phase. Its features are fairly limited,
and the interface is subject to change. Your feedback is appreciated, so please
file [bug reports and feature requests](http://github.com/arachnid/aeoid/issues).


Installation
-

The first thing you need to do is download AEoid. After downloading, unpack it
and copy the 'aeoid' subdirectory into your App Engine app's root directory.

AEoid does its magic by using a piece of WSGI middleware. In order to use it in
your app, you need to include the middleware in your app. If you're using App
Engine's built in webapp framework, or any other framework that calls the
[run_wsgi_app](http://code.google.com/appengine/docs/python/tools/webapp/utilmodule.html)
function, you can use App Engine's configuration framework to install AEoid.
Create a file called "appengine_config.py" in your app's root directory, and put
the following in it:

    from aeoid import middleware

    def webapp_add_wsgi_middleware(app):
      app = middleware.AeoidMiddleware(app)
      return app

If your framework doesn't use run_wsgi_app, you need to insert the middleware
into your processing chain. For example, here's how it's done in the webapp
framework without run_wsgi_app:

    application = webapp.WSGIApplication([
        # ...
    ], debug=True)
    application = middleware.AeoidMiddleware(application)


Using AEoid
-

Now that you've installed AEoid, you can start using it in almost the same manner
as the App Engine Users API. For example:

    from aeoid import users

    class SomeData(db.Model):
      user = users.UserProperty() # Note, _not_ db.UserProperty
      # ...

    user = users.get_current_user()
    if user:
      logging.debug("Nickname is %s, email is %s, ID is %s", 
                    user.nickname(), user.email(), user.user_id())
      data = SomeData(user=user)
      data.put()

A few differences between AEoid's interface and that of the Users API warrant
mention:

 *  You can't construct a User object without supplying an OpenID URL.
 *  Nicknames are user-supplied, and not guaranteed to be unique.
 *  Email addresses are likewise user-supplied, and not guaranteed to be unique,
    or even owned by the user claiming them. If unsure, validate!
 *  is_current_user_admin() is not currently implemented.
 *  login: required and login: admin clauses in app.yaml are not affected by 
    AEoid, and still use the regular Users API. Don't use them unless you want
    to authenticate using the regular API.

That's it! Go wild!


Components
-

AEoid uses the [python-openid](http://openidenabled.com/python-openid/) library
for the grunt work of authenticating with OpenID, and the [beaker](http://beaker.groovie.org/)
sessions library for tracking user sessions.

The current beaker session can be accessed via the 'beaker.session' variable of
the WSGI environment, though this keyword may change in future. Beaker can be
configured by passing a dictionary of arguments to the AeoidMiddleware function
as a second argument.

Currently, it's not possible to configure the OpenID library, though this will
likely change in the near future.


Compatibility
-

AEoid should be compatible with most frameworks, though so far it has only been
tested with the webapp framework. It may have problems integrating with frameworks
that include their own copy of beaker or python-openid.

If you are using AEoid with a framework other than webapp, please let us know so
we can add it to the list. If it's not working, please [file a bug](http://github.com/arachnid/aeoid/issues)!
