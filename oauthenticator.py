"""
Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import json
import os
import sys

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator, LocalAuthenticator
from jupyterhub.utils import url_path_join

from IPython.utils.traitlets import Unicode

class GitHubMixin(OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "http://9.26.148.84:4445/oauth/login"
    _OAUTH_ACCESS_TOKEN_URL = "http://9.26.148.84:4445/access_token"


class GitHubLoginHandler(BaseHandler, GitHubMixin):
    def get(self):
        guess_uri = '{proto}://{path}'.format(
            proto=self.request.protocol,
            path=url_path_join(
                self.hub.server.base_url,
                'oauth_callback'
            )
        )
        
        redirect_uri = self.authenticator.oauth_callback_url or guess_uri
        self.log.info('oauth redirect: %r', redirect_uri)
        
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.github_client_id,
            scope=[],
            response_type='code')


class GitHubOAuthHandler(BaseHandler):
    @gen.coroutine
    def get(self):
        # TODO: Check if state argument needs to be checked
        username = yield self.authenticator.authenticate(self)
        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error page?
            raise web.HTTPError(403)


class GitHubOAuthenticator(Authenticator):
    
    oauth_callback_url = 'http://9.26.148.84:8000/hub/oauth_callback'
    github_client_id = '994b212faf1d6ef8887cf7c2b6f96e8b'
    github_client_secret = '219d063a1fa1fd749185f5aa61e2ec40'
    
    def login_url(self, base_url):
        return url_path_join(base_url, 'oauth_login')
    
    def get_handlers(self, app):
        return [
            (r'/oauth_login', GitHubLoginHandler),
            (r'/oauth_callback', GitHubOAuthHandler),
        ]
    
    @gen.coroutine
    def authenticate(self, handler):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()
        
        # Exchange the OAuth code for a GitHub Access Token
        #
        # See: https://developer.github.com/v3/oauth/
        
        # GitHub specifies a POST request yet requires URL parameters
        params = dict(
                client_id=self.github_client_id,
                client_secret=self.github_client_secret,
                code=code
        )
        
        url = url_concat("http://9.26.148.84:4445/access_token",
                         params)
        
        req = HTTPRequest(url,
                          method="POST",
                          headers={"Accept": "application/json"},
                          body='' # Body is required for a POST...
                          )
        
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']

        # Determine who the logged in user is
        headers={"Accept": "application/json",
                 "User-Agent": "JupyterHub",
                 "Authorization": "token {}".format(access_token)
        }
        req = HTTPRequest("http://9.26.148.84:4445/api/get",
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        username = resp_json["login"]
        if self.whitelist and username not in self.whitelist:
            c = get_config()
            name_is_set = None
            for v in range (1010, 16777215)
                if v in c.SystemUserSpawner.user_ids.values() 
                    continue
                c.SystemUserSpawner.user_ids[username] = v
                self.whitelist.add(username)
                name_is_set = True
                break
            if(not name_is_set)
                username = None 
        raise gen.Return(username)


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):
    """A version that mixes in local system user creation"""
    pass
