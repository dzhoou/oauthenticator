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

from IPython.utils.traitlets import (
    Unicode,
    Dict
)

from textwrap import dedent

# Add Dockerspawner import because I included SystemUserSpawner class...
from dockerspawner import DockerSpawner


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
    user_ids = Dict(
        config=True,
        help=dedent(
            """
            If system users are being used, then we need to know their user id
            in order to mount the home directory. User ids should be specified
            in this dictionary.
            """
        )
    )
    
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
        # Add a new user based on the user on OAuth server! Also see modifications on jupyterhub_config.py
            for v in range (1010, sys.maxsize):
                if v in self.user_ids.values():
                    continue
                self.whitelist.add(username)
                self.user_ids[username] = v
                break

        raise gen.Return(username)


class LocalGitHubOAuthenticator(LocalAuthenticator, GitHubOAuthenticator):
    """A version that mixes in local system user creation"""
    pass


class SystemUserSpawner(DockerSpawner):
    container_image = Unicode("jupyter/systemuser", config=True)
    host_homedir_format_string = Unicode(
        "/home/{username}",
        config=True,
        help=dedent(
        """
        Format string for the path to the user's home directory on the host.
        The format string should include a `username` variable, which will
        be formatted with the user's username.
        """
        )
    )
    user_ids = Dict(
        config=True,
        help=dedent(
            """
            If system users are being used, then we need to know their user id
            in order to mount the home directory. User ids should be specified
            in this dictionary.
            """
        )
    )
    
    @property
    def host_homedir(self):
        """
        Path to the volume containing the user's home directory on the host.
        """
        return self.host_homedir_format_string.format(username=self.user.name)
        
    @property
    def homedir(self):
        """
        Path to the user's home directory in the docker image.
        """
        return "/home/{username}".format(username=self.user.name)
        
    @property
    def volume_mount_points(self):
        """
        Volumes are declared in docker-py in two stages. First, you declare
        all the locations where you're going to mount volumes when you call
        create_container.
        Returns a list of all the values in self.volumes or
        self.read_only_volumes.
        """
        mount_points = super(SystemUserSpawner, self).volume_mount_points
        mount_points.append(self.homedir)
        return mount_points
        
    @property
    def volume_binds(self):
        """
        The second half of declaring a volume with docker-py happens when you
        actually call start(). The required format is a dict of dicts that
        looks like:
        {
            host_location: {'bind': container_location, 'ro': True}
        }
        """
        volumes = super(SystemUserSpawner, self).volume_binds
        volumes[self.host_homedir] = {
        'bind': self.homedir,
        'ro': False
        }
        return volumes
        
    def _env_default(self):
        env = super(SystemUserSpawner, self)._env_default()
        env.update(dict(
            USER=self.user.name,
            USER_ID=self.user_ids[self.user.name],
            HOME=self.homedir
        ))
        return env
    @gen.coroutine
    def start(self, image=None):
        """start the single-user server in a docker container"""
        yield super(SystemUserSpawner, self).start(
            image=image,
            working_dir=self.homedir
        )
