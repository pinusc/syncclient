from hashlib import sha256
from binascii import hexlify, unhexlify
import json
import six
import sys
import os

import requests
import logging
from requests_hawk import HawkAuth
from fxa.core import Client as FxAClient
from fxa.core import Session as FxASession
from fxa.errors import ClientError as FxAClientError
from getpass import getpass

# This is a proof of concept, in python, to get some data of some collections.
# The data stays encrypted and because we don't have the keys to decrypt it
# it just stays like that for now. The goal is simply to prove that it's
# possible to get the data out of the API"""

TOKENSERVER_URL = os.getenv("TOKENSERVER_URL", "https://token.services.mozilla.com/")
FXA_SERVER_URL = os.getenv("FXA_SERVER_URL", "https://api.accounts.firefox.com")

FXA_CLIENT_NAME = 'Firefox Sync client'
FXA_CLIENT_VERSION = '0.9.0.dev0'
FXA_USER_AGENT_DEFAULT = 'Mozilla/5.0 (Mobile; Firefox Accounts; rv:1.0) {}/{}'.format(
    FXA_CLIENT_NAME, FXA_CLIENT_VERSION)

FXA_USER_AGENT = os.getenv("FXA_USER_AGENT", FXA_USER_AGENT_DEFAULT)
FXA_SESSION_FILE = os.getenv("FXA_SESSION_FILE", os.path.expanduser("~") + "/.pyfxa_session.json")


try:
    import http.client as http_client
except ImportError:
    # Python 2
    import httplib as http_client

def timing():
    return bool(os.getenv("HTTP_TIMING", "False"))

def ensure_trace():
    http_client.HTTPConnection.debuglevel = int(os.getenv("HTTP_TRACE", "0"))

def encode_header(value):
    if isinstance(value, str):
        return value
    # Python3, it must be bytes
    if sys.version_info[0] > 2:  # pragma: no cover
        return value.decode('utf-8')
    # Python2, it must be unicode
    else:  # pragma: no cover
        return value.encode('utf-8')

def get_input(message):
    if sys.version_info[0] > 2:
        return input(message)
    return raw_input(message)

def get_fxa_session(email, fxa_server_url=FXA_SERVER_URL):
    ensure_trace()
    client = FxAClient(server_url=fxa_server_url)
    session_data = {}
    update_session = False
    if os.path.exists(FXA_SESSION_FILE):
        try:
            with open(FXA_SESSION_FILE, 'r') as fp:
                session_data = json.load(fp)
        except ValueError:
            update_session = True
            pass

    s_uid = session_data.get("uid")
    s_token = session_data.get("token")
    s_keys = session_data.get("keys")

    keyA, keyB = (None, None)

    if s_uid and s_token and s_keys:
        fxa_session = FxASession(client, email, None, s_uid, s_token)
        fxa_session.keys = (bytes.fromhex(s_keys[0]), bytes.fromhex(s_keys[1]))
        keyA, keyB = fxa_session.keys

        try:
            fxa_session.check_session_status()
        except FxAClientError:
            # ask for the password - never stored...
            password = getpass("Authorization expired - please enter your password ({}): ".format(email))
            fxa_session = client.login(email, password)
            fxa_session.keys = (bytes.fromhex(s_keys[0]), bytes.fromhex(s_keys[1]))
            session_data["uid"] = fxa_session.uid
            session_data["token"] = fxa_session.token
            update_session = True

        fxa_session.get_email_status()
    else:
        # ask for the password - never stored...
        password = getpass("Please enter your password ({}): ".format(email))
        fxa_session = client.login(email, password, keys=True)
        session_data["uid"] = fxa_session.uid
        session_data["token"] = fxa_session.token
        update_session = True

    if not fxa_session.verified:
        if fxa_session.verificationMethod == 'totp-2fa':
            # ask for the verification code
            v_code = get_input("Please enter the TOTP code: ")
            if not fxa_session.totp_verify(v_code):
                raise SyncClientError("Wrong TOTP token")
        else:
            raise SyncClientError("Login verification method not supported: %s"
                                  % (fxa_session.verificationMethod))

    if keyA is None or keyB is None:
        keyA, keyB = fxa_session.fetch_keys()
        if isinstance(keyA, six.text_type):  # pragma: no cover
            keyA = keyA.encode('utf-8')
        if isinstance(keyB, six.text_type):  # pragma: no cover
            keyB = keyB.encode('utf-8')
        session_data["keys"] = (keyA.hex(), keyB.hex())
        update_session = True

    if update_session:
        # don't directly serialize to file - might break JSON syntax
        session_json = json.dumps(session_data)
        with open(FXA_SESSION_FILE, 'w') as fp:
            fp.write(session_json)

    fxa_ensure_devicename(fxa_session, '{} {} (Python {}.{})'.format(
        FXA_CLIENT_NAME, FXA_CLIENT_VERSION, sys.version_info.major,
        sys.version_info.minor))

    return fxa_session

def fxa_ensure_devicename(fxa_session, name):
    devices = fxa_session.apiclient.get("/account/devices", auth=fxa_session._auth)
    my_device = None

    for fxa_device in devices:
        if fxa_device['isCurrentDevice']:
            my_device = fxa_device

    if my_device is None:
        device_data = {
            'name': name
        }
        fxa_session.apiclient.post("/account/device", device_data, auth=fxa_session._auth)
    elif my_device['name'] != name:
        device_data = {
            'id': my_device['id'],
            'name': name
        }
        fxa_session.apiclient.post("/account/device", device_data, auth=fxa_session._auth)

def get_browserid_assertion(fxa_session, tokenserver_url=TOKENSERVER_URL):
    """Trade a user and password for a BrowserID assertion and the client
    state.
    """
    bid_assertion = fxa_session.get_identity_assertion(tokenserver_url)

    return bid_assertion, hexlify(sha256(fxa_session.keys[1]).digest()[0:16])

def ensure_session(session=None):
    if session is None:
        session = requests.Session()
        session.headers['User-Agent'] = FXA_USER_AGENT
    return session

def log_req_timing(resp, method, url):
    if timing():
        perf = resp.elapsed.total_seconds()
        print('[request-time] {:10.6f} {} {}'.format(perf, method.upper(), url), file=sys.stderr)


class SyncClientError(Exception):
    """An error occured in SyncClient."""


class TokenserverClient(object):
    """Client for the Firefox Sync Token Server.
    """
    def __init__(self, bid_assertion, client_state,
                 server_url=TOKENSERVER_URL, verify=None, session=None):
        ensure_trace()
        self.bid_assertion = bid_assertion
        self.client_state = client_state
        self.server_url = server_url
        self.verify = verify
        self._session = ensure_session(session)

    def get_hawk_credentials(self, duration=None):
        """Asks for new temporary token given a BrowserID assertion"""
        authorization = 'BrowserID %s' % encode_header(self.bid_assertion)
        headers = {
            'Authorization': authorization,
            'X-Client-State': self.client_state
        }
        params = {}

        if duration is not None:
            params['duration'] = int(duration)

        url = self.server_url.rstrip('/') + '/1.0/sync/1.5'
        raw_resp = self._session.get(url, headers=headers, params=params,
                                     verify=self.verify)

        log_req_timing(raw_resp, 'get', url)

        raw_resp.raise_for_status()
        return raw_resp.json()


class SyncClient(object):
    """Client for the Firefox Sync server.
    """

    def __init__(self, bid_assertion=None, client_state=None,
                 tokenserver_url=TOKENSERVER_URL, verify=None, session=None,
                 **credentials):

        ensure_trace()

        if bid_assertion is not None and client_state is not None:
            ts_client = TokenserverClient(bid_assertion, client_state,
                                          tokenserver_url)
            credentials = ts_client.get_hawk_credentials()

        else:
            # Make sure if the user wants to use credentials that they
            # give all the needed information.
            credentials_complete = set(credentials.keys()).issuperset({
                'uid', 'api_endpoint', 'hashalg', 'id', 'key'})

            if not credentials_complete:
                raise SyncClientError(
                    "You should either provide a BID assertion and a client "
                    "state or complete Sync credentials (uid, api_endpoint, "
                    "hashalg, id, key)")

        self.user_id = credentials['uid']
        self.api_endpoint = credentials['api_endpoint']
        self.auth = HawkAuth(algorithm=credentials['hashalg'],
                             id=credentials['id'],
                             key=credentials['key'])
        self.verify = verify
        self._session = ensure_session(session)

    def _request(self, method, url, **kwargs):
        """Utility to request an endpoint with the correct authentication
        setup, raises on errors and returns the JSON.

        """
        url = self.api_endpoint.rstrip('/') + '/' + url.lstrip('/')
        kwargs.setdefault('verify', self.verify)
        self.raw_resp = self._session.request(method, url, auth=self.auth, **kwargs)

        log_req_timing(self.raw_resp, method, url)

        self.raw_resp.raise_for_status()

        if self.raw_resp.status_code == 304:
            http_error_msg = '%s Client Error: %s for url: %s' % (
                self.raw_resp.status_code,
                self.raw_resp.reason,
                self.raw_resp.url)
            raise requests.exceptions.HTTPError(http_error_msg,
                                                response=self.raw_resp)
        return self.raw_resp.text

    def info_collections(self, **kwargs):
        """
        Returns an object mapping collection names associated with the account
        to the last-modified time for each collection.

        The server may allow requests to this endpoint to be authenticated
        with an expired token, so that clients can check for server-side
        changes before fetching an updated token from the Token Server.
        """
        return self._request('get', '/info/collections', **kwargs)

    def info_quota(self, **kwargs):
        """
        Returns a two-item list giving the user's current usage and quota
        (in KB). The second item will be null if the server does not enforce
        quotas.

        Note that usage numbers may be approximate.
        """
        return self._request('get', '/info/quota', **kwargs)

    def get_collection_usage(self, **kwargs):
        """
        Returns an object mapping collection names associated with the account
        to the data volume used for each collection (in KB).

        Note that these results may be very expensive as it calculates more
        detailed and accurate usage information than the info_quota method.
        """
        return self._request('get', '/info/collection_usage', **kwargs)

    def get_collection_counts(self, **kwargs):
        """
        Returns an object mapping collection names associated with the
        account to the total number of items in each collection.
        """
        return self._request('get', '/info/collection_counts', **kwargs)

    def delete_all_records(self, **kwargs):
        """Deletes all records for the user."""
        return self._request('delete', '/', **kwargs)

    def get_records(self, collection, full=True, ids=None, newer=None,
                    limit=None, offset=None, sort=None, **kwargs):
        """
        Returns a list of the BSOs contained in a collection. For example:

        >>> ["GXS58IDC_12", "GXS58IDC_13", "GXS58IDC_15"]

        By default only the BSO ids are returned, but full objects can be
        requested using the full parameter. If the collection does not exist,
        an empty list is returned.

        :param ids:
            a comma-separated list of ids. Only objects whose id is in
            this list will be returned. A maximum of 100 ids may be provided.

        :param newer:
            a timestamp. Only objects whose last-modified time is strictly
            greater than this value will be returned.

        :param full:
            any value. If provided then the response will be a list of full
            BSO objects rather than a list of ids.

        :param limit:
            a positive integer. At most that many objects will be returned.
            If more than that many objects matched the query,
            an X-Weave-Next-Offset header will be returned.

        :param offset:
            a string, as returned in the X-Weave-Next-Offset header of a
            previous request using the limit parameter.

        :param sort:
            sorts the output:
            "newest" - orders by last-modified time, largest first
            "index" - orders by the sortindex, highest weight first
            "oldest" - orders by last-modified time, oldest first
        """
        params = kwargs.pop('params', {})
        if full:
            params['full'] = True
        if ids is not None:
            params['ids'] = ','.join(map(str, ids))
        if newer is not None:
            params['newer'] = newer
        if limit is not None:
            params['limit'] = limit
        if offset is not None:
            params['offset'] = offset
        if sort is not None and sort in ('newest', 'index', 'oldest'):
            params['sort'] = sort

        return self._request('get', '/storage/%s' % collection.lower(),
                             params=params, **kwargs)

    def get_record(self, collection, record_id, **kwargs):
        """Returns the BSO in the collection corresponding to the requested id.
        """
        return self._request('get', '/storage/%s/%s' % (collection.lower(),
                                                        record_id), **kwargs)

    def delete_record(self, collection, record_id, **kwargs):
        """Deletes the BSO at the given location.
        """
        return self._request('delete', '/storage/%s/%s' % (
            collection.lower(), record_id), **kwargs)

    def put_record(self, collection, record, **kwargs):
        """
        Creates or updates a specific BSO within a collection.
        The passed record must be a python object containing new data for the
        BSO.

        If the target BSO already exists then it will be updated with the
        data from the request body. Fields that are not provided will not be
        overwritten, so it is possible to e.g. update the ttl field of a
        BSO without re-submitting its payload. Fields that are explicitly set
        to null in the request body will be set to their default value by the
        server.

        If the target BSO does not exist, then fields that are not provided in
        the python object will be set to their default value by the server.

        Successful responses will return the new last-modified time for the
        collection.

        Note that the server may impose a limit on the amount of data
        submitted for storage in a single BSO.
        """
        # XXX: Workaround until request-hawk supports the json parameter. (#17)
        if isinstance(record, six.string_types):
            record = json.loads(record)
        record = record.copy()
        record_id = record.pop('id')
        headers = {}
        if 'headers' in kwargs:
            headers = kwargs.pop('headers')

        headers['Content-Type'] = 'application/json; charset=utf-8'

        return self._request('put', '/storage/%s/%s' % (
            collection.lower(), record_id), data=json.dumps(record),
            headers=headers, **kwargs)

    def post_records(self, collection, records, **kwargs):
        """
        Takes a list of BSOs in the request body and iterates over them,
        effectively doing a series of individual PUTs with the same timestamp.

        Each BSO record must include an "id" field, and the corresponding BSO
        will be created or updated according to the semantics of a PUT request
        targeting that specific record.

        In particular, this means that fields not provided will not be
        overwritten on BSOs that already exist.

        Successful responses will contain a JSON object with details of
        success or failure for each BSO. It will have the following keys:

            modified: the new last-modified time for the updated items.
            success: a (possibly empty) list of ids of BSOs that were
                     successfully stored.
            failed: a (possibly empty) object whose keys are the ids of BSOs
                    that were not stored successfully, and whose values are
                    lists of strings describing possible reasons for the
                    failure.

        For example:

        {
         "modified": 1233702554.25,
         "success": ["GXS58IDC_12", "GXS58IDC_13", "GXS58IDC_15",
                     "GXS58IDC_16", "GXS58IDC_18", "GXS58IDC_19"],
         "failed": {"GXS58IDC_11": ["invalid ttl"],
                    "GXS58IDC_14": ["invalid sortindex"]}
        }

        Posted BSOs whose ids do not appear in either "success" or "failed"
        should be treated as having failed for an unspecified reason.

        Note that the server may impose a limit on the total amount of data
        included in the request, and/or may decline to process more than a
        certain number of BSOs in a single request. The default limit on the
        number of BSOs per request is 100.
        """
        pass
