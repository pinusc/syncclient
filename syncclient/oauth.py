import argparse
import client
import json
from fxa.errors import ClientError
from fxa.oauth import Client


class OAuthClient(object):

    def __init__(self, oauth_client, client_id, fxa_session):
        self._client = oauth_client
        self._client_id = client_id
        self._fxa_session = fxa_session

    def create(self, scopes=['profile']):
        if isinstance(scopes, str):
            scopes = scopes.split(',')

        token, _ = client.create_oauth_token(self._fxa_session,
                                             self._client_id,
                                             scopes=scopes,
                                             with_refresh=False)
        return {'token': token}

    def delete(self, token):
        self._client.destroy_token(token)

    def verify(self, token, scope=None):
        return self._client.verify_token(token, scope)

    def introspect(self, token, token_type='access_token'):
        url = '/introspect'
        body = {
            'token': token,
            'token_type_hint': token_type
        }
        return self._client.apiclient.post(url, body)


def main():
    parser = argparse.ArgumentParser(
        description="""CLI to manage OAuth tokens""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # debugging / tracing flags...
    parser.add_argument('-t', '--trace', dest='trace', action='store_true',
                        help='Enable tracing of requests')
    parser.add_argument('-T', '--timing', dest='timing', action='store_true',
                        help='Enable printing elapsed time of API requests'
                        ' to stderr')
    parser.add_argument('-d', '--dump', dest='dump_response',
                        action='store_true',
                        help='Enable dumping of response data'
                        ' (requires --timing or --trace)')

    # API interaction options...
    parser.add_argument('-c', '--client-id', dest='client_id', required=True,
                        help='The client_id to use for OAuth (mandatory).')
    parser.add_argument('-u', '--user', dest='login', required=True,
                        help='Firefox Accounts login (email address).')

    parser.add_argument(dest='action', help='The action to be executed',
                        nargs='?',
                        choices=[m for m in dir(OAuthClient)
                                 if not m.startswith('_')])

    args, extra = parser.parse_known_args()

    # activate tracing/printf-debugging options...
    if args.trace:
        client.enable_http_trace()

    if args.timing:
        client.enable_http_timing()

    if args.dump_response and (args.timing or args.trace):
        client.enable_http_dump_response()

    # create or verify a FxA session for this machine...
    fxa_session = client.get_fxa_session(args.login)

    # create an OAuth client...
    oauth_client = Client(args.client_id, None,
                          server_url=client.OAUTH_SERVER_URL)
    oauth_client.apiclient._session = fxa_session.apiclient._session

    wrapper = OAuthClient(oauth_client, args.client_id, fxa_session)

    # execute the desired action...
    try:
        data = getattr(wrapper, args.action)(*extra)

        if data is not None:
            if isinstance(data, dict) or isinstance(data, list):
                data = json.dumps(data)
            print(data)
    except ClientError as e:
        print(json.dumps(e.details))


if __name__ == '__main__':
    main()
