import argparse
import os
import client
import hashlib
import requests

def main():
    parser = argparse.ArgumentParser(
        description="""CLI to interact with Firefox Sync""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # debugging / tracing flags...
    parser.add_argument('-t', '--trace', dest='trace', action='store_true',
                        help='Enable tracing of requests')
    parser.add_argument('-T', '--timing', dest='timing', action='store_true',
                        help='Enable printing elapsed time of API requests to stderr')
    parser.add_argument('-d', '--dump', dest='dump_response', action='store_true',
                        help='Enable dumping of response data (requires --timing or --trace)')

    # input / output flags...
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='Disable printing out anything except errors (does not affect trace output)')
    parser.add_argument('-n', '--non-interactive', dest='no_ask', action='store_true',
                        help='Disable asking anything (assumes a valid session)')

    # API interaction options...
    parser.add_argument('-c', '--client-id', dest='client_id', required=True,
                        help='The client_id to use for OAuth (mandatory).')
    parser.add_argument('-u', '--user', dest='login',
                        help='Firefox Accounts login (email address).')

    parser.add_argument('--token-ttl', dest='token_ttl', type=int, default=300,
                        help='The validity of the OAuth token in seconds')

    # data retrieval options...
    parser.add_argument('--full', dest='full', action='store_true',
                        help='get_records: fetch full BSO records instead of only ID')
    parser.add_argument('--ids', dest='ids', nargs='+', default=None,
                        help='get_records: filter records by ID')
    parser.add_argument('--newer', dest='newer', type=int, default=None,
                        help='get_records: return only records modified after this value (unix epoch)')
    parser.add_argument('--limit', dest='limit', type=int, default=None,
                        help='get_records: the maximum number of records to return')
    parser.add_argument('--offset', dest='offset', type=int, default=None,
                        help='get_records: the number of records to skip over')
    parser.add_argument('--sort', dest='sort', default=None,
                        choices=['newest', 'oldest', 'index'],
                        help='get_records: the sort order of the records')
    parser.add_argument('--decrypt', dest='decrypt', action='store_true',
                        help='Whether to decrypt encrypted BSO records (implies --full).')

    parser.add_argument(dest='action', help='The action to be executed',
                        default='info_collections', nargs='?',
                        choices=[m for m in dir(client.SyncClient)
                                 if not m.startswith('_')] + ['put_files'])

    args, extra = parser.parse_known_args()

    # activate tracing/printf-debugging options...
    if args.trace:
        client.enable_http_trace()

    if args.timing:
        client.enable_http_timing()

    if args.dump_response and (args.timing or args.trace):
        client.enable_http_dump_response()

    # handle dependencies...
    if args.decrypt:
        args.full = True

    # add action-dependent extra-arguments...
    params = {}

    if args.action == 'get_records':
        params["full"] = args.full
        params["ids"] = args.ids
        params["newer"] = args.newer
        params["limit"] = args.limit
        params["offset"] = args.offset

    if args.action in ['get_record', 'get_records']:
        params["decrypt"] = args.decrypt

    # create or verify a FxA session for this machine...
    fxa_session = client.get_fxa_session(args.login)

    # get an OAuth access token...
    (access_token, _) = client.create_oauth_token(fxa_session, args.client_id,
                                                  token_ttl=args.token_ttl,
                                                  with_refresh=False)

    # create an authorized sync client...
    sync_client = client.get_sync_client(fxa_session, args.client_id,
                                         access_token,
                                         token_ttl=args.token_ttl,
                                         auto_renew=True)

    # execute the desired action...
    try:
        if args.action == 'put_files':
            for f in extra[1:]:
                rec_id = hashlib.sha1(bytes(f, 'utf-8')).hexdigest()
                try:
                    data = sync_client.put_file(extra[0], rec_id, f)
                    if not args.quiet:
                        print('Uploaded file "{}" => id "{}": {}'.format(f, rec_id, data))
                except requests.exceptions.HTTPError as e:
                    if e.response.status_code != 400:
                        raise e
                    print('File too large: {}'.format(f))
        else:
            data = getattr(sync_client, args.action)(*extra, **params)
            if not args.quiet:
                print(data)
    finally:
        client.destroy_oauth_token(fxa_session, args.client_id, access_token)

if __name__ == '__main__':
    main()
