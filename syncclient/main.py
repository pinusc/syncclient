import argparse
import os
import client


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

    # data retrieval options...
    parser.add_argument('--full', dest='decrypt', action='store_true',
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
                                 if not m.startswith('_')])

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

    # create an authorized sync client...
    sync_client, oauth_client, access_token = client.get_sync_client(
        fxa_session, args.client_id)

    # execute the desired action...
    try:
        data = getattr(sync_client, args.action)(*extra, **params)
        if not args.quiet:
            print(data)
    finally:
        if oauth_client is not None:
            oauth_client.destroy_token(access_token)

if __name__ == '__main__':
    main()
