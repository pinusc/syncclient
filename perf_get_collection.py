#!/usr/bin/env python3

import argparse
import json
import time
import requests
from syncclient import client


def main():
    parser = argparse.ArgumentParser(
        description="""Evaluate performance of collection page requests""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # input / output flags...
    parser.add_argument('-n', '--non-interactive', dest='no_ask',
                        action='store_true', help='Disable asking anything'
                        ' (assumes a valid session)')

    # API interaction options...
    parser.add_argument('-c', '--client-id', dest='client_id', required=True,
                        help='The client_id to use for OAuth (mandatory).')
    parser.add_argument('-u', '--user', dest='login',
                        help='Firefox Accounts login (email address).')

    parser.add_argument('--times', dest='times', type=int, default=1000,
                        help='The number of times to repeat the request')

    parser.add_argument('--token-ttl', dest='token_ttl', type=int, default=300,
                        help='The validity of the OAuth token in seconds')

    # data retrieval options...
    parser.add_argument('--full', dest='full', action='store_true',
                        help='fetch full BSO records instead of only ID')
    parser.add_argument('--limit', dest='limit', type=int, default=50,
                        help='the maximum number of records to return')
    parser.add_argument('--offset', dest='offset', type=int, default=None,
                        help='the number of records to skip over')
    parser.add_argument('--sort', dest='sort', default=None,
                        choices=['newest', 'oldest', 'index'],
                        help='get_records: the sort order of the records')
    parser.add_argument('--decrypt', dest='decrypt', action='store_true',
                        help='Whether to decrypt encrypted BSO records'
                        ' (implies --full).')

    parser.add_argument(dest='collection', help='The collection to fetch')

    args, extra = parser.parse_known_args()

    # handle dependencies...
    if args.decrypt:
        args.full = True

    # add action-dependent extra-arguments...
    params = {
        'full': args.full,
        'offset': args.offset,
        'limit': args.limit,
        'decrypt': args.decrypt,
        'sort': args.sort,
        'ignore_response': True
    }

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

    time_sum = 0
    time_max = 0
    count = 0

    # execute the desired action...
    try:
        while count < args.times:
            start = time.monotonic()
            try:
                sync_client.get_records(args.collection, **params)

                # avoids counter increment
                count += 1
                duration = time.monotonic() - start
                if time_max < duration:
                    time_max = duration
                time_sum += duration
                result = {
                    'count': args.times,
                    'index': (count - 1),
                    'time': round(duration, 6),
                    'time_sum': round(time_sum, 6),
                    'time_max': round(time_max, 6),
                    'time_avg': round((time_sum / count), 6)
                }
                print(json.dumps(result))
            except requests.exceptions.HTTPError as e:
                # OAuth token expired - get a new one...
                if count < 0 or e.response.status_code != 401:
                    raise e

                (access_token, _) = client.create_oauth_token(
                    fxa_session, args.client_id, token_ttl=args.token_ttl,
                    with_refresh=False)

                sync_client = client.get_sync_client(
                    fxa_session, args.client_id, access_token,
                    token_ttl=args.token_ttl, auto_renew=True)
    finally:
        client.destroy_oauth_token(fxa_session, args.client_id, access_token)


if __name__ == '__main__':
    main()
