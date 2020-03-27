import argparse
import os
import requests
import time
import sys
from client import SyncClient, get_fxa_session, get_browserid_assertion
from datetime import datetime

def log(level, message=None, error=None, response=None):
    current_timestamp = datetime.utcnow().isoformat(timespec='milliseconds')
    print('{}Z [{}] {}'.format(current_timestamp, level,
                               message if error is None else error),
          file=sys.stderr)

    if response is not None:
        print(response.text, file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description="""CLI to interact with Firefox Sync""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-t', '--trace', dest='trace', action='store_true',
                        help='Enable tracing of requests')
    parser.add_argument('-T', '--timing', dest='timing', action='store_true',
                        help='Enable printing elapsed time of API requests to stderr')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='Disable printing out anything except errors (does not affect trace output)')
    parser.add_argument('-n', '--non-interactive', dest='no_ask', action='store_true',
                        help='Disable asking anything (assumes a valid session)')
    parser.add_argument('-u', '--user', dest='login',
                        help='Firefox Accounts login (email address).')
    parser.add_argument('-c', '--count', dest='count', type=int, default=10,
                        help='Number of calls to make')
    parser.add_argument('-d', '--delay', dest='delay', type=float, default=0.0,
                        help='Delay in seconds (can be fractional) between calls')
    parser.add_argument('-p', '--param', dest='params', action='append',
                        type=lambda kv: kv.split("=", 1),
                        help='Additional function-specific key-value parameters')
    parser.add_argument(dest='action', help='The action to be executed',
                        default='info_collections', nargs='?',
                        choices=[m for m in dir(SyncClient)
                                 if not m.startswith('_')])

    args, extra = parser.parse_known_args()
    kwargs = dict(args.params) if args.params else {}

    if args.trace:
        os.environ["HTTP_TRACE"] = "1"

    if args.timing:
        os.environ["HTTP_TIMING"] = "True"

    fxa_session = get_fxa_session(args.login)
    bid_assertion_args = get_browserid_assertion(fxa_session)
    client = SyncClient(*bid_assertion_args)
    bso_id_prefix = extra[1] if args.action in ["put_file", "put_record"] else None

    # retry configuration...
    sleep_factor = 1.25
    sleep_start = float(1.0)
    max_retries = 10
    abort = False

    for i in range(args.count):
        if i > 0 and args.delay > 0.0:
            time.sleep(args.delay)

        if bso_id_prefix:
            extra[1] = '{}_{:06d}'.format(bso_id_prefix, i)
        resp = None

        # retry with back-off...
        sleep_value = sleep_start
        num = 0
        while resp is None and num < max_retries:
            try:
                resp = getattr(client, args.action)(*extra, **kwargs)
                break
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 401:
                    # get a new assertion...
                    log('warning', error=e, response=e.response)
                    pass

                log('error', error=e, response=e.response)
                abort = True
                break
            except requests.exceptions.ConnectionError as e:
                # retry with new browserid but back-off...
                log('error', error=e)
                time.sleep(sleep_value)
                sleep_value = sleep_value * sleep_factor
                pass

            # only executed in an error case...
            bid_assertion_args = get_browserid_assertion(fxa_session)
            client = SyncClient(*bid_assertion_args)
            num += 1

        if abort:
            sys.exit(1)

        if not args.quiet:
            print(resp)


if __name__ == '__main__':
    main()
