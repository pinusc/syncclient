import argparse
import os
from client import SyncClient, get_browserid_assertion


def main():
    parser = argparse.ArgumentParser(
        description="""CLI to interact with Firefox Sync""",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-t', '--trace', dest='trace', action='store_true',
                        help='Enable tracing of requests')
    parser.add_argument('-q', '--quiet', dest='quiet', action='store_true',
                        help='Disable printing out anything except errors (does not affect trace output)')
    parser.add_argument(dest='login',
                        help='Firefox Accounts login.')
    parser.add_argument(dest='password',
                        help='Firefox Accounts password.')
    parser.add_argument(dest='action', help='The action to be executed',
                        default='info_collections', nargs='?',
                        choices=[m for m in dir(SyncClient)
                                 if not m.startswith('_')])

    args, extra = parser.parse_known_args()

    if args.trace:
        os.environ["HTTP_TRACE"] = "1"

    bid_assertion_args = get_browserid_assertion(args.login, args.password)
    client = SyncClient(*bid_assertion_args)
    resp = getattr(client, args.action)(*extra)
    if not args.quiet:
        print(resp)


if __name__ == '__main__':
    main()
