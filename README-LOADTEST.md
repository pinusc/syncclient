* You'll need python 3 for testing. Probably, you will use `brew` to install python 3 if you don't have it.
  I suppose that python 3 is accessible by `python3`, if you use something else please change following instructions accordingly.

* cd to project folder

* install dependencies by running `pip3 install -r requirements.txt` or pip instead of pip3.

* set environmemt variables
  `export FXA_SERVER_URL=https://api.accounts.fxa.enote.net`
  `export TOKENSERVER_URL=https://sync.fxa.enote.net`

* run `python3 syncclient/main.py --user valeriy.van@enote.com get_collection_counts` to check if everything is ok. It should ask password.
  The password is `hujbuK-zocpo9-guqbov`.
  You may need to use something else instaed of `python3` depending on your install.

  If it's running normally (you will understand that by responce), please continue.

* open `loadtest.swift` and in line 65 in `let collection = "c-" + String(i)` change collection beginning to something unique like your name.
  You may need also change `python3` appropriately on line 36. Path to python interpreter also may need to be changed.. To determine path run `which python3`.

* run `swift loadtest.swift` and leave it running for a some time, e.g. for a night.

Unfortunately `Process().run()` doesn't close ports so script leaks memory while running. But it should survive overnight.

