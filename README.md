# XSS Bomber

Script to infect any MySQL database with XSS payloads.

For testing purposes only.

## Installation

Use the `pip` and `venv` to install the script.

```bash
$ python3 -m venv venv
$ . venv/bin/activate
$ pip install -r requirements.txt
```

## Usage

Backup your database!!!

Before start edit `config.yml` and update database settings.

Try it withought making any real changes in database (dry run)

```bash
(venv) $ python xss_bomber.py config.yml --dry-run
```

Then run when ready

```bash
(venv) $ python xss_bomber.py config.yml
```

Enjoy.

## Thanks

@payloadbox for [xss-payload-list](https://github.com/payloadbox/xss-payload-list)

Don't forget to update xss-payload-list.txt before using.

## License

[MIT](https://choosealicense.com/licenses/mit/)

