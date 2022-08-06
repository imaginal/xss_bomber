#!/usr/bin/env python
import sys
import yaml
import pymysql
import pymysql.cursors
import pymysql.err
import random


class XSSBomber(object):
    def update_row(self, query, payload):
        if self.dry_run:
            payload = "'{}'".format(payload.replace("'", "\\'"))
            print("SQL>", query % payload)
            return
        try:
            affected_rows = self.cursor.execute(query, payload)
            if affected_rows:
                self.connection.commit()
                print('.', end='')
            else:
                self.update_errors += 1
                print('0', end='')
        except pymysql.err.MySQLError:
            self.update_errors += 1
            self.connection.rollback()
            print('E', end='')
        sys.stdout.flush()

    def update_json_column(self, table, column, count, max_errors, update):
        print("+ COLUMN", column, "IS JSON")
        if update['json_before']:
            self.update_errors = 0
            for n in range(count):
                query = ("UPDATE `{}` SET `{}`=REPLACE(`{}`, ':\"', %s) WHERE `{}` IS NOT NULL "
                         "ORDER BY RAND() LIMIT 1").format(table, column, column, column)
                payload = random.choice(self.xss_payloads)
                payload = ':\"{}'.format(payload.replace('"', '\\"'))
                self.update_row(query, payload)
                if self.update_errors > max_errors:
                    break
        if update['json_after']:
            for n in range(count):
                query = ("UPDATE `{}` SET `{}`=REPLACE(`{}`, '\",', %s) WHERE `{}` IS NOT NULL "
                         "ORDER BY RAND() LIMIT 1").format(table, column, column, column)
                payload = random.choice(self.xss_payloads)
                payload = '{}\",'.format(payload.replace('"', '\\"'))
                self.update_row(query, payload)
                if self.update_errors > max_errors:
                    break
        print("")

    def update_column(self, table, column, count):
        print("+ COLUMN", column[0], column[1])
        column = column[0]
        max_errors = self.config['limits'].get('errors', 100)
        max_update = self.config['limits'].get('update', 10000)
        update = {
            'update_factor': 1.0,
            'append_before': True,
            'append_after': True,
            'replace_space': True,
            'replace_tail': True,
            'replace_null': False,
            'replace_all': False,
            'json_before': True,
            'json_after': True,
        }
        update.update(self.config['update'])
        count = int(count * update['update_factor'])
        if count < 1:
            count = 1
        if count > max_update:
            count = max_update
        # CHECK FOR NULL
        if not update['replace_null']:
            query = ("SELECT `{}` FROM `{}` WHERE `{}` IS NOT NULL "
                     "LIMIT 1").format(column, table, column)
            self.cursor.execute(query)
            if not self.cursor.fetchone():
                print("- COLUMN", column, "IS NULL")
                return
        # BEGIN JSON
        json_cols = self.config['columns']['json']
        table_column = "{}.{}".format(table, column)
        for js in json_cols:
            if table_column.find(js) >= 0:
                self.update_json_column(table, column, count, max_errors, update)
                return
        # END JSON
        if update['append_before']:
            self.update_errors = 0
            for n in range(count):
                query = ("UPDATE `{}` SET `{}`=CONCAT(%s, `{}`) WHERE `{}` IS NOT NULL "
                         "ORDER BY RAND() LIMIT 1").format(table, column, column, column)
                payload = random.choice(self.xss_payloads)
                self.update_row(query, payload)
                if self.update_errors > max_errors:
                    break
        if update['append_after']:
            self.update_errors = 0
            for n in range(count):
                query = ("UPDATE `{}` SET `{}`=CONCAT(`{}`, %s) WHERE `{}` IS NOT NULL "
                         "ORDER BY RAND() LIMIT 1").format(table, column, column, column)
                payload = random.choice(self.xss_payloads)
                self.update_row(query, payload)
                if self.update_errors > max_errors:
                    break
        if update['replace_space']:
            self.update_errors = 0
            for n in range(count):
                query = ("UPDATE `{}` SET `{}`=REPLACE(`{}`, ' ', %s) WHERE `{}` IS NOT NULL "
                         "ORDER BY RAND() LIMIT 1").format(table, column, column, column)
                payload = random.choice(self.xss_payloads)
                payload = " {} ".format(payload)
                self.update_row(query, payload)
                if self.update_errors > max_errors:
                    break
        if update['replace_tail']:
            self.update_errors = 0
            for n in range(count):
                query = ("UPDATE `{}` SET `{}`=CONCAT(SUBSTRING(`{}`, 1, 5), %s) WHERE `{}` IS NOT NULL "
                         "ORDER BY RAND() LIMIT 1").format(table, column, column, column)
                for n in range(100):
                    payload = random.choice(self.xss_payloads)
                    if len(payload) < 25:
                        break
                self.update_row(query, payload)
                if self.update_errors > max_errors:
                    break
        if update['replace_null']:
            self.update_errors = 0
            for n in range(count):
                query = ("UPDATE `{}` SET `{}`=%s WHERE `{}` IS NULL "
                         "ORDER BY RAND() LIMIT 1").format(table, column, column)
                payload = random.choice(self.xss_payloads)
                self.update_row(query, payload)
                if self.update_errors > max_errors:
                    break
        if update['replace_all']:
            self.update_errors = 0
            for n in range(count):
                query = ("UPDATE `{}` SET `{}`=%s WHERE `{}` IS NOT NULL "
                         "ORDER BY RAND() LIMIT 1").format(table, column, column)
                payload = random.choice(self.xss_payloads)
                self.update_row(query, payload)
                if self.update_errors > max_errors:
                    break
        print("")

    def process_table(self, table):
        cursor = self.cursor
        cursor.execute("SELECT COUNT(1) FROM " + table)
        count, = cursor.fetchone()
        if count == 0:
            print("TABLE", table, "IS EMPTY")
            return
        print("TABLE {} ({} rows)".format(table, count))
        cursor.execute("DESCRIBE " + table)
        columns = []
        colconf = {
            'types': ['varchar'],
            'allow': [],
            'deny': [],
            'json': []
        }
        colconf.update(self.config['columns'])
        all_columns = list(cursor.fetchall())
        for col in all_columns:
            coltype = col[1]
            if '(' in coltype:
                coltype, _ = coltype.split('(', 1)
            if coltype not in colconf['types']:
                continue
            table_column = "{}.{}".format(table, col[0])
            if colconf['allow']:
                found = False
                for allow in colconf['allow']:
                    if table_column.find(allow) >= 0:
                        found = True
                        break
                if not found:
                    continue
            if colconf['deny']:
                found = False
                for deny in colconf['deny']:
                    if table_column.find(deny) >= 0:
                        found = True
                        break
                if found:
                    continue
            columns.append(col)
        if not columns:
            print("- NO TEXT COLUMNS")
            return
        for col in columns:
            self.update_column(table, col, count)

    def process_tables(self):
        cursor = self.cursor
        cursor.execute("SHOW TABLES")
        tables = [t for t, in cursor.fetchall()]
        for table in tables:
            self.process_table(table)

    def run(self, config, dry_run):
        with open(config) as fp:
            self.config = yaml.safe_load(fp)

        self.dry_run = self.config.get('dry_run', False)
        if dry_run:
            self.dry_run = True

        self.xss_payloads = []
        for filename in self.config['payloads']:
            with open(filename) as fp:
                for s in fp:
                    s = s.strip()
                    if s and s[0] != '#':
                        self.xss_payloads.append(s)

        try:
            self.connection = pymysql.connect(**self.config['database'])
        except pymysql.err.OperationalError as exc:
            print("ERROR", exc)
            return

        with self.connection:
            with self.connection.cursor() as cursor:
                self.cursor = cursor
                self.process_tables()


def main():
    if len(sys.argv) < 2:
        print("usage: xss_bomber.py config.yml [--dry-run]")
        return
    config = sys.argv[1]
    dry_run = '--dry-run' in sys.argv
    XSSBomber().run(config, dry_run)


if __name__ == '__main__':
    main()
