import sqlite3

from codeforesight.data.cvefixes import (
    build_stage1_samples,
    extract_vulnerability_events,
)


def make_db(path):
    connection = sqlite3.connect(path)
    connection.executescript(
        '''
        CREATE TABLE cve (
            cve_id TEXT PRIMARY KEY,
            published_date TEXT,
            last_modified_date TEXT,
            cvss3_base_score REAL,
            cvss2_base_score REAL,
            severity REAL,
            cvss3_base_severity TEXT
        );
        CREATE TABLE fixes (
            cve_id TEXT,
            hash TEXT,
            repo_url TEXT
        );
        CREATE TABLE repository (
            repo_url TEXT PRIMARY KEY,
            repo_name TEXT,
            repo_language TEXT,
            date_created TEXT
        );
        CREATE TABLE commits (
            hash TEXT,
            repo_url TEXT,
            committer_date TEXT,
            author_date TEXT,
            num_lines_added INTEGER,
            num_lines_deleted INTEGER
        );
        CREATE TABLE file_change (
            file_change_id INTEGER PRIMARY KEY,
            hash TEXT,
            filename TEXT,
            programming_language TEXT
        );
        CREATE TABLE method_change (
            method_change_id INTEGER PRIMARY KEY,
            file_change_id INTEGER,
            name TEXT,
            signature TEXT,
            code TEXT,
            before_change INTEGER,
            nloc INTEGER,
            complexity INTEGER
        );
        '''
    )
    connection.execute(
        'INSERT INTO cve VALUES (?, ?, ?, ?, ?, ?, ?)',
        ('CVE-2026-0001', '2026-01-02', '2026-01-03', 8.8, None, None, 'HIGH'),
    )
    connection.execute(
        'INSERT INTO fixes VALUES (?, ?, ?)',
        ('CVE-2026-0001', 'abc', 'https://github.com/acme/demo.git'),
    )
    connection.execute(
        'INSERT INTO repository VALUES (?, ?, ?, ?)',
        ('https://github.com/acme/demo.git', 'acme/demo', 'C', '2020-01-01'),
    )
    connection.execute(
        'INSERT INTO commits VALUES (?, ?, ?, ?, ?, ?)',
        ('abc', 'https://github.com/acme/demo.git', '2025-12-20', '2025-12-19', 10, 2),
    )
    connection.execute(
        'INSERT INTO file_change VALUES (?, ?, ?, ?)',
        (1, 'abc', 'demo.c', 'C'),
    )
    connection.executemany(
        'INSERT INTO method_change VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [
            (1, 1, 'copy', 'copy(char*)', 'void copy(char *x){strcpy(buf,x);}', 1, 1, 1),
            (2, 1, 'copy', 'copy(char*)', 'void copy(char *x){strncpy(buf,x,9);}', 0, 1, 1),
        ],
    )
    connection.commit()
    connection.close()


def test_cvefixes_event_and_stage1_extract(tmp_path):
    db = tmp_path / 'CVEfixes.db'
    make_db(db)

    events_path = tmp_path / 'events.csv'
    repos_path = tmp_path / 'repos.csv'
    events = extract_vulnerability_events(db, events_path, repos_path)
    assert len(events) == 1
    assert events.iloc[0]['cvss_score'] == 8.8
    assert events.iloc[0]['repository'] == 'acme/demo'

    samples_path = tmp_path / 'stage1.csv'
    samples = build_stage1_samples(db, samples_path, language='C', min_code_chars=10)
    assert len(samples) == 2
    assert set(samples['label']) == {0, 1}
    assert samples['group_id'].nunique() == 1
