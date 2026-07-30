from codeforesight.data.git_metrics import (
    parse_git_log,
)


def test_parse_git_log():
    text = (
        "__CF_COMMIT__\x1fabc"
        "\x1fdev@example.com"
        "\x1f2026-01-02T03:04:05+00:00"
        "\x1fp1\n"
        "10\t2\tsrc/a.py\n"
        "3\t1\tsrc/b.py\n"
        "__CF_COMMIT__\x1fdef"
        "\x1fdev2@example.com"
        "\x1f2026-01-03T03:04:05+00:00"
        "\x1fp1 p2\n"
        "-\t-\tbinary.bin\n"
    )

    records = parse_git_log(text)

    assert len(records) == 2
    assert records[0].additions == 13
    assert records[0].deletions == 3
    assert len(records[0].files) == 2
    assert records[1].is_merge == 1
