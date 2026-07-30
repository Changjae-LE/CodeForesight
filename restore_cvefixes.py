from pathlib import Path
import subprocess

SQLITE_EXE = Path("sqlite3.exe").resolve()
SQL_FILE = Path("CVEfixes_v1.0.8.sql").resolve()
DATABASE_FILE = Path("CVEfixes.db").resolve()
ERROR_LOG = Path("import_errors.log").resolve()

# SQLite가 오류를 보고한 실제 SQL 파일 줄 번호
BAD_LINES = {73829}


def validate_files() -> None:
    if not SQLITE_EXE.exists():
        raise FileNotFoundError(
            f"sqlite3.exe를 찾을 수 없습니다: {SQLITE_EXE}"
        )

    if not SQL_FILE.exists():
        raise FileNotFoundError(
            f"SQL 파일을 찾을 수 없습니다: {SQL_FILE}"
        )


def main() -> None:
    validate_files()

    if DATABASE_FILE.exists():
        DATABASE_FILE.unlink()

    print(f"입력 파일: {SQL_FILE}")
    print(f"출력 DB: {DATABASE_FILE}")
    print(f"제외할 SQL 줄: {sorted(BAD_LINES)}")
    print("Import를 시작합니다.")

    broken_pipe = False

    with ERROR_LOG.open("wb") as error_file:
        process = subprocess.Popen(
            [str(SQLITE_EXE), str(DATABASE_FILE)],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=error_file,
        )

        if process.stdin is None:
            raise RuntimeError("SQLite 입력 스트림을 만들 수 없습니다.")

        # 오류가 발생해도 가능한 한 다음 SQL을 계속 실행
        process.stdin.write(b".bail off\n")

        with SQL_FILE.open("rb") as sql_file:
            for line_number, line in enumerate(sql_file, start=1):
                if line_number in BAD_LINES:
                    print(f"[건너뜀] SQL line {line_number}")
                    continue

                # SQL dump 내부에서 .bail on을 다시 설정한다면 비활성화
                if line.lstrip().lower().startswith(b".bail on"):
                    line = b".bail off\n"

                try:
                    process.stdin.write(line)
                except BrokenPipeError:
                    broken_pipe = True
                    print(
                        "\nSQLite가 입력 도중 종료됐습니다. "
                        "import_errors.log를 확인하세요."
                    )
                    break

                if line_number % 10_000 == 0:
                    print(f"{line_number:,}줄 처리 완료")

        try:
            process.stdin.close()
        except BrokenPipeError:
            broken_pipe = True

        exit_code = process.wait()

    print(f"\nSQLite 종료 코드: {exit_code}")
    print(f"생성된 DB: {DATABASE_FILE}")
    print(f"오류 로그: {ERROR_LOG}")

    if broken_pipe or exit_code != 0:
        print("\nImport 중 추가 오류가 발생했습니다.")
        print("다음 명령으로 로그를 확인하세요:")
        print(r"Get-Content .\import_errors.log -TotalCount 30")
    else:
        print("\nImport가 완료됐습니다.")


if __name__ == "__main__":
    main()