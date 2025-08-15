import argparse
import dataclasses
import logging
import re
import subprocess
import sys
from pathlib import Path

import packaging.version
import rich.logging
import versioningit

__self__ = Path(__file__)

log = logging.getLogger(__self__.stem)

dirty_re = re.compile(r"\+d\d{8}")


@dataclasses.dataclass()
class Opts:
    index: str


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--index",
        "--repo",
        "-r",
        help="Destination PyPi Index",
        choices=["main", "test"],
        required=True,
    )
    argv = parser.parse_args()
    return Opts(**vars(argv))


def find_git_toplevel() -> Path:
    try:
        git_toplevel = subprocess.check_output(
            "git rev-parse --show-toplevel", shell=True, text=True, stderr=sys.stderr
        )
    except subprocess.CalledProcessError:
        log.exception("Unable to determine project root directory")
        return sys.exit(11)
    filepath = Path(git_toplevel.strip()).absolute()
    if not filepath.exists():
        raise FileNotFoundError(filepath)
    return filepath


def main():
    opts = parse_args()

    git_toplevel = find_git_toplevel()
    log.debug(f"project_dir={git_toplevel}")

    current_version = versioningit.get_version(git_toplevel)
    log.debug(f"git_verison={current_version}")

    v = packaging.version.parse(current_version)
    log.debug(f"parsed_version={v!s}")

    errors = 0

    if v.local:
        if dirty_re.search(v.local):
            log.error(f"Cannot Publish Dirty Package (uncommited changes): {v!s}")
            errors += 1
        else:
            log.error(f"Cannot Publish package with local part: {v!s}")
            errors += 1
    if opts.index == "main" and v.is_devrelease:
        log.error(f"Cannot Publish Dev Release {v!s} to pypi.org (main)")
        errors += 1
    return sys.exit(errors)


if __name__ == "__main__":
    logging.basicConfig(format="%(message)s", handlers=[rich.logging.RichHandler()])
    main()
