from reconpilot.cli import parse_args
from reconpilot.session import run_session


def main():
    args = parse_args()
    run_session(args)


if __name__ == "__main__":
    main()
