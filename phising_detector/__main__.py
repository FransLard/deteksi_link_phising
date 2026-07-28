import sys

if len(sys.argv) > 1 and sys.argv[1] == "gui":
    from .gui import main as gui_main
    gui_main()
else:
    from .cli import main as cli_main
    cli_main()
