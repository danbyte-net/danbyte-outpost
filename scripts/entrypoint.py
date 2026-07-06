"""PyInstaller entry point — a plain script so PyInstaller has a target to
freeze. Delegates to the package's real main()."""
from outpost.run import main

raise SystemExit(main())
