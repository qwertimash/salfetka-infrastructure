#!/usr/bin/env python3
"""Salfetka managed installer entry point; errors never include credentials."""
import sys
from installer.common import Failure
from installer.manager import main

if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print(str(error) if isinstance(error, Failure) else 'operation_failed_state_preserved; run salfetka status', file=sys.stderr)
        sys.exit(1)
