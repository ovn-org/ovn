#!/usr/bin/env python3

import atexit
import os
import signal
import sys
from pathlib import Path


from ovn_upgrade_utils import (
    log,
    chdir,
    run_command,
    run_shell_command,
    ovn_upgrade_save_current_binaries,
    ovn_upgrade_extract_info,
    run_upgrade_workflow,
    remove_upgrade_test_directory,
    UpgradeConfig
)

DEFAULT_BASE_BRANCH = 'branch-26.03'


def run_tests(config):
    log(f"Running system tests in upgrade scenario with flags "
        f"{config.env.flags}")

    # Tests are run from the base-branch folder (when upgrading ovn-controller
    # and not yet northd, new features do not work. Hence we cannot use new
    # system-tests. We use the latest .ci/linux-build.sh i.e. from
    # ovn_root_dir.
    with chdir(config.path.base_dir):
        no_debug = "0" if config.is_ci else "1"

        cmd = f"""CC={config.env.cc} TESTSUITE=system-test UPGRADE_TEST=yes
              TEST_RANGE="{config.env.flags}" UNSTABLE={config.env.unstable}
              NO_DEBUG={no_debug}
              . {config.path.ovn_root_dir}/.ci/linux-build.sh"""

        return run_shell_command(cmd)


def main():
    test_success = False

    def cleanup():
        flags = os.environ.get('TESTSUITEFLAGS', '')
        if '-d' in flags or '--debug' in flags or not test_success:
            log(f"Keeping {config.path.upgrade_dir} for debugging")
        else:
            remove_upgrade_test_directory(config)

    atexit.register(cleanup)
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(1))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(1))

    config = UpgradeConfig.get(Path.cwd(), DEFAULT_BASE_BRANCH)

    log("=" * 70)
    log(f"OVN Upgrade Test - Base: {config.base_version}, "
        f"Flags: {config.env.flags}")
    log("=" * 70)

    if run_command("sudo -v").returncode:
        log("sudo access required")
        return 1

    if not remove_upgrade_test_directory(config):
        return 1

    config.path.upgrade_dir.mkdir(parents=True, exist_ok=True)
    config.path.base_dir.mkdir(parents=True, exist_ok=True)
    config.path.binaries_dir.mkdir(parents=True, exist_ok=True)

    if not ovn_upgrade_save_current_binaries(config):
        return 1

    if not ovn_upgrade_extract_info(config):
        return 1

    if not run_upgrade_workflow(config):
        if config.is_ci:
            print(config.file.git_log.read_text(encoding='utf-8'))
        else:
            log(f"Check: {config.file.git_log}")
        return 1

    test_success = run_tests(config)

    log("=" * 70)
    if test_success:
        log("UPGRADE TESTS PASSED")
    else:
        log("UPGRADE TESTS FAILED")
        log(f"Check: {config.file.test_log}")
    log("=" * 70)

    return 0 if test_success else 1


if __name__ == "__main__":
    sys.exit(main())
