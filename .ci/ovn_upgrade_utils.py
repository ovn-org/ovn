#!/usr/bin/env python3

import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
import contextlib
import shlex
import sys

UPGRADE_DIR = 'tests/upgrade-testsuite.dir'
SYSTEM_TESTS_LOGS = 'tests/system-kmod-testsuite.log'
SYSTEM_TESTS_DIR = 'tests/system-kmod-testsuite.dir'
BASE_REPO_DIR = 'base-repo'
BINARIES_DIR = 'ovn-upgrade-binaries'
BUILD_LOG = 'build-base.log'
GIT_LOG = 'git.log'
NEW_EGRESS = 'ovn-upgrade-new-log-egress.txt'
M4_DEFINES = 'ovn-upgrade-oftable-m4-defines.txt'
OFCTL_DEFINES = 'ovn-upgrade-ofctl-defines.h'


@contextlib.contextmanager
def chdir(target_dir):
    original_dir = Path.cwd()
    try:
        os.chdir(target_dir)
        yield
    finally:
        os.chdir(original_dir)


@dataclass
class PathConfig:
    ovn_root_dir: Path  # Path from which make check-upgrade is run
    upgrade_dir: Path   # Path where all upgrade-tests related files are stored
    base_dir: Path      # Path for base branch i.e. from which we upgrade
    binaries_dir: Path  # Path for binaries from dst branch
    test_dir: Path      # Path for system tests run by upgrade tests.


@dataclass
class FileConfig:
    git_log: Path
    test_log: Path
    build_log: Path
    new_egress: Path
    m4_defines: Path
    ofctl_defines: Path


@dataclass
class EnvConfig:
    cc: str
    flags: str
    jobs: str
    opts: str
    unstable: str
    use_sparse: str


@dataclass
class UpgradeConfig:
    path: PathConfig
    env: EnvConfig
    file: FileConfig
    base_version: str
    is_ci: bool

    @classmethod
    def get(cls, ovn_root_dir, default_base_version):
        upgrade_dir = ovn_root_dir / UPGRADE_DIR
        base_dir = upgrade_dir / BASE_REPO_DIR
        base_version = os.environ.get('BASE_VERSION', default_base_version)
        is_ci = not sys.stdout.isatty()

        path_obj = PathConfig(
            ovn_root_dir=ovn_root_dir,
            binaries_dir=upgrade_dir / BINARIES_DIR,
            base_dir=base_dir,
            upgrade_dir=upgrade_dir,
            test_dir=base_dir / SYSTEM_TESTS_DIR,
        )

        file_obj = FileConfig(
            test_log=base_dir / SYSTEM_TESTS_LOGS,
            build_log=upgrade_dir / BUILD_LOG,
            git_log=upgrade_dir / GIT_LOG,
            new_egress=upgrade_dir / NEW_EGRESS,
            m4_defines=upgrade_dir / M4_DEFINES,
            ofctl_defines=upgrade_dir / OFCTL_DEFINES
        )

        env_obj = EnvConfig(
            cc=os.environ.get('CC', 'gcc'),
            flags=os.environ.get('TESTSUITEFLAGS', ''),
            jobs=os.environ.get('JOBS', ''),
            opts=os.environ.get('OPTS', ''),
            unstable=os.environ.get('UNSTABLE', 'no'),
            # Enable parse in CI. Disable for local run as might depend of
            # content of /usr/local/include/openvswitch
            use_sparse='yes' if (is_ci and shutil.which('sparse')) else 'no'
        )

        return cls(path=path_obj, env=env_obj, file=file_obj,
                   base_version=base_version, is_ci=is_ci)

    def get_ctx(self):
        env = os.environ.copy()
        env.update(CC=self.env.cc, OPTS=self.env.opts,
                   JOBS=self.env.jobs, USE_SPARSE=self.env.use_sparse)
        return env


def log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def run_command(cmd_str, log_file=None):
    cmd = shlex.split(cmd_str)
    if log_file:
        with open(log_file, 'a', encoding='utf-8') as f:
            return subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT,
                                  check=False)
    else:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)


def run_shell_command(cmd, log_file=None, env_ctx=None):
    if log_file:
        with open(log_file, 'a', encoding='utf-8') as f:
            result = subprocess.run(['bash', '-c', cmd], stdout=f,
                                    stderr=subprocess.STDOUT, check=False,
                                    env=env_ctx)
    else:
        result = subprocess.run(['bash', '-c', cmd], check=False, env=env_ctx)
    return result.returncode == 0


def extract_oftable_values(content):
    log_egress = None
    save_inport = None
    for line in content:
        if line.startswith("#define"):
            _, var, val, *rest = line.strip().split(maxsplit=3)
            if var == "OFTABLE_LOG_EGRESS_PIPELINE":
                log_egress = int(val)
            if var == "OFTABLE_SAVE_INPORT":
                save_inport = int(val)
        if log_egress and save_inport:
            break
    return log_egress, save_inport


def replace_block_in_file(target_file, src_file, line_prefix):
    if not target_file.exists():
        return False
    if not src_file.exists():
        # No src_file file means nothing to replace.
        return True
    with open(target_file, encoding='utf-8') as f:
        lines = f.readlines()
    with open(src_file, encoding='utf-8') as f:
        new_content = f.read()

    # Replace all lines starting with line_prefix with new_content.
    output_lines = []
    inserted = False

    for line in lines:
        if line.startswith(line_prefix):
            if not inserted:
                output_lines.append(new_content)
                inserted = True
            # Skip old lines with this prefix
            continue
        output_lines.append(line)

    with open(target_file, 'w', encoding='utf-8') as f:
        f.writelines(output_lines)

    return True


def ovn_upgrade_build(config):
    log(f"Rebuilding OVN with {config.env.cc}")

    build_script = f"""
        set -e
        make {config.env.jobs}
    """
    return run_shell_command(build_script, config.file.build_log,
                             config.get_ctx())


def ovs_ovn_upgrade_build(config):
    log(f"Building OVS and OVN with {config.env.cc}")
    build_script = """
        set -e
        . .ci/linux-build.sh
    """
    return run_shell_command(build_script, config.file.build_log,
                             config.get_ctx())


def log_binary_version(binary_path, keywords):
    result = run_command(f"{binary_path} --version")
    if result.returncode == 0:
        for line in result.stdout.splitlines():
            if any(kw in line for kw in keywords):
                log(f"  {line}")


def ovn_upgrade_save_current_binaries(config):
    files = [
        'controller/ovn-controller',
        'ovs/vswitchd/ovs-vswitchd',
        'ovs/ovsdb/ovsdb-server',
        'ovs/utilities/ovs-vsctl',
        'ovs/utilities/ovs-ofctl',
        'ovs/utilities/ovs-appctl',
        'ovs/utilities/ovs-dpctl',
        'ovs/vswitchd/vswitch.ovsschema'
    ]

    log("Saving current version binaries")

    for file in files:
        try:
            shutil.copy(Path(file), config.path.binaries_dir)
        except Exception as e:
            log(f"Failed to save current binaries: failed to copy {file}: {e}")
            return False

    log("Saved current versions:")
    log_binary_version(config.path.binaries_dir / 'ovn-controller',
                       ['ovn-controller', 'SB DB Schema'])
    log_binary_version(config.path.binaries_dir / 'ovs-vswitchd', ['vSwitch'])
    return True


def ovn_upgrade_extract_info(config):
    lflow_h = Path('controller/lflow.h')
    if not lflow_h.exists():
        log('controller/lflow.h not found')
        return False

    # Get all ofctl defines from lflow.h.
    with open(lflow_h, encoding='utf-8') as f:
        oftable_defines = [
            line.strip() for line in f if line.startswith('#define OFTABLE_')
        ]

    if not oftable_defines:
        log("Failed to extract info: no #define OFTABLE_ found in lflow.h")
        return False

    with open(config.file.ofctl_defines, 'w', encoding='utf-8') as of:
        of.write('\n'.join(oftable_defines) + '\n')
    log(f"  Wrote {config.file.ofctl_defines}")

    # Get value of OFTABLE_LOG_EGRESS_PIPELINE.
    new_log_egress, _ = extract_oftable_values(oftable_defines)

    if not new_log_egress:
        log("Failed to extract info: could not extract "
            "OFTABLE_LOG_EGRESS_PIPELINE value")
        return False

    with open(config.file.new_egress, 'w', encoding='utf-8') as f:
        f.write(str(new_log_egress) + '\n')
    log(f"  Wrote {config.file.new_egress}")

    # Get all m4_define([OFTABLE_ from ovn-macros.at.
    macros_file = Path("tests/ovn-macros.at")
    if macros_file.exists():
        with open(macros_file, encoding='utf-8') as f:
            m4_defines = [
                line.strip() for line in f
                if line.startswith('m4_define([OFTABLE_')
            ]

            with open(config.file.m4_defines, 'w', encoding='utf-8') as of:
                of.write('\n'.join(m4_defines) + '\n' if m4_defines else '')
            log(f"  Wrote {config.file.m4_defines}")

    return True


def ovn_upgrade_checkout_local(config, base_version):
    base_dir = config.path.base_dir
    git_log = config.file.git_log
    log(f"Running locally. Cloning to {base_dir}")

    result = run_command(f"git clone --local --shared . {str(base_dir)} "
                         f" --branch {base_version}", git_log)
    if result.returncode:
        log(f"Failed to clone to {base_dir}")
        return False

    with chdir(base_dir):
        log(f"Checking out base version: {base_version} from {base_dir}")
        result = run_command(f"git checkout {base_version}", git_log)

        if result.returncode:
            log(f"Failed to checkout {base_version}")
            return False

        return True


def ovn_upgrade_clone_github(config, base_version):
    base_dir = config.path.base_dir
    git_log = config.file.git_log

    result = run_command("git config --get remote.origin.url")
    if result.returncode or not result.stdout.strip():
        log("Could not get origin URL from working directory")
        return False

    origin_url = result.stdout.strip()
    with chdir(base_dir):
        log(f"Cloning {base_version} from {origin_url} ")
        result = run_command(f"git clone {origin_url} {base_dir} "
                             f"--branch {base_version} --depth 1 "
                             "--no-tags", git_log)

        if (result.returncode and
                origin_url != "https://github.com/ovn-org/ovn"):
            log(f"Not found in {origin_url}, trying ovn-org...")
            result = run_command(
                "git clone https://github.com/ovn-org/ovn.git "
                f"{base_dir} --branch {base_version} --depth 1 "
                "--no-tags", git_log
            )
        if result.returncode:
            log(f"Failed to clone {base_version}")
            log(result.stderr)
            return False

        return True


def ovn_upgrade_checkout_base(config):
    base_dir = config.path.base_dir
    base_version = config.base_version
    git_log = config.file.git_log
    is_local = True

    if base_version.startswith('origin/'):
        base_version = base_version.split('/', 1)[-1]
        is_local = False

    success = False
    if is_local:
        success = ovn_upgrade_checkout_local(config, base_version)

    if not success:
        # Branch not requested or found in local repo.
        # Get working directory's origin URL (the real remote, e.g., GitHub)
        success = ovn_upgrade_clone_github(config, base_version)

    if not success:
        log(f"Failed to fetch/checkout {base_version}")
        return False

    # Now move to folder with the cloned version, where we will build
    # the base.
    with chdir(base_dir):
        result = run_command(f"git checkout {base_version}", git_log)

        if result.returncode:
            log(f"Failed to checkout {base_version}")
            log(result.stderr)
            return False

        log(f"Checked out {base_version}")
        log("Updating OVS submodule...")
        result = run_command("git submodule update --init --depth 1", git_log)

        if result.returncode:
            log(f"Failed to update submodules: {result.stderr}")
            return False

        return True


def ovn_upgrade_patch_for_ovn_debug(config):
    return replace_block_in_file(
        Path('controller/lflow.h'),
        config.file.ofctl_defines,
        '#define OFTABLE_')


def ovn_upgrade_save_ovn_debug(binaries_dir):
    log("Saving hybrid ovn-debug...")
    src = Path("utilities/ovn-debug")
    dst = binaries_dir / "ovn-debug"

    try:
        shutil.copy(src, dst)
    except Exception as e:
        log(f"Failed to save ovn-debug: {e}")
        return False

    return True


def _parse_oftable_defines(lines):
    """Return {name: int_value} for all OFTABLE_ #defines."""
    result = {}
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and parts[0] == '#define' \
                and parts[1].startswith('OFTABLE_'):
            try:
                result[parts[1]] = int(parts[2])
            except ValueError:
                pass
    return result


def update_test(table_remap, test_file):
    with open(test_file, encoding='utf-8') as f:
        content = f.read()

    def replace_table(match):
        table_num = int(match.group(1))
        if table_num in table_remap:
            return f"table={table_remap[table_num]}"
        return match.group(0)

    # Replace all table=NUMBER patterns
    updated_content = re.sub(r'table\s*=\s*(\d+)', replace_table, content)

    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(updated_content)


def ovn_upgrade_table_numbers_in_tests_patch(config):
    lflow_h = Path('controller/lflow.h')

    if not config.file.ofctl_defines.exists():
        log("No ofctl defines file")
        return False

    if not lflow_h.exists():
        log("Controller/lflow.h not found")
        return False

    # Get new OFTABLE values (saved from the current version).
    with open(config.file.ofctl_defines, encoding='utf-8') as f:
        new_defines = _parse_oftable_defines(f.readlines())

    # Get old OFTABLE values from the base version's lflow.h.
    with open(lflow_h, encoding='utf-8') as f:
        old_defines = _parse_oftable_defines(f.readlines())

    old_log_egress = old_defines.get('OFTABLE_LOG_EGRESS_PIPELINE')
    old_save_inport = old_defines.get('OFTABLE_SAVE_INPORT')

    if not old_log_egress or not old_save_inport:
        log("Could not extract LOG_EGRESS / SAVE_INPORT from base")
        return False

    new_log_egress = new_defines.get('OFTABLE_LOG_EGRESS_PIPELINE')

    # Build {old_value: new_value} remap for all changed tables.
    table_remap = {}

    # Range-based shift for in-pipeline tables [LOG_EGRESS, SAVE_INPORT).
    # These include hardcoded offsets that are not OFTABLE_ defines.
    if new_log_egress and new_log_egress != old_log_egress:
        shift = new_log_egress - old_log_egress
        for t in range(old_log_egress, old_save_inport):
            table_remap[t] = t + shift

    # Exact remap for every OFTABLE_ define that changed and is
    # outside the pipeline range (e.g. CHK_LB_AFFINITY, ECMP_NH).
    for name, old_val in old_defines.items():
        if name in new_defines and new_defines[name] != old_val:
            if old_val not in table_remap:
                table_remap[old_val] = new_defines[name]

    if not table_remap:
        log("No table number changes detected")
        return True

    log(f"Updating hardcoded table numbers in tests "
        f"({len(table_remap)} table(s) remapped)")

    # Update test files
    for test_file in ['tests/system-ovn.at', 'tests/system-ovn-kmod.at',
                      'tests/system-ovn-netlink.at']:
        if Path(test_file).exists():
            log(f"Updating {test_file}")
            update_test(table_remap, test_file)
    return True


def ovn_upgrade_schema_in_macros_patch():
    schema_filter = '/OVN_Southbound database lacks/d'
    ovn_pattern = r'/has no network name\*/d'

    macros_file = Path('tests/ovn-macros.at')
    if macros_file.exists():
        with open(macros_file, encoding='utf-8') as f:
            content = f.read()

        if schema_filter not in content:
            if re.search(ovn_pattern, content):
                content = re.sub(f'({ovn_pattern})',
                                 rf'\1\n{schema_filter}', content, count=1)
                with open(macros_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                log("Added schema warning filter to ovn-macros.at")
            else:
                log("Could not find pattern in ovn-macros.at")
        else:
            log("Schema already updated in macro")
    else:
        log("tests/ovn-macros.at not found")
        return False

    kmod_file = Path('tests/system-kmod-macros.at')
    if kmod_file.exists():
        with open(kmod_file, encoding='utf-8') as f:
            content = f.read()

        if schema_filter not in content:
            ovs_pattern = r'\[OVS_VSWITCHD_STOP\(\[\$1\]\)'

            if re.search(ovs_pattern, content):
                content = re.sub(
                    ovs_pattern,
                    rf'[OVS_VSWITCHD_STOP([dnl\n$1";{schema_filter}"])',
                    content, count=1)
                with open(kmod_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                log("Added schema warning filter to system-kmod-macros.at")
            else:
                log("Could not find pattern in system-kmod-macros.at")
                return False

    return True


def ovn_upgrade_oftable_ovn_macro_patch(config):
    return replace_block_in_file(
        Path('tests/ovn-macros.at'),
        config.file.m4_defines,
        'm4_define([OFTABLE_')


def ovn_upgrade_apply_tests_patches(config):
    log("Applying schema filter and table number patches...")
    if not ovn_upgrade_table_numbers_in_tests_patch(config):
        return False
    if not ovn_upgrade_schema_in_macros_patch():
        return False
    if not ovn_upgrade_oftable_ovn_macro_patch(config):
        return False
    return True


def ovn_upgrade_restore_binaries(config):
    log("Replacing binaries with current versions")

    binaries = [
        ('ovn-controller', 'controller/ovn-controller'),
        ('ovn-debug', 'utilities/ovn-debug'),
        ('ovs-vswitchd', 'ovs/vswitchd/ovs-vswitchd'),
        ('ovsdb-server', 'ovs/ovsdb/ovsdb-server'),
        ('ovs-vsctl', 'ovs/utilities/ovs-vsctl'),
        ('ovs-ofctl', 'ovs/utilities/ovs-ofctl'),
        ('ovs-appctl', 'ovs/utilities/ovs-appctl'),
        ('ovs-dpctl', 'ovs/utilities/ovs-dpctl'),
        ('vswitch.ovsschema', 'ovs/vswitchd/vswitch.ovsschema'),
    ]

    for src_name, dest_path in binaries:
        src = config.path.binaries_dir / src_name
        dest = Path(dest_path)
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(src, dest)
        except Exception as e:
            log(f"Failed to copy {src_name} to {dest}: {e}")
            return False

    log("Current versions (from current patch):")
    log_binary_version("controller/ovn-controller",
                       ['ovn-controller', 'SB DB Schema'])
    log_binary_version("ovs/vswitchd/ovs-vswitchd", ['vSwitch'])

    log("Base versions (for compatibility testing):")
    log_binary_version("northd/ovn-northd", ['ovn-northd'])
    log_binary_version("utilities/ovn-nbctl", ['ovn-nbctl'])

    return True


def run_upgrade_workflow(config):
    base_dir = config.path.base_dir
    git_log = config.file.git_log
    build_log = config.file.build_log
    binaries_dir = config.path.binaries_dir

    if not ovn_upgrade_checkout_base(config):
        log("Upgrade_workflow failed: failed to checkout base version")
        return False

    with chdir(base_dir):
        if not ovn_upgrade_apply_tests_patches(config):
            log("Upgrade_workflow failed: failed to apply test patches")
            return False

        log("Patching lflow.h with current OFTABLE defines...")
        ovn_upgrade_patch_for_ovn_debug(config)

        # Build base version with patched lflow.h
        log(f"Building base version (with patched lflow.h) from {Path.cwd()}")
        if not ovs_ovn_upgrade_build(config):
            log("Upgrade_workflow failed: failed to build base version")
            log(f"See config.log and {build_log}")
            return False

        # Refresh sudo timestamp after long build
        run_command("sudo -v")

        if not ovn_upgrade_save_ovn_debug(binaries_dir):
            log("Upgrade_workflow failed: failed to save ovn_debug")
            return False

        # Rebuild with original lflow.h
        log("Restoring lflow.h to original...")
        run_command("git checkout controller/lflow.h", git_log)

        log("Rebuilding base version (clean lflow.h)...")
        if not ovn_upgrade_build(config):
            log("Upgrade_workflow failed: failed to rebuild base version")
            log(f"See {build_log}")
            return False

        if not ovn_upgrade_restore_binaries(config):
            return False

        return True


def remove_upgrade_test_directory(config):
    upgrade_dir = config.path.upgrade_dir
    test_dir = config.path.test_dir
    test_log = config.file.test_log

    if not upgrade_dir.exists():
        return True

    log(f"Removing old {upgrade_dir}...")

    run_command(f"sudo rm -rf {test_dir}")
    run_command(f"sudo rm -f {test_log}")

    try:
        shutil.rmtree(upgrade_dir)
        return True
    except OSError as e:
        log(f"Failed to remove {upgrade_dir}: {e}")
        return False
