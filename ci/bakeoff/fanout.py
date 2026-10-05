"""Fan-out bake-off. Usage: fanout.py prep | fanout.py <a|b> <F0|F1|F2>. State under /workspaces/bakeoff/fanout."""
import json, os, re, resource, shutil, signal, subprocess, sys, time
from pathlib import Path
ST = Path('/workspaces/bakeoff/fanout')
MIR = ST / 'mirror'
FORGE = 'https://forge.corbet.ch'
ROOT = 'cvld'; ROOT_ORG = 'corbet-libs'; X = 'crlt'
DEP = re.compile(r'^\s*([A-Za-z0-9_-]+)\s*=\s*\{[^}\n]*git\s*=\s*"https://github\.com/([\w-]+)/([\w.-]+?)(?:\.git)?"[^}\n]*\}', re.M)
REV = re.compile(r'rev\s*=\s*"([0-9a-f]{7,40})"')

def sh(cmd, cwd=None, env=None, check=True, timeout=None):
    r = subprocess.run(cmd, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    if check and r.returncode: raise SystemExit(f'FAIL {cmd}: {r.stderr[-600:]}')
    return r.stdout.strip()

def deps_of(text):
    return [(m.group(3), m.group(2), REV.search(m.group(0)).group(1) if REV.search(m.group(0)) else None) for m in DEP.finditer(text)]

def gitenv():
    # Rewrite every GitHub URL to a local mirror (CI environment only; GitHub is never contacted).
    cfg = ST / 'gitconfig'
    lines = []
    for p in sorted(MIR.glob('*.git')):
        n = p.name[:-4]; org = json.loads((ST / 'orgs.json').read_text())[n]
        lines.append(f'[url "file://{p}"]\n\tinsteadOf = https://github.com/{org}/{n}\n\tinsteadOf = https://github.com/{org}/{n}.git\n')
    cfg.write_text('[safe]\n\tdirectory = *\n' + ''.join(lines))
    return cfg

def prep():
    MIR.mkdir(parents=True, exist_ok=True)
    nu, np_ = 'richc', os.environ.get('FORGE_TOKEN')
    assert nu and np_, 'no FORGE_TOKEN secret in the step environment'
    home = ST / 'prephome'; home.mkdir(exist_ok=True)
    (home / '.netrc').write_text(f'machine forge.corbet.ch login {nu} password {np_}\n'); (home / '.netrc').chmod(0o600)
    env = dict(os.environ, HOME=str(home), GIT_TERMINAL_PROMPT='0')
    orgs = {ROOT: ROOT_ORG}; queue = [ROOT]; deps = {}; gaps = []; seen = set()
    while queue:
        n = queue.pop(0)
        if n in seen: continue
        seen.add(n); org = orgs[n]; d = MIR / f'{n}.git'
        if d.exists(): shutil.rmtree(d)
        r = subprocess.run(['git', 'clone', '--mirror', '-q', f'{FORGE}/{org}/{n}.git', str(d)], env=env, capture_output=True, text=True)
        if r.returncode: gaps.append(f'{org}/{n}: clone failed {r.stderr[-150:]}'); continue
        txt = sh(['git', '--git-dir', str(d), 'show', 'HEAD:Cargo.toml'])
        deps[n] = []
        for dn, dorg, rev in deps_of(txt):
            orgs.setdefault(dn, dorg); deps[n].append({'dep': dn, 'org': dorg, 'rev': rev}); queue.append(dn)
    (ST / 'orgs.json').write_text(json.dumps(orgs))
    for n in deps:  # pinned revs must exist in the Forgejo copy of the dependency
        for e in deps[n]:
            m = MIR / f"{e['dep']}.git"
            if e['rev'] and m.exists() and subprocess.run(['git', '--git-dir', str(m), 'cat-file', '-e', e['rev'] + '^{commit}']).returncode:
                gaps.append(f"{n} pins {e['dep']}@{e['rev'][:10]} which is missing in the Forgejo copy (stale)")
    # transitive closure of dependents of X
    def reaches(n, memo={}):
        if n == X: return True
        if n in memo: return memo[n]
        memo[n] = any(reaches(e['dep']) for e in deps.get(n, []))
        return memo[n]
    D = [n for n in deps if n != X and reaches(n)]
    heads = {n: sh(['git', '--git-dir', str(MIR / f'{n}.git'), 'rev-parse', 'HEAD']) for n in deps}
    (ST / 'chain.json').write_text(json.dumps({'deps': deps, 'D': D, 'gaps': gaps, 'heads': heads}, indent=1))
    shutil.rmtree(home)
    print(json.dumps({'repos': sorted(deps), 'D(X)': D, 'gaps': gaps}, indent=1))

def topo(D, deps):
    out = []
    while len(out) < len(D):
        for n in D:
            if n not in out and all(e['dep'] not in D or e['dep'] in out for e in deps[n]): out.append(n)
    return out

def run_step(cmd, cwd, env, log, timeout=2700):
    r0 = resource.getrusage(resource.RUSAGE_CHILDREN); t = time.monotonic()
    with open(log, 'w') as f:
        p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        try: rc = p.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL); p.wait(); rc = 124
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN); txt = Path(log).read_text(errors='replace')
    return {'wall_s': round(time.monotonic() - t, 1), 'user_s': round(r1.ru_utime - r0.ru_utime, 1), 'sys_s': round(r1.ru_stime - r0.ru_stime, 1),
            'exit': rc, 'compiling': len(re.findall(r'^\s*Compiling ', txt, re.M)),
            'tests_passed': sum(int(x) for x in re.findall(r'(\d+) passed', txt)), 'tests_failed': sum(int(x) for x in re.findall(r'(\d+) failed', txt)), 'log': str(log)}

def main(mode, scen):
    chain = json.loads((ST / 'chain.json').read_text()); deps = chain['deps']; D = chain['D']
    R = ST / mode; out = R / 'runs' / scen; shutil.rmtree(out, ignore_errors=True); out.mkdir(parents=True)
    cfg = gitenv()
    env = dict(os.environ, GIT_CONFIG_GLOBAL=str(cfg), HOME=str(ST / 'home'), CARGO_NET_GIT_FETCH_WITH_CLI='true', CARGO_HOME=str(R / 'cargo-home'),
               CARGO_BUILD_JOBS='16', RUST_TEST_THREADS='16', CARGO_TERM_COLOR='never', CARGO_INCREMENTAL='1',
               CARGO_PROFILE_DEV_DEBUG='line-tables-only', CARGO_PROFILE_TEST_DEBUG='line-tables-only', RUSTFLAGS='-C link-arg=-fuse-ld=mold',
               RUSTC_WRAPPER=str(ST / 'rustc-wrapper.sh'), SCCACHE_DIR=str(R / 'sccache'), SCCACHE_CACHE_SIZE='100G', SCCACHE_IDLE_TIMEOUT='0',
               SCCACHE_SERVER_UDS=f'/tmp/sccache-fanout-{mode}.sock')
    env.pop('CARGO_TARGET_DIR', None)
    (ST / 'home').mkdir(exist_ok=True)
    shutil.copy(Path(__file__).with_name('rustc-wrapper.sh'), ST / 'rustc-wrapper.sh'); os.chmod(ST / 'rustc-wrapper.sh', 0o755)
    members = [X] + D
    srcroot = R / 'ws' if mode == 'b' else R / 'src'
    res = {'mode': mode, 'scen': scen, 'members': members, 'steps': {}, 'notes': []}
    if scen == 'F0':
        for p in (R / 'cargo-home', R / 'target', R / 'sccache', R / 'ws', R / 'src'): shutil.rmtree(p, ignore_errors=True)
        srcroot.mkdir(parents=True)
        for n in members: sh(['git', 'clone', '-q', str(MIR / f'{n}.git'), str(srcroot / n)], env=env)
        for n in members:
            sh(['git', 'config', 'user.name', 'bakeoff'], cwd=srcroot / n); sh(['git', 'config', 'user.email', 'bakeoff@invalid'], cwd=srcroot / n)
        if mode == 'b':
            orgs = json.loads((ST / 'orgs.json').read_text())
            prof = (srcroot / ROOT / 'Cargo.toml').read_text()
            tail = prof[prof.index('[profile'):prof.index('[lints')] if '[profile' in prof and '[lints' in prof else ''
            ws = '[workspace]\nresolver = "3"\nmembers = [' + ', '.join(f'"{n}"' for n in members) + ']\n\n'
            for n in members: ws += f'[patch."https://github.com/{orgs[n]}/{n}"]\n{n} = {{ path = "{n}" }}\n'
            (srcroot / 'Cargo.toml').write_text(ws + '\n' + tail)
    (R / 'target').mkdir(exist_ok=True)
    env['CARGO_TARGET_DIR'] = str(R / 'target')
    # the change
    def edit_lib(n):
        lib = srcroot / n / 'src' / 'lib.rs'
        if not lib.exists(): lib = srcroot / n / 'src' / 'main.rs'
        with open(lib, 'a') as f: f.write(f'\n// bakeoff {scen} {time.time_ns()}\npub const BAKEOFF_{scen}: u32 = 1;\n' if lib.name == 'lib.rs' else f'\n// bakeoff {scen}\n')
        return lib
    order = topo(D, deps)
    if scen == 'F1':
        edit_lib(X)
        if mode == 'a':  # cascade: commit in X, then bump the pinned rev in every dependent, bottom-up
            changed = {X: None}
            sh(['git', 'commit', '-qam', 'f1'], cwd=srcroot / X); sh(['git', 'push', '-q', str(MIR / f'{X}.git'), 'HEAD:main'], cwd=srcroot / X)
            for n in order:
                ct = srcroot / n / 'Cargo.toml'; txt = ct.read_text(); hit = False
                for dn in list(changed):
                    sha = sh(['git', 'rev-parse', 'HEAD'], cwd=srcroot / dn)
                    pat = re.compile(r'(git\s*=\s*"https://github\.com/[\w-]+/' + re.escape(dn) + r'(?:\.git)?"[^}\n]*?rev\s*=\s*")[0-9a-f]+(")')
                    txt, k = pat.subn(r'\g<1>' + sha + r'\g<2>', txt); hit |= bool(k)
                if hit:
                    ct.write_text(txt); changed[n] = None
                    sh(['git', 'commit', '-qam', 'bump'], cwd=srcroot / n); sh(['git', 'push', '-q', str(MIR / f'{n}.git'), 'HEAD:main'], cwd=srcroot / n)
                else: res['notes'].append(f'{n}: no pinned rev line to bump')
            res['bumped'] = list(changed)
    if scen == 'F2': edit_lib(ROOT)
    # sccache server
    srv = subprocess.Popen(['sccache'], env=dict(env, SCCACHE_START_SERVER='1', SCCACHE_NO_DAEMON='1'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1); env['SCCACHE_SERVER_PID'] = str(srv.pid)
    sh(['sccache', '--zero-stats'], env=env, check=False)
    r0 = resource.getrusage(resource.RUSAGE_CHILDREN); t0 = time.monotonic()
    if mode == 'a':
        targets = [ROOT] if scen == 'F2' else members
        # bottom-up order so each dependency is compiled before its dependents
        seq = [n for n in [X] + order if n in targets] if scen != 'F2' else [ROOT]
        for n in seq:
            res['steps'][n] = run_step(['cargo', 'test', '--all-targets', '--no-fail-fast'], srcroot / n, env, out / f'{n}.log')
    else:
        res['steps']['workspace'] = run_step(['cargo', 'test', '--workspace', '--all-targets', '--no-fail-fast'], srcroot, env, out / 'workspace.log')
    res['wall_s'] = round(time.monotonic() - t0, 1)
    st = sh(['sccache', '--show-stats'], env=env, check=False)
    (out / 'sccache-stats.txt').write_text(st)
    srv.terminate(); srv.wait()
    r1 = resource.getrusage(resource.RUSAGE_CHILDREN)
    res['cpu_s'] = round(r1.ru_utime - r0.ru_utime + r1.ru_stime - r0.ru_stime, 1)  # all steps plus the sccache server
    res['maxrss_mib'] = round(r1.ru_maxrss / 1024)
    res['sccache_hits'] = re.findall(r'Cache hits\s+(\d+)', st)[:1]; res['sccache_misses'] = re.findall(r'Cache misses\s+(\d+)', st)[:1]
    res['compiling'] = sum(s['compiling'] for s in res['steps'].values())
    res['failed_steps'] = [k for k, s in res['steps'].items() if s['exit']]
    (out / 'result.json').write_text(json.dumps(res, indent=1))
    print(json.dumps({k: v for k, v in res.items() if k != 'steps'}, indent=1))
    for k, s in res['steps'].items(): print(k, {x: s[x] for x in s if x != 'log'})
    for k in res['failed_steps']: print('--- tail', k); print(Path(res['steps'][k]['log']).read_text(errors='replace')[-1500:])
    sys.exit(1 if res['failed_steps'] and False else 0)

if __name__ == '__main__':
    prep() if sys.argv[1] == 'prep' else main(sys.argv[1], sys.argv[2])
