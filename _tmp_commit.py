import subprocess, os, glob, sys
candidates = sorted(glob.glob("/private/tmp/s*-n*s"))
print("Candidates:", candidates)
dest = candidates[0]
os.chdir(dest)
print("cwd:", os.getcwd())
for args in (
    ["git", "add", "shannon/src/parsers/nats.rs"],
    ["git", "commit", "-m", "feat(parser): NATS core protocol with CONNECT credential redaction"],
    ["git", "rev-parse", "HEAD"],
):
    r = subprocess.run(args, capture_output=True, text=True)
    print(args, r.returncode)
    print("stdout:", r.stdout)
    print("stderr:", r.stderr)
    if r.returncode != 0 and args[1] != "commit":
        sys.exit(1)
