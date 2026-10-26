"""Deploy reviewed files, without logging usable credentials."""

import json
from ssh_access import connect, execute, FOLDER

STAGE = "/root/raksmart-proxy-deploy-20261009"
client = connect()
try:
    code, output, error = execute(client, "install -d -m 0700 " + STAGE)
    if code:
        raise RuntimeError("Unable to prepare staging directory")
    with client.open_sftp() as sftp:
        for local, remote, mode in [
            ("artifacts/linux-64/xray", "xray-ready", 0o700),
            ("server.private.json", "config.json", 0o600),
            ("xray.service", "xray.service", 0o600),
            ("install_remote.sh", "install.sh", 0o700),
        ]:
            sftp.put(str(FOLDER / local), STAGE + "/" + remote, confirm=True)
            sftp.chmod(STAGE + "/" + remote, mode)
    code, output, error = execute(client, "bash " + STAGE + "/install.sh", timeout=55)
    report = {"remote_exit": code, "stdout": output, "stderr": error}
    (FOLDER / "deployment-result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(output)
    if error:
        print(error)
    if code:
        raise SystemExit(code)
finally:
    client.close()
