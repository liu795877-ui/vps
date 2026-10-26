"""Read-only, credential-safe member service startup diagnostics."""

import json
import re
from ssh_access import FOLDER, connect, execute


def main():
    client = connect()
    try:
        code, output, error = execute(client,
            "journalctl --no-pager --since '20 minutes ago' -u 'xray-panel@*.service' -o json", timeout=45)
        (FOLDER / 'multiuser-member-journal.private.log').write_text(output + '\n' + error, encoding='utf-8')
        messages = []
        for line in output.splitlines():
            try:
                message = json.loads(line).get('MESSAGE', '')
            except (ValueError, AttributeError):
                continue
            if not isinstance(message, str):
                continue
            if re.search(r'Failed at step|Failed to set|status=|Operation not permitted|Permission denied|Failed to start|Failed to load|kernel does not support|Failed to determine|Namespace', message, re.I):
                # Systemd step/status lines carry process ids and paths, never
                # the private Xray config. Do not surface generic Xray output.
                messages.append(message)
        print(json.dumps({'journal_read_success':code == 0, 'diagnostic_messages':list(dict.fromkeys(messages))}))
    finally:
        client.close()


if __name__ == '__main__':
    main()
