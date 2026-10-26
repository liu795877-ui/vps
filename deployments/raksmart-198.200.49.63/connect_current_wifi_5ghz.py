"""Select the existing profile's strong 5 GHz AP using the Windows WLAN API.

No elevation, password reads, driver settings or network profile changes.
Failure reconnects the same original profile/AP. Only --run reconnects.
"""
import argparse
import ctypes as C
import json
from pathlib import Path
import re
import subprocess
import time
import uuid

FOLDER = Path(__file__).resolve().parent


def netsh(*args):
    p = subprocess.run(['netsh', 'wlan'] + list(args), capture_output=True, timeout=12)
    if p.returncode:
        raise RuntimeError('WLAN status command failed')
    return p.stdout.decode('utf-8', 'replace')


def current():
    raw = netsh('show', 'interfaces')
    def value(key):
        found = re.search(r'^\s*' + re.escape(key) + r'\s*:\s*(.*?)\s*$', raw, re.M)
        return found.group(1) if found else None
    result = {k: value(k) for k in ('Name', 'GUID', 'State', 'SSID', 'Profile', 'Band', 'Channel')}
    result['bssid'] = value('AP BSSID') or value('BSSID')
    if not (result['Name'] == 'WLAN' and result['State'] == 'connected'
            and result['SSID'] == 'HONOR' and result['Profile'] == 'HONOR'):
        raise RuntimeError('Current WLAN profile differs from the verified network')
    return result


class GUID(C.Structure):
    _fields_ = [('Data1', C.c_uint32), ('Data2', C.c_uint16),
                ('Data3', C.c_uint16), ('Data4', C.c_ubyte * 8)]


class HEADER(C.Structure):
    _fields_ = [('Type', C.c_ubyte), ('Revision', C.c_ubyte), ('Size', C.c_uint16)]


class BSSID_LIST(C.Structure):
    _fields_ = [('Header', HEADER), ('uNumOfEntries', C.c_uint32),
                ('uTotalNumOfEntries', C.c_uint32), ('BSSIDs', (C.c_ubyte * 6) * 1)]


class PARAMETERS(C.Structure):
    _fields_ = [('wlanConnectionMode', C.c_uint32), ('strProfile', C.c_wchar_p),
                ('pDot11Ssid', C.c_void_p), ('pDesiredBssidList', C.POINTER(BSSID_LIST)),
                ('dot11BssType', C.c_uint32), ('dwFlags', C.c_uint32)]


def connect(wlan, handle, interface, profile, mac):
    guid = GUID.from_buffer_copy(uuid.UUID(interface).bytes_le)
    preferred = BSSID_LIST()
    preferred.Header = HEADER(0x80, 1, C.sizeof(BSSID_LIST))
    preferred.uNumOfEntries = preferred.uTotalNumOfEntries = 1
    preferred.BSSIDs[0][:] = bytes.fromhex(mac.replace(':', ''))
    params = PARAMETERS(0, profile, None, C.pointer(preferred), 1, 0)
    return wlan.WlanConnect(handle, C.byref(guid), C.byref(params), None)


def main(run):
    result = {'success': False, 'connection_attempted': False,
              'profile_settings_changed': False, 'driver_settings_changed': False,
              'wifi_password_read': False, 'elevation_requested': False}
    wlan = handle = None
    before = None
    try:
        before = current()
        result['before'] = {k: v for k, v in before.items() if k not in ('bssid', 'GUID')}
        blocks = re.split(r'(?m)^SSID [0-9]+\s*:', netsh('show', 'networks', 'mode=bssid'))
        candidate = None
        for block in blocks[1:]:
            if block.splitlines()[0].strip() != before['SSID']:
                continue
            for match in re.finditer(r'BSSID\s+\d+\s*:\s*([0-9a-fA-F:]{17})(.*?)(?=BSSID\s+\d+\s*:|\Z)', block, re.S):
                if re.search(r'Band\s*:\s*5 GHz', match.group(2)):
                    signal = re.search(r'Signal\s*:\s*(\d+)%', match.group(2))
                    if signal and int(signal.group(1)) >= 70:
                        candidate = match.group(1)
                        result['candidate_signal_percent'] = int(signal.group(1))
                        break
        if not candidate:
            raise RuntimeError('No strong 5 GHz AP for the original profile')
        uuid.UUID(before['GUID'])
        if not all(re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac or '')
                   for mac in (before['bssid'], candidate)):
            raise RuntimeError('Invalid original or target AP identity')
        if not run:
            result.update(success=True, read_only=True, candidate_band='5 GHz')
            return result
        wlan = C.WinDLL('wlanapi.dll')
        wlan.WlanOpenHandle.argtypes = [C.c_uint32, C.c_void_p, C.POINTER(C.c_uint32), C.POINTER(C.c_void_p)]
        wlan.WlanOpenHandle.restype = C.c_uint32
        wlan.WlanConnect.argtypes = [C.c_void_p, C.POINTER(GUID), C.POINTER(PARAMETERS), C.c_void_p]
        wlan.WlanConnect.restype = C.c_uint32
        wlan.WlanCloseHandle.argtypes = [C.c_void_p, C.c_void_p]
        wlan.WlanCloseHandle.restype = C.c_uint32
        handle, negotiated = C.c_void_p(), C.c_uint32()
        code = wlan.WlanOpenHandle(2, None, C.byref(negotiated), C.byref(handle))
        if code:
            result['api_error_code'] = code
            raise RuntimeError('Unable to open native WLAN handle')
        result['connection_attempted'] = True
        code = connect(wlan, handle, before['GUID'], before['Profile'], candidate)
        result['connect_return_code'] = code
        if code:
            raise RuntimeError('Native WLAN connect refused')
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            try:
                after = current()
                if after['Band'] == '5 GHz' and after['bssid'].lower() == candidate.lower():
                    result.update(success=True, after={k: v for k, v in after.items() if k not in ('bssid', 'GUID')},
                                  same_profile=True, original_access_network_retained=True)
                    return result
            except RuntimeError:
                pass
            time.sleep(1)
        raise RuntimeError('Requested 5 GHz AP was not selected')
    except Exception as error:
        result['error_type'] = type(error).__name__
        if result['connection_attempted'] and wlan and handle:
            result['restore_original_ap_return_code'] = connect(
                wlan, handle, before['GUID'], before['Profile'], before['bssid'])
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                try:
                    restored = current()
                    result['original_profile_connection_restored'] = all(
                        restored[key] == before[key] for key in ('Profile', 'SSID', 'Name', 'GUID'))
                    result['original_ap_restored'] = (result['original_profile_connection_restored']
                        and restored['bssid'].lower() == before['bssid'].lower())
                    if result['original_ap_restored']:
                        break
                except RuntimeError:
                    pass
                time.sleep(1)
    finally:
        if wlan and handle:
            wlan.WlanCloseHandle(handle, None)
        if run:
            (FOLDER / 'fast-browser-wifi-band-switch.json').write_text(
                json.dumps(result, indent=2) + '\n', encoding='utf-8')
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true')
    result = main(parser.parse_args().run)
    print(json.dumps(result))
    raise SystemExit(0 if result['success'] else 1)
