import logging
import time
from datetime import datetime

from pc_ble_driver_py.exceptions import NordicSemiException
from pc_ble_driver_py.ble_driver import util

import bond_store
from nrf_adapter        import NrfAdapter
from nrf_event          import *
from nrf_serial_no      import nrf_sd_fwid
from nrf_types          import *
from ble_gattc          import GattClient


ADDR_SHIELD = "FB:5E:B7:BD:EC:39,r"
ADDR_BUILD  = 'DE:31:CD:FB:0B:57,r'
ADDR_BUILD2 = 'F5:1A:BE:53:2E:28,r'
ADDR_WATCH  = "FE:E4:5D:E9:02:19,r"
ADDR_DEV    = "D6:60:C4:A9:6B:5F,r"

def logger_setup():
    logger = logging.getLogger('fjase')
    logger.setLevel(logging.DEBUG)

    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logging.getLogger().addHandler(sh)
    return logger

logger = logger_setup()

def _le_to_int(le):
    return int("".join(map("{0:02x}".format, le[::-1])), 16)

def _int_to_le(integer):
    return [(integer >>  0) & 0xff, (integer >>  8) & 0xff,
            (integer >> 16) & 0xff, (integer >> 24) & 0xff]

def _get_time(time_stamp = None):
    if time_stamp is None:
        time_stamp = int(time.time())
    else:
        time_stamp = int(time_stamp) # Make sure we drop second fractions
    return _int_to_le(time_stamp)

class Slice(object):
    dfu_cp      = 0x0027
    stream_cp   = 0x002b
    sync_cp     = 0x0031
    sync_data   = 0x0034
    config_cp   = 0x003a

    def __init__(self, adapter, peer_addr):
        self.adapter        = adapter
        self.peer_addr      = peer_addr

        self.conn_handle    = None
        self.own_addr       = None
        self.gattc          = None

    def connect(self):
        logger.info('BLE: Connecting...')
        with EventSync(self.adapter, GapEvtConnected) as evt_sync:
            conn_params = BLEGapConnParams(min_conn_interval_ms = 15,
                                           max_conn_interval_ms = 30,
                                           conn_sup_timeout_ms  = 4000,
                                           slave_latency        = 0)
            self.adapter.ble_gap_connect(self.peer_addr, conn_params=conn_params)

            event = evt_sync.get(timeout=2)
            if not event:
                raise NordicSemiException('Timeout. Device not found.')

            self.conn_handle    = event.conn_handle
            self.peer_addr      = event.peer_addr
            self.own_addr       = event.own_addr

        self.gattc = GattClient(self.adapter, self.conn_handle)

    def _pair(self):
        with EventSync(self.adapter, [GapEvtSec]) as evt_sync:
            self.gattc.gap_authenticate(io_caps = GapIoCaps.KEYBOARD_DISPLAY)

            event = evt_sync.get(timeout=32)
            if not isinstance(event, GapEvtSecParamsRequest):
                raise NordicSemiException('Did not get GapEvtSecParamsRequest in time.')
            key_set = BLEGapSecKeyset()
            self.adapter.ble_gap_sec_params_reply(self.conn_handle, 0, None, key_set)

            event = evt_sync.get(timeout=32)
            if not isinstance(event, GapEvtAuthKeyRequest):
                raise NordicSemiException('Did not get GapEvtConnSecUpdate in time.')
            if not event.key_type == GapAuthKeyType.PASSKEY:
                raise Exception("Unsupported auth key event")
            passkey = '123456' # passkey = raw_input("pass key: ")
            self.adapter.ble_gap_auth_key_reply(self.conn_handle, event.key_type, map(ord, passkey))

            event = evt_sync.get(timeout=32)
            if not isinstance(event, GapEvtConnSecUpdate):
                raise NordicSemiException('Did not get GapEvtConnSecUpdate in time.')
            event = evt_sync.get(timeout=32)
            if not isinstance(event, GapEvtAuthStatus):
                raise NordicSemiException('Did not get GapEvtConnSecUpdate in time.')

            # TODO: Move knowledge of sec_keyset structure
            bond_store.store_bond(self.own_addr, self.peer_addr,
                    key_set.sec_keyset.keys_peer.p_enc_key.master_id.ediv,
                    util.uint8_array_to_list(key_set.sec_keyset.keys_peer.p_enc_key.master_id.rand, 8),
                    util.uint8_array_to_list(key_set.sec_keyset.keys_peer.p_enc_key.enc_info.ltk,
                            key_set.sec_keyset.keys_peer.p_enc_key.enc_info.ltk_len),
                    key_set.sec_keyset.keys_peer.p_enc_key.enc_info.lesc,
                    key_set.sec_keyset.keys_peer.p_enc_key.enc_info.auth)

            return key_set

    def _encrypt(self, bond):
        with EventSync(self.adapter, [GapEvtSec, GapEvtDisconnected]) as evt_sync:
            self.adapter.ble_gap_encrypt(self.conn_handle, bond.ediv, bond.rand, bond.ltk, bond.lesc, bond.auth)
            event =  evt_sync.get(timeout=32)
            if   isinstance(event, GapEvtConnSecUpdate):
                if event.sec_mode == 1 and event.sec_level == 1:
                    logger.info("Enc failed, deleting bond")
                    bond_store.delete(str(bond.peer_addr))
            elif isinstance(event, GapEvtDisconnected):
                raise NordicSemiException('encryption failed.')

    def authenticate(self):
        bond = bond_store.get_bond(self.peer_addr)
        if bond:
            self._encrypt(bond)
        else:
            key_set = self._pair()
            self.enable_services()
        time.sleep(1)

    def read_name(self):
        return self.gattc.read(0x0003)

    def dfu_goto_state(self):
        self.gattc.write(self.dfu_cp + 1,     [1, 0])
        time.sleep(.1)
        self.gattc.write(self.dfu_cp, [1])

    def version_get(self):
        with EventSync(self.adapter, [GattcEvtWriteResponse, GattcEvtHvx]) as evt_sync:
            self.gattc.write(self.config_cp, [0x01, 0xFD])

    def _config_write(self, cmd):
        with EventSync(self.adapter, [GattcEvtWriteResponse, GattcEvtHvx]) as evt_sync:
            self.gattc.write(self.config_cp, cmd)

            for _ in range(5): # Arbitrarly chosen a number to not loop for ever
                event = evt_sync.get()

                if event is None:
                    logger.info("Timeout waiting for config write reply")
                    return

                if isinstance(event, GattcEvtWriteResponse):
                    if event.status == BLEGattStatusCode.cps_cccd_config_error:
                        logger.error("Config service not enabled")
                        return
                    elif event.status == BLEGattStatusCode.insuf_authentication:
                        logger.error("Not bonded")
                        return
                    else:
                        continue

                if isinstance(event, GattcEvtHvx):
                    return event

    def version_get(self):
        event = self._config_write([0x01, 0xFD])
        if not event:
            return
        data = event.data
        if len(data) >= 11 and data[2] == 1:
            fwid = data[3] + (data[4] << 8)
            print "Softdevice FWID:    0x%04x: %s"                  % (fwid, nrf_sd_fwid.get(fwid, ''))
            print 'Bootloader version: %02d.%02d.%02d.rc%02d'       % (data[ 8],   data[ 7],         data[ 6],          data[ 5])
            print 'App version:        %02d.%02d.%02d.rc%02d.%0.7x' % (data[12],   data[11],         data[10],          data[ 9],
                                                                           data[13] + (data[14] << 8) + (data[15] << 16) + (data[16] << 24))

    def enable_services(self):
        self.gattc.write(self.sync_cp   + 1,   [1, 0])
        time.sleep(.1)
        self.gattc.write(self.sync_data + 1,   [1, 0])
        time.sleep(.1)
        self.gattc.write(self.config_cp + 1,   [1, 0])
        time.sleep(.1)

    def streaming_enable(self):
        self.gattc.write(self.stream_cp + 1,   [1, 0])

    def config_wrist_action(self, on=True):
        self.gattc.write(self.config_cp, [0x11, 0x00, 1 if on else 0])

    def config_afe_current(self, current=25, led_mode=0):
        pass
        #self.gattc.write(self.fisken, [0x01, 0xfe, 0x06,
        #    0, # mode
        #    0, # profile
        #    led_mode, # LED mode (constant/increment)
        #    current, # current
        #    30, # current max
        #    ])

    def config_display_brightness(self, brightness=80):
        if brightness < 7:
            brightness = 7
        if brightness > 100:
            brightness = 100
        self.adapter.write_attr(self.config_cp, [0x10, 0x00, brightness])
        time.sleep(.1)

    def time(self, timestamp=None):
        config_cmd = [0x01, 0xF0]
        if timestamp:
            config_cmd.extend(_get_time(timestamp))
            print 'setting time', datetime.fromtimestamp(timestamp), timestamp

        self.adapter.write_attr(0x003a, config_cmd)
        #with Blipp(self.hcidev, Att.AttHandleValueNotification) as blipp:
        #    self.le_device.gattc.write(self.config_cp, config_cmd)
        #    retval = blipp.Wait(1)
        #    if len(retval) == 6 and retval[5] == 1:
        #        self.log.info("Time set")
        #    elif len(retval) > 6 and retval[5] == 1:
        #        timestamp = _le_to_int(retval[ 6:10])
        #        print 'current_time', datetime.utcfromtimestamp(timestamp), timestamp


def main(args):
    adapter = NrfAdapter.open_serial(serial_port=args.device, baud_rate=115200)

    ## Scan for devices
    #def adv_callback(event):
    #    print 'hello', repr(event)
    #    return True
    #with EventSync(adapter, GapEvtAdvReport, callback=adv_callback) as evt_sync:
    #    adapter.ble_gap_scan_start()
    #    time.sleep(.5)
    #    adapter.ble_gap_scan_stop()

    slice_device = Slice(adapter, BLEGapAddr.from_string(ADDR_DEV))
    slice_device.connect()
    slice_device.authenticate()

    #slice_device.gattc.service_discovery()
    #time.sleep(1)
    #slice_device.time((datetime.now() - datetime.utcfromtimestamp(0)).total_seconds())
    #time.sleep(1)
    print slice_device.read_name()
    #slice_device.config_display_brightness(20)
    slice_device.version_get()

    #slice_device.dfu_goto_state()
    adapter.close()


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(prog='slice_test')
    parser.add_argument("-d", "--device", dest="device", help="Select master device")
    main(parser.parse_args())

