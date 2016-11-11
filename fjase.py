import abc
import logging
import Queue
import time
#import struct
#import binascii
from datetime import datetime

from pc_ble_driver_py.exceptions    import NordicSemiException, IllegalStateException
from pc_ble_driver_py.ble_driver    import driver, util, BLEDriverObserver, NordicSemiException
from pc_ble_driver_py.ble_driver    import BLEGapAddr, BLEGapConnParams, BLEGattcWriteParams, BLEGattWriteOperation, BLEGattExecWriteFlag, NordicSemiException

import bond_store
from nrf_event import *
from fjase_ble_driver import FjaseBLEDriver, RawBLEDriverObserver


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

class Fjase(object):
    dfu_cp      = 0x0027
    stream_cp   = 0x002b
    sync_cp     = 0x0031
    sync_data   = 0x0034
    config_cp   = 0x003a

    def __init__(self, serial_port, baud_rate=115200):
        self.baud_rate      = baud_rate
        self.serial_port    = serial_port
        self.adapter        = None

        self.conn_handle    = None
        self.peer_addr      = None
        self.own_addr       = None

    def open(self):
        logger.debug("Connecting to adapter")
        if self.adapter:
            raise IllegalStateException('DFU Adapter is already open')

        driver = FjaseBLEDriver(serial_port = self.serial_port, baud_rate = self.baud_rate)
        self.adapter = FjaseAdapter(driver)
        self.adapter.open()

    def close(self):
        logger.debug("Disconnecting adapter")
        if not self.adapter:
            raise IllegalStateException('DFU Adapter is already closed')
        self.adapter.close()
        self.adapter = None

    def scan_start(self, timeout=1):
        logger.info('BLE: Scanning...')
        self.adapter.ble_gap_scan_start()
        time.sleep(timeout)
        self.adapter.ble_gap_scan_stop()

    def connect(self, target_device_addr):
        logger.info('BLE: Connecting...')
        conn_params = BLEGapConnParams(min_conn_interval_ms = 15,
                                       max_conn_interval_ms = 30,
                                       conn_sup_timeout_ms  = 4000,
                                       slave_latency        = 0)
        self.adapter.ble_gap_connect(address    = target_device_addr, conn_params = conn_params)

        evt, params = self.adapter.event_q.get(timeout=1)
        if evt == 'BLE_GAP_EVT_CONNECTED':
            # params contains (conn_handle, peer_addr, own_addr, role, conn_params)
            self.conn_handle    = params[0]
            self.peer_addr      = params[1]
            self.own_addr       = params[2]
        else:
            raise NordicSemiException('Timeout. Device not found.')

    def pair(self):
        with EventSync(self.adapter, [GapEvtSec]) as evt_sync:
            self.adapter.gap_authenticate(self.conn_handle, io_caps = GapIoCaps.KEYBOARD_DISPLAY)

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
            passkey = raw_input("pass key: ")
            self.adapter.ble_gap_auth_key_reply(self.conn_handle, event.key_type, map(ord, passkey))

            event = evt_sync.get(timeout=32)
            if not isinstance(event, GapEvtConnSecUpdate):
                raise NordicSemiException('Did not get GapEvtConnSecUpdate in time.')
            event = evt_sync.get(timeout=32)
            if not isinstance(event, GapEvtAuthStatus):
                raise NordicSemiException('Did not get GapEvtConnSecUpdate in time.')

            bond_store.store_bond(self.own_addr, self.peer_addr,
                    key_set.sec_keyset.keys_peer.p_enc_key.master_id.ediv,
                    util.uint8_array_to_list(key_set.sec_keyset.keys_peer.p_enc_key.master_id.rand, 8),
                    util.uint8_array_to_list(key_set.sec_keyset.keys_peer.p_enc_key.enc_info.ltk,
                            key_set.sec_keyset.keys_peer.p_enc_key.enc_info.ltk_len),
                    key_set.sec_keyset.keys_peer.p_enc_key.enc_info.lesc,
                    key_set.sec_keyset.keys_peer.p_enc_key.enc_info.auth)

            return key_set

    def encrypt(self, bond):
        with EventSync(self.adapter, [GapEvtSec, GapEvtDisconnected]) as evt_sync:
            self.adapter.ble_gap_encrypt(self.conn_handle, bond.ediv, bond.rand, bond.ltk, bond.lesc, bond.auth)
            event =  evt_sync.get(timeout=32)
            if   isinstance(event, GapEvtConnSecUpdate):
                if event.sec_mode == 1 and event.sec_level == 1:
                    logger.info("Enc failed, deleting bond")
                    bond_store.delete(str(bond.peer_addr))
            elif isinstance(event, GapEvtDisconnected):
                raise NordicSemiException('encryption failed.')

    def read_attr(self, attr_handle):
        with EventSync(self.adapter, [GattcEvtReadResponse]) as evt_sync:
            self.adapter.ble_gattc_read(self.conn_handle, attr_handle)
            return evt_sync.get()

    def dfu_goto_state(self):
        self.adapter.gattc_write_attr(self.conn_handle, self.dfu_cp + 1,     [1, 0])
        time.sleep(.1)
        self.adapter.gattc_write_attr(self.conn_handle, self.dfu_cp, [1])

    def version_get(self):
        self.adapter.gattc_write_attr(self.conn_handle, self.config_cp, [0x01, 0xFD])
        time.sleep(1)

    def enable_services(self):
        self.adapter.gattc_write_attr(self.conn_handle, self.sync_cp   + 1,   [1, 0])
        time.sleep(.1)
        self.adapter.gattc_write_attr(self.conn_handle, self.sync_data + 1,   [1, 0])
        time.sleep(.1)
        self.adapter.gattc_write_attr(self.conn_handle, self.config_cp + 1,   [1, 0])
        time.sleep(.1)

    def streaming_enable(self):
        self.adapter.gattc_write_attr(self.conn_handle, self.stream_cp + 1,   [1, 0])

    def config_wrist_action(self, on=True):
        self.adapter.gattc_write_attr(self.conn_handle, self.config_cp, [0x11, 0x00, 1 if on else 0])

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


class FjaseAdapter(RawBLEDriverObserver, BLEDriverObserver):

    def __init__(self, driver):
        super(FjaseAdapter, self).__init__()
        self.conn_handles       = []
        self.peer_addr          = None
        self.own_addr           = None
        self.driver             = driver
        self.notifications_q    = Queue.Queue()
        self.event_q            = Queue.Queue()
        self.driver.observer_register(self)
        self.driver.extended_observer_register(self)

        # Do poor mans inheritance
        self.ble_gap_scan_start         = self.driver.ble_gap_scan_start
        self.ble_gap_scan_stop          = self.driver.ble_gap_scan_stop
        self.ble_gap_connect            = self.driver.ble_gap_connect
        self.ble_gap_encrypt            = self.driver.ble_gap_encrypt
        self.ble_gap_sec_params_reply   = self.driver.ble_gap_sec_params_reply
        self.ble_gap_auth_key_reply     = self.driver.ble_gap_auth_key_reply
        self.ble_gattc_read             = self.driver.ble_gattc_read
        self.ble_gattc_write            = self.driver.ble_gattc_write


    def open(self):
        self.driver.open()
        self.driver.ble_enable()

    def gap_authenticate(self, conn_handle, bond=True, mitm=True, le_sec_pairing=False, keypress_noti=False, io_caps=None,
                         oob=False, min_key_size=16, max_key_size=16, kdist_own=None, kdist_peer=None):
        # TODO Create BLEGapSecKeyDist static values with defaults
        if not io_caps:
            io_caps = GapIoCaps.None
        if not kdist_own:
            kdist_own = BLEGapSecKeyDist()
        if not kdist_peer:
            kdist_peer = BLEGapSecKeyDist(enc_key=True)
        sec_params = BLEGapSecParams(bond           = bond,
                                     mitm           = mitm,
                                     le_sec_pairing = le_sec_pairing,
                                     keypress_noti  = keypress_noti,
                                     io_caps        = io_caps,
                                     oob            = oob,
                                     min_key_size   = min_key_size,
                                     max_key_size   = max_key_size,
                                     kdist_own      = kdist_own,
                                     kdist_peer     = kdist_peer)
        self.driver.ble_gap_authenticate(conn_handle, sec_params)

    def service_discovery(self):
        logger.debug('BLE: Service Discovery...')
        #self.adapter.service_discovery(conn_handle=self.conn_handle)
        logger.debug('BLE: Service Discovery done')


    def gattc_write_attr(self, conn_handle, attr_handle, value, offset=0):
        write_params = BLEGattcWriteParams(BLEGattWriteOperation.write_req,
                                           BLEGattExecWriteFlag.unused,
                                           attr_handle,
                                           value,
                                           offset)
        self.ble_gattc_write(conn_handle, write_params)

    def close(self):
        for conn_handle in self.conn_handles:
            logger.info('BLE: Disconnecting from target')
            self.driver.ble_gap_disconnect(conn_handle)
            evt, params = self.event_q.get(timeout=1)
        self.driver.close()

    def on_event(self, ble_driver, event):
        logger.info('high level event %r', event)

    def on_gap_evt_connected(self, ble_driver, conn_handle, peer_addr, own_addr, role, conn_params):
        logger.info('BLE: Connected to {}'.format(peer_addr))
        self.event_q.put(('BLE_GAP_EVT_CONNECTED', (conn_handle, peer_addr, own_addr, role, conn_params)))

    def on_gap_evt_disconnected(self, ble_driver, conn_handle, reason):
        self.event_q.put(('BLE_GAP_EVT_DISCONNECTED', (conn_handle, reason)))
        self.conn_handle = None
        logger.info('BLE: Disconnected')

    def on_gap_evt_adv_report(self, ble_driver, conn_handle, peer_addr, rssi, adv_type, adv_data):
        print "Hello", ble_driver, peer_addr.addr_type, peer_addr.addr, rssi, adv_type, adv_data

    def on_gattc_evt_hvx(self, ble_driver, conn_handle, status, error_handle, attr_handle, hvx_type, data):
        logger.info("Got notification status %s err_handle %s attr_handle %s hvx_type %s data: %r",
                status, error_handle, attr_handle, hvx_type, ''.join(map(chr, data)))

    def on_gattc_evt_write_rsp(self, ble_driver, conn_handle, status, error_handle, attr_handle, write_op, offset, data):
        logger.info("Got write response status %s err_handle %s attr_handle %s write_op %s offset %s data: %r",
                status, error_handle, attr_handle, write_op, offset, ''.join(map(chr, data)))

ADDR_SHIELD = "FB:5E:B7:BD:EC:39,r"
ADDR_BUILD  = 'DE:31:CD:FB:0B:57,r'
ADDR_BUILD2 = 'F5:1A:BE:53:2E:28,r'
ADDR_WATCH  = "FE:E4:5D:E9:02:19,r"
ADDR_DEV    = "D6:60:C4:A9:6B:5F,r"

def main(args):
    #ble_backend = Fjase(serial_port="COM17")
    ble_backend = Fjase(serial_port=args.device)
    ble_backend.open()
    #ble_backend.scan_start(timeout=.3)

    peer = BLEGapAddr.from_string(ADDR_BUILD)
    ble_backend.connect(peer)

    bond = bond_store.get_bond(peer)
    if bond:
        ble_backend.encrypt(bond)
    else:
        key_set = ble_backend.pair()
        ble_backend.enable_services()
    time.sleep(1)

    #ble_backend.adapter.service_discovery()
    #time.sleep(1)
    #ble_backend.time((datetime.now() - datetime.utcfromtimestamp(0)).total_seconds())
    #time.sleep(1)
    print ble_backend.read_attr(0x0003)
    time.sleep(1)
    #ble_backend.config_display_brightness(20)
    #ble_backend.version_get()

    #ble_backend.dfu_goto_state()
    ble_backend.close()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(prog='slice_test')
    parser.add_argument("-d", "--device", dest="device", help="Select master device")
    main(parser.parse_args())

