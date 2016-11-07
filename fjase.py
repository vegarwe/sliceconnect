import abc
import logging
import Queue
import time
#import struct
#import binascii

from pc_ble_driver_py.exceptions    import NordicSemiException, IllegalStateException
from pc_ble_driver_py.ble_driver    import util, BLEDriverObserver, BLEUUIDBase, BLEUUID, BLEGapAddr, BLEGapConnParams, NordicSemiException
from pc_ble_driver_py.ble_adapter   import BLEAdapter, BLEAdapterObserver, EvtSync

from fjase_ble_driver import FjaseBLEDriver, FjaseBLEDriverObserver, BLEGapSecParams, BLEGapSecKeyset, BLEGapSecKeyDist


def logger_setup():
    logger = logging.getLogger('fjase')
    logger.setLevel(logging.DEBUG)

    sh = logging.StreamHandler()
    sh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    logging.getLogger().addHandler(sh)
    return logger

logger = logger_setup()

import json
import os
class Bond(object):
    def __init__(self, peer_addr, own_addr, ediv, rand, ltk):
        self.peer_addr  = peer_addr
        self.own_addr   = own_addr
        self.ediv       = ediv
        self.rand       = rand
        self.ltk        = ltk

    @classmethod
    def from_json(cls, bonds):
        parsed = []
        for addr_str, bond_dict in bonds.iteritems():
            addr = BLEGapAddr.from_string(str(addr_str)) # TODO(vw): str(...) needed to handle unicode, but why???
            parsed.append(cls(addr, bond_dict['Own'], bond_dict['Ediv'], bond_dict['Rand'], bond_dict['Ltk']))
        return parsed


class BondStorage(object):
    DATA_STORE = os.path.join(os.path.expanduser('~'), 'bonds.json')

    @classmethod
    def _read_data_store(cls):
        try:
            with open(cls.DATA_STORE) as data_file:
                return json.load(data_file)
        except ValueError:
            return {}
        except IOError:
            return {}

    @classmethod
    def store_bond(cls, own_addr, peer_addr, ediv, rand, ltk, lesc, auth):
        #print 'own  %s' % own_addr
        #print 'peer %s' % peer_addr
        #print 'ediv %r' % ediv
        #print 'rand %r' % rand
        #print 'ltk  %r' % ltk
        #print 'lesc %r' % lesc
        #print 'auth %r' % auth

        peer_addr_str   = str(peer_addr)
        own_addr_str    = str(own_addr)

        data_store = cls._read_data_store()
        if data_store.has_key(peer_addr_str):
            data_store[peer_addr_str]['Ediv'] = ediv
            data_store[peer_addr_str]['Rand'] = rand
            data_store[peer_addr_str]['Ltk' ] = ltk
            data_store[peer_addr_str]['Own' ] = own_addr_str
        else:
            data_store[peer_addr_str] = {'Ediv': ediv,
                                         'Rand': rand,
                                         'Ltk' : ltk,
                                         'Own' : own_addr_str}

        with open(cls.DATA_STORE, 'w') as store:
            json.dump(data_store, store)

    def delete(self, addr_str):
        data_store = self._read_data_store()
        data_store.pop(addr_str, None)
        with open(self.DATA_STORE, 'w') as store:
            json.dump(data_store, store)

    def get_bonds(self):
        bonds = Bond.from_json(self._read_data_store())
        return {str(bond.peer_addr): bond for bond in bonds}

    def get_bond(self, addr):
        addr_str = addr
        for bond in Bond.from_json(self._read_data_store()):
            if bond.peer_addr == addr:
                return bond
        return None

class Fjase(object):
    def __init__(self, serial_port, baud_rate=115200):
        self.baud_rate          = baud_rate
        self.serial_port        = serial_port
        self.fjase_adapter      = None

    def open(self):
        logger.debug("Connecting to adapter")
        if self.fjase_adapter:
            raise IllegalStateException('DFU Adapter is already open')

        driver           = FjaseBLEDriver(serial_port    = self.serial_port,
                                     baud_rate      = self.baud_rate)
        adapter          = BLEAdapter(driver)
        self.fjase_adapter = FjaseAdapter(adapter       = adapter)
        self.fjase_adapter.open()

    def close(self):
        logger.debug("Disconnecting adapter")
        if not self.fjase_adapter:
            raise IllegalStateException('DFU Adapter is already closed')
        self.fjase_adapter.close()
        self.fjase_adapter = None

class FjaseAdapter(FjaseBLEDriverObserver, BLEDriverObserver, BLEAdapterObserver):

    def __init__(self, adapter):
        super(FjaseAdapter, self).__init__()
        self.evt_sync           = EvtSync(['connected', 'disconnected'])
        self.conn_handle        = None
        self.peer_addr          = None
        self.own_addr           = None
        self.adapter            = adapter
        self.notifications_q    = Queue.Queue()
        self.event_q            = Queue.Queue()
        self.adapter.observer_register(self)
        self.adapter.driver.observer_register(self)
        self.adapter.driver.extended_observer_register(self)


    def open(self):
        self.adapter.driver.open()
        self.adapter.driver.ble_enable()

    def connect(self, target_device_addr):
        logger.info('BLE: Connecting...')
        conn_params = BLEGapConnParams(min_conn_interval_ms = 15,
                                       max_conn_interval_ms = 30,
                                       conn_sup_timeout_ms  = 4000,
                                       slave_latency        = 0)
        self.adapter.connect(address = target_device_addr, conn_params = conn_params)
        self.conn_handle = self.evt_sync.wait('connected')
        if self.conn_handle is None:
            raise NordicSemiException('Timeout. Device not found.')
        evt, params = self.event_q.get(timeout=.1)
        if evt == 'BLE_GAP_EVT_CONNECTED':
            # params contains (conn_handle, peer_addr, own_addr, role, conn_params)
            self.peer_addr = params[1]
            self.own_addr = params[2]

    def service_discovery(self):
        logger.debug('BLE: Service Discovery...')
        self.adapter.service_discovery(conn_handle=self.conn_handle)
        logger.debug('BLE: Service Discovery done')


    def read_attr(self, attr_handle):
        logger.debug('BLE: Read...')
        self.adapter.driver.read(self.conn_handle, 0x0003)
        #self.adapter.driver.write_req(
        time.sleep(1)
        logger.debug('BLE: Read done')

    def pair(self):
        sec_params = BLEGapSecParams(bond           = True,
                                 mitm           = True,
                                 le_sec_pairing = False,
                                 keypress_noti  = False,
                                 io_caps        = 4, # KeyboardDisplay
                                 oob            = False,
                                 min_key_size   = 16,
                                 max_key_size   = 16,
                                 kdist_own      = BLEGapSecKeyDist(),
                                 kdist_peer     = BLEGapSecKeyDist(enc_key=True))
                                 #kdist_peer     = BLEGapSecKeyDist())
        self.adapter.driver.ble_gap_authenticate(self.conn_handle, sec_params)
        sec_event = self.event_q.get(timeout=32)

        key_set = BLEGapSecKeyset()
        self.adapter.driver.ble_gap_sec_params_reply(self.conn_handle, 0, None, key_set)

        evt, key_type = self.event_q.get(timeout=32)
        if key_type == 0x01:
            passkey = raw_input("pass key: ")
            self.adapter.driver.ble_gap_auth_key_reply(self.conn_handle, key_type, map(ord, passkey))
        else:
            raise Exception("Unsupported auth key event")

        evt, params = self.event_q.get(timeout=32)
        evt, params = self.event_q.get(timeout=32)
        if evt == 'BLE_GAP_EVT_AUTH_STATUS':
            BondStorage.store_bond(self.own_addr, self.peer_addr,
                    key_set.sec_keyset.keys_peer.p_enc_key.master_id.ediv,
                    util.uint8_array_to_list(key_set.sec_keyset.keys_peer.p_enc_key.master_id.rand, 8),
                    util.uint8_array_to_list(key_set.sec_keyset.keys_peer.p_enc_key.enc_info.ltk,
                            key_set.sec_keyset.keys_peer.p_enc_key.enc_info.ltk_len),
                    key_set.sec_keyset.keys_peer.p_enc_key.enc_info.lesc,
                    key_set.sec_keyset.keys_peer.p_enc_key.enc_info.auth)

        return key_set

    def encrypt(self, ediv, rand, ltk):
        self.adapter.driver.ble_gap_encrypt(self.conn_handle, ediv, rand, ltk)

    def enable_notifications(self):
        logger.debug('BLE: Enabling Notifications')
        #self.adapter.enable_notification(conn_handle=self.conn_handle, uuid=DFUAdapter.CP_UUID)
        #return self.target_device_name, self.target_device_addr

    def scan_start(self, timeout=1):
        logger.info('BLE: Scanning...')
        self.adapter.driver.ble_gap_scan_start()
        time.sleep(timeout)
        self.adapter.driver.ble_gap_scan_stop()

    def close(self):
        if self.conn_handle is not None:
            logger.info('BLE: Disconnecting from target')
            self.adapter.disconnect(self.conn_handle)
            self.evt_sync.wait('disconnected')
        self.adapter.driver.close()


    def on_gap_evt_connected(self, ble_driver, conn_handle, peer_addr, own_addr, role, conn_params):
        logger.info('BLE: Connected to {}'.format(peer_addr))
        self.evt_sync.notify(evt = 'connected', data = conn_handle)
        self.event_q.put(('BLE_GAP_EVT_CONNECTED', (conn_handle, peer_addr, own_addr, role, conn_params)))

    def on_gap_evt_disconnected(self, ble_driver, conn_handle, reason):
        self.evt_sync.notify(evt = 'disconnected', data = conn_handle)
        self.conn_handle = None
        logger.info('BLE: Disconnected')

    def on_gap_evt_adv_report(self, ble_driver, conn_handle, peer_addr, rssi, adv_type, adv_data):
        print "Hello", ble_driver, peer_addr.addr_type, peer_addr.addr, rssi, adv_type, adv_data

    def on_gap_evt_sec_params_request(self, ble_driver, conn_handle, sec_params):
        logger.info('BLE_GAP_EVT_SEC_PARAMS_REQUEST %r', sec_params)
        self.event_q.put(('BLE_GAP_EVT_SEC_PARAMS_REQUEST', sec_params))

    def on_gap_evt_auth_key_request(self, ble_driver, conn_handle, key_type):
        logger.info('BLE_GAP_EVT_AUTH_KEY_REQUEST %r', key_type)
        self.event_q.put(('BLE_GAP_EVT_AUTH_KEY_REQUEST', key_type))

    def on_gap_evt_conn_sec_update(self, ble_driver, conn_handle, sec_mode, sec_level, encr_key_size):
        logger.info('BLE_GAP_EVT_CONN_SEC_UPDATE')
        self.event_q.put(('BLE_GAP_EVT_CONN_SEC_UPDATE', (conn_handle, sec_mode, sec_level, encr_key_size)))

    def on_gap_evt_auth_status(self, ble_driver, conn_handle, auth_status, error_src, bonded, sm1_levels, sm2_levels, kdist_own, kdist_peer):
        logger.info('BLE_GAP_EVT_AUTH_STATUS auth_status %r, error_src %r, bonded %r, sm1_levels %r, sm2_levels %r, kdist_own %r, kdist_peer %r',
                auth_status, error_src, bonded, sm1_levels, sm2_levels, kdist_own, kdist_peer)
        self.event_q.put(('BLE_GAP_EVT_AUTH_STATUS', (conn_handle, auth_status, error_src, bonded, sm1_levels, sm2_levels, kdist_own, kdist_peer)))



    def on_notification(self, ble_adapter, conn_handle, uuid, data):
        if self.conn_handle         != conn_handle: return
        print uuid, data
        #if DFUAdapter.CP_UUID.value != uuid.value:  return
        logger.debug(data)
        self.notifications_q.put(data)



    def on_gattc_evt_read_rsp(self, ble_driver, conn_handle, status, error_handle, attr_handle, offset, data):
        logger.info("Got read response conn_handle %s status %s err_handle %s attr_handle %s offset %s data: %r",
                conn_handle, status, error_handle, attr_handle, offset, ''.join(map(chr, data)))

def main():
    ble_backend = Fjase(serial_port="COM17")
    ble_backend.open()

    #ble_backend.fjase_adapter.scan_start(timeout=.3)

    peer = BLEGapAddr.from_string("D6:60:C4:A9:6B:5F,r")
    #peer = BLEGapAddr.from_string("FE:E4:5D:E9:02:19,r")
    #peer = BLEGapAddr(BLEGapAddr.Types.random_static, [0xEA, 0x81, 0xE3, 0xD0, 0x09, 0xC2])
    #peer = BLEGapAddr(BLEGapAddr.Types.random_static, [0xFB, 0x5E, 0xB7, 0xBD, 0xEC, 0x39])
    ble_backend.fjase_adapter.connect(peer)

    bond = BondStorage().get_bond(peer)
    if bond:
        ble_backend.fjase_adapter.encrypt(bond.ediv, bond.rand, bond.ltk)
    else:
        key_set = ble_backend.fjase_adapter.pair()

    ble_backend.fjase_adapter.service_discovery()
    time.sleep(1)
    ble_backend.fjase_adapter.read_attr(0x0003)
    ble_backend.close()

if __name__ == '__main__':
	main()
