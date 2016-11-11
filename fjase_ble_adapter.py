import logging
import Queue

from pc_ble_driver_py.exceptions    import IllegalStateException
from pc_ble_driver_py.ble_driver    import BLEDriverObserver
from pc_ble_driver_py.ble_driver    import BLEGattcWriteParams, BLEGattWriteOperation, BLEGattExecWriteFlag

from nrf_event import *
from fjase_ble_driver import RawBLEDriverObserver

logger = logging.getLogger('fjase')


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

