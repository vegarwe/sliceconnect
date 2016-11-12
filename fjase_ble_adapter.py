import logging
import Queue

from nrf_event import *
from fjase_ble_driver import RawBLEDriverObserver, FjaseBLEDriver

logger = logging.getLogger('fjase')


class FjaseAdapter(RawBLEDriverObserver):

    def __init__(self, driver):
        super(FjaseAdapter, self).__init__()
        self.conn_handles   = []
        self.driver         = driver
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

    @classmethod
    def open_serial(cls, serial_port, baud_rate):
        adapter = cls(FjaseBLEDriver(serial_port=serial_port, baud_rate=baud_rate))
        adapter.open()
        return adapter

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

    def close(self):
        with EventSync(self, [GapEvtDisconnected]) as evt_sync:
            for conn_handle in self.conn_handles[:]:
                logger.info('BLE: Disconnecting conn_handle %r', conn_handle)
                self.driver.ble_gap_disconnect(conn_handle)
                evt_sync.get(timeout=0.2) # TODO: If we know the conn_params we can be more informed about timeout
        self.driver.close()

    def on_event(self, ble_driver, event):
        logger.info('high level event %r', event)
        if   isinstance(event, GapEvtConnected):
            self.conn_handles.append(event.conn_handle)
        elif isinstance(event, GapEvtDisconnected):
            try:
                self.conn_handles.remove(event.conn_handle)
            except ValueError:
                pass
