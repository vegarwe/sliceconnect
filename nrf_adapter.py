import logging
import Queue

from nrf_event import *
from nrf_driver import NrfDriverObserver, NrfDriver

logger = logging.getLogger('fjase')


class NrfAdapter(NrfDriverObserver):

    def __init__(self, driver):
        super(NrfAdapter, self).__init__()
        self.conn_handles   = []
        self.driver         = driver
        self.driver.observer_register(self)

        # Do poor mans inheritance
        self.ble_gap_scan_start         = self.driver.ble_gap_scan_start
        self.ble_gap_scan_stop          = self.driver.ble_gap_scan_stop
        self.ble_gap_connect            = self.driver.ble_gap_connect
        self.ble_gap_encrypt            = self.driver.ble_gap_encrypt
        self.ble_gap_sec_params_reply   = self.driver.ble_gap_sec_params_reply
        self.ble_gap_auth_key_reply     = self.driver.ble_gap_auth_key_reply
        self.ble_gattc_read             = self.driver.ble_gattc_read
        self.ble_gattc_write            = self.driver.ble_gattc_write


    @classmethod
    def open_serial(cls, serial_port, baud_rate):
        adapter = cls(NrfDriver(serial_port=serial_port, baud_rate=baud_rate))
        adapter.open()
        return adapter

    def open(self):
        self.driver.open()
        self.driver.ble_enable()

    def close(self):
        with EventSync(self, [GapEvtDisconnected]) as evt_sync:
            for conn_handle in self.conn_handles[:]:
                logger.info('BLE: Disconnecting conn_handle %r', conn_handle)
                self.driver.ble_gap_disconnect(conn_handle)
                evt_sync.get(timeout=0.2) # TODO: If we know the conn_params we can be more informed about timeout
        self.driver.observer_unregister(self)
        self.driver.close()

    def on_event(self, ble_driver, event):
        if   isinstance(event, GapEvtConnected):
            self.conn_handles.append(event.conn_handle)
        elif isinstance(event, GapEvtDisconnected):
            try:
                self.conn_handles.remove(event.conn_handle)
            except ValueError:
                pass
        elif isinstance(event, GapEvtAdvReport):
            pass # TODO: Maintain list of seen devices
