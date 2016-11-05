import logging
import wrapt

from pc_ble_driver_py.ble_driver import driver, util, BLEEvtID, BLEGattStatusCode, NordicSemiErrorCheck, BLEDriver, BLEDriverObserver

logger = logging.getLogger('fjase')

class FjaseBLEDriverObserver(object):
    def on_gattc_evt_read_rsp(self, ble_driver, conn_handle, status, error_handle, attr_handle, offset, data):
        pass

class FjaseBLEDriver(BLEDriver):
    def __init__(self, **kwargs):
        BLEDriver.__init__(self, **kwargs)

        self.extended_observers = list()

    @wrapt.synchronized(BLEDriver.observer_lock)
    def extended_observer_register(self, observer):
        self.extended_observers.append(observer)


    @wrapt.synchronized(BLEDriver.observer_lock)
    def extended_observer_unregister(self, observer):
        self.extended_observers.remove(observer)

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def read(self, conn_handle, read_handle, offset=0):
        #assert isinstance(write_params, BLEGattcWriteParams), 'Invalid argument type'
        return driver.sd_ble_gattc_read(self.rpc_adapter, conn_handle, read_handle, offset)

    #def read(self):
    #    driver.sd_ble_gattc_read(self.rpc_adapter, self.conn_handle, 0x0003, 0)

    def log_message_handler(self, adapter, severity, log_message):
        pass#logger.info("log_message %s, %s", severity, log_message)

    def ble_evt_handler(self, adapter, ble_event):
        if not self._sync_extended_evt_handler(adapter, ble_event):
            #super(BLEDriver, self).sync_ble_evt_handler(adapter, ble_event)
            BLEDriver.sync_ble_evt_handler(self, adapter, ble_event)

    @wrapt.synchronized(BLEDriver.observer_lock)
    def _sync_extended_evt_handler(self, adapter, ble_event):
        try:
            if ble_event.header.evt_id == driver.BLE_GATTC_EVT_READ_RSP:
                read_rsp = ble_event.evt.gattc_evt.params.read_rsp
                data = util.uint8_array_to_list(read_rsp.data, read_rsp.len)
                for obs in self.extended_observers:
                    obs.on_gattc_evt_read_rsp(ble_driver   = self,
                                              conn_handle  = ble_event.evt.gattc_evt.conn_handle,
                                              status       = BLEGattStatusCode(ble_event.evt.gattc_evt.gatt_status),
                                              error_handle = ble_event.evt.gattc_evt.error_handle,
                                              attr_handle  = read_rsp.handle,
                                              offset       = read_rsp.offset,
                                              data         = util.uint8_array_to_list(read_rsp.data, read_rsp.len))
                return True
        except Exception as e:
            logger.error("Exception: {}".format(str(e)))
            for line in traceback.extract_tb(sys.exc_info()[2]):
                logger.error(line)
            logger.error("")

        return False

