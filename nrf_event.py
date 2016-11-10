import logging
import Queue

from pc_ble_driver_py.ble_driver import driver, util, BLEEvtID, BLEGattStatusCode, BLEDriverObserver

logger = logging.getLogger('fjase')

class EventSync(BLEDriverObserver):
    def __init__(self, driver, event_filter=None):
        super(BLEDriverObserver, self).__init__()
        self._driver        = driver
        if isinstance(event_filter, (list, tuple)):
            self._events = event_filter
        elif classes == None:
            self._events = None
        else:
            self._events = [event_filter]
        self._queue         = Queue.Queue()

    def _isinstance_of_event(self, ble_event):
        if self._events == None:
            return True
        for _class in self._events:
            if isinstance(ble_event, _class):
                return True
        return False

    def on_event(self, ble_driver, ble_event):
        if not self._isinstance_of_event(ble_event):
            return
        self._queue.put(ble_event)

    def get(self, block=True, timeout=None):
        return self._queue.get(block, timeout)

    def register_as_observer(self):
        self._driver.extended_observer_register(self)

    def unregister_as_observer(self):
        self._driver.extended_observer_unregister(self)

    def __enter__(self):
        self.register_as_observer()
        return self

    def __exit__(self, type, value, traceback):
        self.unregister_as_observer()

class BLEEvent(object):
    evt_id = None

    def __init__(self, conn_handle):
        self.conn_handle  = conn_handle

class GapEvt(BLEEvent):
    pass

class GapEvtDisconnected(GapEvt):
    evt_id = driver.BLE_GAP_EVT_DISCONNECTED

class GapSecEvt(GapEvt):
    pass

class GapSecEvtConnSecUpdate(GapSecEvt):
    evt_id = driver.BLE_GAP_EVT_CONN_SEC_UPDATE

    def __init__(self, conn_handle, sec_mode, sec_level, encr_key_size):
        self.conn_handle      = conn_handle
        self.sec_mode         = sec_mode
        self.sec_level        = sec_level
        self.encr_key_size    = encr_key_size

    @classmethod
    def from_c(cls, ble_event):
        conn_sec = ble_event.evt.gap_evt.params.conn_sec_update.conn_sec
        return cls(conn_handle      = ble_event.evt.gap_evt.conn_handle,
                   sec_mode         = conn_sec.sec_mode.sm,
                   sec_level        = conn_sec.sec_mode.lv,
                   encr_key_size    = conn_sec.encr_key_size)

    def __repr__(self):
        return "%s(conn_handle=%r, sec_mode=%r, sec_level=%r, encr_key_size=%r)" % (
                self.__class__.__name__, self.conn_handle, self.sec_mode, self.sec_level, self.encr_key_size)

class GattcEvt(BLEEvent):
    pass

class GattcEvtReadResponse(GattcEvt):
    evt_id = driver.BLE_GATTC_EVT_READ_RSP

    def __init__(self, conn_handle, status, error_handle, attr_handle, offset, data):
        super(GattcEvtReadResponse, self).__init__(conn_handle)
        self.status         = status
        self.error_handle   = error_handle
        self.attr_handle    = attr_handle
        self.offset         = offset
        if isinstance(data, str):
            self.data       = map(ord, data)
        else:
            self.data       = data

    @classmethod
    def from_c(cls, ble_event):
        read_rsp = ble_event.evt.gattc_evt.params.read_rsp
        return cls(conn_handle     = ble_event.evt.gattc_evt.conn_handle,
                   status          = BLEGattStatusCode(ble_event.evt.gattc_evt.gatt_status),
                   error_handle    = ble_event.evt.gattc_evt.error_handle,
                   attr_handle     = read_rsp.handle,
                   offset          = read_rsp.offset,
                   data            = util.uint8_array_to_list(read_rsp.data, read_rsp.len))

    def __repr__(self):
        data = ''.join(map(chr, self.data))
        return "%s(conn_handle=%r, status=%r, error_handle=%r, attr_handle=%r, offset=%r, data=%r)" % (
                self.__class__.__name__, self.conn_handle, self.status,
                self.error_handle, self.attr_handle, self.offset, data)


def decode(ble_event):
    if ble_event.header.evt_id == GattcEvtReadResponse.evt_id:
        return GattcEvtReadResponse.from_c(ble_event)
    elif ble_event.header.evt_id == driver.BLE_GAP_EVT_SEC_PARAMS_REQUEST:
        sec_params = ble_event.evt.gap_evt.params.sec_params_request.peer_params
        #for obs in self.extended_observers:
        #    obs.on_gap_evt_sec_params_request(ble_driver    = self,
        #                                      conn_handle   = ble_event.evt.gap_evt.conn_handle,
        #                                      sec_params    = BLEGapSecParams.from_c(sec_params))
    #elif ble_event.header.evt_id == driver.BLE_GAP_EVT_SEC_INFO_REQUEST:
    #    logger.info('BLE_GAP_EVT_SEC_INFO_REQUEST')
    #    return True
    #elif ble_event.header.evt_id == driver.BLE_GAP_EVT_SEC_REQUEST:
    #    logger.info('BLE_GAP_EVT_SEC_REQUEST')
    #    return True
    elif ble_event.header.evt_id == driver.BLE_GAP_EVT_AUTH_KEY_REQUEST:
        auth_key_request = ble_event.evt.gap_evt.params.auth_key_request
        #for obs in self.extended_observers:
        #    obs.on_gap_evt_auth_key_request(ble_driver  = self,
        #                                    conn_handle = ble_event.evt.gap_evt.conn_handle,
        #                                    key_type    = auth_key_request.key_type)
    elif ble_event.header.evt_id == GapSecEvtConnSecUpdate.evt_id:
        return GapSecEvtConnSecUpdate.from_c(ble_event)
    elif ble_event.header.evt_id == driver.BLE_GAP_EVT_AUTH_STATUS:
        auth_status = ble_event.evt.gap_evt.params.auth_status
        #for obs in self.extended_observers:
        #    obs.on_gap_evt_auth_status(ble_driver           = self,
        #                               conn_handle          = ble_event.evt.gap_evt.conn_handle,
        #                               auth_status          = auth_status.auth_status,
        #                               error_src            = auth_status.error_src,
        #                               bonded               = auth_status.bonded,
        #                               sm1_levels           = BLEGapSecLevels.from_c(auth_status.sm1_levels),
        #                               sm2_levels           = BLEGapSecLevels.from_c(auth_status.sm2_levels),
        #                               kdist_own            = BLEGapSecKeyDist.from_c(auth_status.kdist_own),
        #                               kdist_peer           = BLEGapSecKeyDist.from_c(auth_status.kdist_peer)
        #                               )
