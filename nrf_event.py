import logging
import Queue
import time
from enum import IntEnum

from pc_ble_driver_py.ble_driver import driver, util, BLEDriverObserver
from pc_ble_driver_py.ble_driver import BLEHci, BLEEvtID, BLEAdvData
from pc_ble_driver_py.ble_driver import BLEGapAddr, BLEGapRoles, BLEGapAdvType, BLEGapConnParams
from pc_ble_driver_py.ble_driver import BLEGattStatusCode, BLEGattWriteOperation, BLEGattHVXType

logger = logging.getLogger('fjase')


class EventSync(BLEDriverObserver):
    def __init__(self, adapter, event_filter=None, callback=None):
        super(BLEDriverObserver, self).__init__()
        self._driver        = adapter.driver
        if isinstance(event_filter, (list, tuple)):
            self._events    = event_filter
        elif event_filter is not None:
            self._events    = [event_filter]
        else:
            self._events    = None
        self._callback      = callback
        self._queue         = Queue.Queue() # TODO: Should not be unbound

    def _isinstance_of_event(self, event):
        if self._events == None:
            return True
        for _class in self._events:
            if isinstance(event, _class):
                return True
        return False

    def on_event(self, ble_driver, event):
        if self._callback and self._callback(event):
            return # Event handled by callback
        if not self._isinstance_of_event(event):
            return
        self._queue.put(event)

    def get(self, block=True, timeout=1):
        return self._queue.get(block, timeout)

    # TODO: Needs more testing!!!!
    def get_specific(self, event_type=None, block=True, timeout=None):
        start_time = time.time()
        while True:
            try:
                event = self._queue.get(block, min(timeout, .1))
                if not event_type:
                    return event
                if event_type and isinstance(event, event_type):
                    return event
                if time.time() - start_time > timeout:
                    return event
            except Queue.Empty:
                if not block:
                    return None
                if time.time() - start_time > timeout:
                    return None

    def register_as_observer(self):
        self._driver.observer_register(self)

    def unregister_as_observer(self):
        self._driver.observer_unregister(self)

    def __enter__(self):
        self.register_as_observer()
        return self

    def __exit__(self, type, value, traceback):
        self.unregister_as_observer()

class BLEEvent(object):
    evt_id = None

    def __init__(self, conn_handle):
        self.conn_handle = conn_handle # TODO: Does all events have conn_handle? Nooooo?...

class EvtTxComplete(BLEEvent):
    evt_id = driver.BLE_EVT_TX_COMPLETE

    def __init__(self, conn_handle, count):
        super(EvtTxComplete, self).__init__(conn_handle)
        self.count = count

    @classmethod
    def from_c(cls, event):
        tx_complete_evt = event.evt.common_evt.params.tx_complete
        return cls(conn_handle  = event.evt.common_evt.conn_handle,
                   count        = tx_complete_evt.count)

    def __repr__(self):
        return "%s(conn_handle=%r, count=%r)" % (self.conn_handle, self.count)

class GapEvt(BLEEvent):
    pass

class GapEvtAdvReport(GapEvt):
    evt_id = driver.BLE_GAP_EVT_ADV_REPORT

    def __init__(self, conn_handle, peer_addr, rssi, adv_type, adv_data):
        # TODO: What? Adv event has conn_handle? Does not compute
        super(GapEvtAdvReport, self).__init__(conn_handle)
        self.peer_addr      = peer_addr
        self.rssi           = rssi
        self.adv_type       = adv_type
        self.adv_data       = adv_data

    @classmethod
    def from_c(cls, event):
        adv_report_evt = event.evt.gap_evt.params.adv_report

        # TODO: adv_type what? We don't have a type for scan response?
        adv_type = None
        if not adv_report_evt.scan_rsp:
            adv_type = BLEGapAdvType(adv_report_evt.type)

        return cls(conn_handle  = event.evt.gap_evt.conn_handle,
                   peer_addr    = BLEGapAddr.from_c(adv_report_evt.peer_addr),
                   rssi         = adv_report_evt.rssi,
                   adv_type     = adv_type,
                   adv_data     = BLEAdvData.from_c(adv_report_evt))

    def __str__(self):
        return "%s(conn_handle=%r, peer_addr=%r, rssi=%r, adv_type=%r, adv_data=%r)" % (
                self.__class__.__name__, self.conn_handle,
                self.peer_addr, self.rssi, self.adv_type, self.adv_data)

class GapEvtTimeout(GapEvt):
    evt_id = driver.BLE_GAP_EVT_TIMEOUT

    def __init__(self, conn_handle, peer_addr, src):
        super(GapEvt, self).__init__(conn_handle)
        self.src = src

    @classmethod
    def from_c(cls, event):
        return cls(conn_handle  = event.evt.gap_evt.conn_handle,
                   src          = BLEGapTimeoutSrc(timeout_evt.src))

    def __repr__(self):
        return "%s(conn_handle=%r, src=%r)" % (self.conn_handle, self.src)

class GapEvtConnected(GapEvt):
    evt_id = driver.BLE_GAP_EVT_CONNECTED
    def __init__(self, conn_handle, peer_addr, own_addr, role, conn_params):
        super(GapEvtConnected, self).__init__(conn_handle)
        self.peer_addr      = peer_addr
        self.own_addr       = own_addr
        self.role           = role
        self.conn_params    = conn_params

    @classmethod
    def from_c(cls, event):
        connected_evt = event.evt.gap_evt.params.connected
        return cls(conn_handle    = event.evt.gap_evt.conn_handle,
                   peer_addr      = BLEGapAddr.from_c(connected_evt.peer_addr),
                   own_addr       = BLEGapAddr.from_c(connected_evt.own_addr),
                   role           = BLEGapRoles(connected_evt.role),
                   conn_params    = BLEGapConnParams.from_c(connected_evt.conn_params))

    def __repr__(self):
        return "%s(conn_handle=%r, peer_addr=%r, own_addr=%r, role=%r, conn_params=%r)" % (
                self.__class__.__name__, self.conn_handle,
                self.peer_addr, self.own_addr, self.role, self.conn_params)


class GapEvtDisconnected(GapEvt):
    evt_id = driver.BLE_GAP_EVT_DISCONNECTED

    def __init__(self, conn_handle, reason):
        super(GapEvtDisconnected, self).__init__(conn_handle)
        self.reason = reason

    @classmethod
    def from_c(cls, event):
        disconnected_evt = event.evt.gap_evt.params.disconnected
        return cls(conn_handle  = event.evt.gap_evt.conn_handle,
                   reason       = BLEHci(disconnected_evt.reason))

    def __repr__(self):
        return "%s(conn_handle=%r, reason=%r)" % (
                self.__class__.__name__, self.conn_handle, self.reason)


class GapEvtSec(GapEvt):
    pass

class GapEvtConnSecUpdate(GapEvtSec):
    evt_id = driver.BLE_GAP_EVT_CONN_SEC_UPDATE

    def __init__(self, conn_handle, sec_mode, sec_level, encr_key_size):
        super(GapEvtConnSecUpdate, self).__init__(conn_handle)
        self.sec_mode         = sec_mode
        self.sec_level        = sec_level
        self.encr_key_size    = encr_key_size

    @classmethod
    def from_c(cls, event):
        conn_sec = event.evt.gap_evt.params.conn_sec_update.conn_sec
        return cls(conn_handle      = event.evt.gap_evt.conn_handle,
                   sec_mode         = conn_sec.sec_mode.sm,
                   sec_level        = conn_sec.sec_mode.lv,
                   encr_key_size    = conn_sec.encr_key_size)

    def __repr__(self):
        return "%s(conn_handle=%r, sec_mode=%r, sec_level=%r, encr_key_size=%r)" % (
                self.__class__.__name__, self.conn_handle, self.sec_mode, self.sec_level, self.encr_key_size)

class GapEvtSecParamsRequest(GapEvtSec):
    evt_id = driver.BLE_GAP_EVT_SEC_PARAMS_REQUEST

    def __init__(self, conn_handle, sec_params):
        super(GapEvtSecParamsRequest, self).__init__(conn_handle)
        self.sec_params = sec_params

    @classmethod
    def from_c(cls, event):
        sec_params = event.evt.gap_evt.params.sec_params_request.peer_params
        return cls(conn_handle  = event.evt.gap_evt.conn_handle,
                   sec_params   = BLEGapSecParams.from_c(sec_params))

    def __repr__(self):
        return "%s(conn_handle=%r, sec_params=%r)" % ( self.__class__.__name__, self.conn_handle, self.sec_params)

class GapIoCaps(IntEnum):
    DISPLAY_ONLY        = driver.BLE_GAP_IO_CAPS_DISPLAY_ONLY
    DISPLAY_YESNO       = driver.BLE_GAP_IO_CAPS_DISPLAY_YESNO
    KEYBOARD_ONLY       = driver.BLE_GAP_IO_CAPS_KEYBOARD_ONLY
    NONE                = driver.BLE_GAP_IO_CAPS_NONE
    KEYBOARD_DISPLAY    = driver.BLE_GAP_IO_CAPS_KEYBOARD_DISPLAY

class GapAuthKeyType(IntEnum):
    NONE    = driver.BLE_GAP_AUTH_KEY_TYPE_NONE
    PASSKEY = driver.BLE_GAP_AUTH_KEY_TYPE_PASSKEY
    OOB     = driver.BLE_GAP_AUTH_KEY_TYPE_OOB

class GapEvtAuthKeyRequest(GapEvtSec):
    evt_id = driver.BLE_GAP_EVT_AUTH_KEY_REQUEST

    def __init__(self, conn_handle, key_type):
        super(GapEvtAuthKeyRequest, self).__init__(conn_handle)
        self.key_type = key_type

    @classmethod
    def from_c(cls, event):
        auth_key_request = event.evt.gap_evt.params.auth_key_request
        return cls(conn_handle = event.evt.gap_evt.conn_handle,
                   key_type    = GapAuthKeyType(auth_key_request.key_type))

    def __repr__(self):
        return "%s(conn_handle=%r, key_type=%r)" % ( self.__class__.__name__, self.conn_handle, self.key_type)

class GapEvtAuthStatus(GapEvtSec):
    evt_id = driver.BLE_GAP_EVT_AUTH_STATUS

    def __init__(self, conn_handle, auth_status, error_src, bonded, sm1_levels, sm2_levels, kdist_own, kdist_peer):
        super(GapEvtAuthStatus, self).__init__(conn_handle)
        self.auth_status    = auth_status
        self.error_src      = error_src
        self.bonded         = bonded
        self.sm1_levels     = sm1_levels
        self.sm2_levels     = sm2_levels
        self.kdist_own      = kdist_own
        self.kdist_peer     = kdist_peer

    @classmethod
    def from_c(cls, event):
        auth_status = event.evt.gap_evt.params.auth_status
        return cls(conn_handle  = event.evt.gap_evt.conn_handle,
                   auth_status  = auth_status.auth_status,
                   error_src    = auth_status.error_src,
                   bonded       = auth_status.bonded,
                   sm1_levels   = BLEGapSecLevels.from_c(auth_status.sm1_levels),
                   sm2_levels   = BLEGapSecLevels.from_c(auth_status.sm2_levels),
                   kdist_own    = BLEGapSecKeyDist.from_c(auth_status.kdist_own),
                   kdist_peer   = BLEGapSecKeyDist.from_c(auth_status.kdist_peer))

    def __str__(self):
        return "%s(conn_handle=%r, auth_status=%r, error_src=%r, bonded=%r, sm1_levels=%r, sm2_levels=%r, kdist_own=%r, kdist_peer=%r)" % (
                self.__class__.__name__, self.conn_handle, self.auth_status, self.error_src, self.bonded,
                self.sm1_levels, self.sm2_levels, self.kdist_own, self.kdist_peer)

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
    def from_c(cls, event):
        read_rsp = event.evt.gattc_evt.params.read_rsp
        return cls(conn_handle  = event.evt.gattc_evt.conn_handle,
                   status       = BLEGattStatusCode(event.evt.gattc_evt.gatt_status),
                   error_handle = event.evt.gattc_evt.error_handle,
                   attr_handle  = read_rsp.handle,
                   offset       = read_rsp.offset,
                   data         = util.uint8_array_to_list(read_rsp.data, read_rsp.len))

    def __repr__(self):
        data = ''.join(map(chr, self.data))
        return "%s(conn_handle=%r, status=%r, error_handle=%r, attr_handle=%r, offset=%r, data=%r)" % (
                self.__class__.__name__, self.conn_handle,
                self.status, self.error_handle, self.attr_handle, self.offset, data)

class GattcEvtHvx(GattcEvt):
    evt_id = driver.BLE_GATTC_EVT_HVX

    def __init__(self, conn_handle, status, error_handle, attr_handle, hvx_type, data):
        super(GattcEvtHvx, self).__init__(conn_handle)
        self.status         = status
        self.error_handle   = error_handle
        self.attr_handle    = attr_handle
        self.hvx_type       = hvx_type
        if isinstance(data, str):
            self.data       = map(ord, data)
        else:
            self.data       = data

    @classmethod
    def from_c(cls, event):
        hvx_evt = event.evt.gattc_evt.params.hvx
        return cls(conn_handle  = event.evt.gattc_evt.conn_handle,
                   status       = BLEGattStatusCode(event.evt.gattc_evt.gatt_status),
                   error_handle = event.evt.gattc_evt.error_handle,
                   attr_handle  = hvx_evt.handle,
                   hvx_type     = BLEGattHVXType(hvx_evt.type),
                   data         = util.uint8_array_to_list(hvx_evt.data, hvx_evt.len))

    def __repr__(self):
        data = ''.join(map(chr, self.data))
        return "%s(conn_handle=%r, status=%r, error_handle=%r, attr_handle=%r, hvx_type=%r, data=%r)" % (
                self.__class__.__name__, self.conn_handle,
                self.status, self.error_handle, self.attr_handle, self.hvx_type, data)

class GattcEvtWriteResponse(GattcEvt):
    evt_id = driver.BLE_GATTC_EVT_WRITE_RSP

    def __init__(self, conn_handle, status, error_handle, attr_handle, write_op, offset, data):
        super(GattcEvtWriteResponse, self).__init__(conn_handle)
        self.status         = status
        self.error_handle   = error_handle
        self.attr_handle    = attr_handle
        self.write_op       = write_op
        self.offset         = offset
        if isinstance(data, str):
            self.data       = map(ord, data)
        else:
            self.data       = data

    @classmethod
    def from_c(cls, event):
        write_rsp_evt   = event.evt.gattc_evt.params.write_rsp
        return cls(conn_handle  = event.evt.gattc_evt.conn_handle,
                   status       = BLEGattStatusCode(event.evt.gattc_evt.gatt_status),
                   error_handle = event.evt.gattc_evt.error_handle,
                   attr_handle  = write_rsp_evt.handle,
                   write_op     = BLEGattWriteOperation(write_rsp_evt.write_op),
                   offset       = write_rsp_evt.offset,
                   data         = util.uint8_array_to_list(write_rsp_evt.data, write_rsp_evt.len))

    def __repr__(self):
        data = ''.join(map(chr, self.data))
        return "%s(conn_handle=%r, status=%r, error_handle=%r, attr_handle=%r, write_op=%r, offset=%r, data=%r)" % (
                self.__class__.__name__, self.conn_handle,
                self.status, self.error_handle, self.attr_handle, self.write_op, self.offset, data)

def event_decode(event):
    if   event.header.evt_id == GapEvtAdvReport.evt_id:         return GapEvtAdvReport.from_c(event)
    elif event.header.evt_id == GapEvtConnected.evt_id:         return GapEvtConnected.from_c(event)
    elif event.header.evt_id == GapEvtDisconnected.evt_id:      return GapEvtDisconnected.from_c(event)
    elif event.header.evt_id == GapEvtTimeout.evt_id:           return GapEvtTimeout.from_c(event)

    elif event.header.evt_id == GapEvtSecParamsRequest.evt_id:  return GapEvtSecParamsRequest.from_c(event)
    elif event.header.evt_id == GapEvtAuthKeyRequest.evt_id:    return GapEvtAuthKeyRequest.from_c(event)
    elif event.header.evt_id == GapEvtConnSecUpdate.evt_id:     return GapEvtConnSecUpdate.from_c(event)
    elif event.header.evt_id == GapEvtAuthStatus.evt_id:        return GapEvtAuthStatus.from_c(event)
    #elif event.header.evt_id == driver.BLE_GAP_EVT_SEC_INFO_REQUEST:
    #elif event.header.evt_id == driver.BLE_GAP_EVT_SEC_REQUEST:

    elif event.header.evt_id == EvtTxComplete.evt_id:           return EvtTxComplete.from_c(event)

    elif event.header.evt_id == GattcEvtReadResponse.evt_id:    return GattcEvtReadResponse.from_c(event)
    elif event.header.evt_id == GattcEvtHvx.evt_id:             return GattcEvtHvx.from_c(event)
    elif event.header.evt_id == GattcEvtWriteResponse.evt_id:   return GattcEvtWriteResponse.from_c(event)

