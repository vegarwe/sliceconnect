import logging
import Queue
import time
from enum import IntEnum

from pc_ble_driver_py.ble_driver import driver, util, BLEGapAddr, BLEGapRoles, BLEGapAdvType, BLEAdvData, BLEGapConnParams, BLEHci, BLEEvtID, BLEGattStatusCode, BLEDriverObserver

logger = logging.getLogger('fjase')

################### Types #####################

class BLEGapSecLevels(object):
    def __init__(self, lv1, lv2, lv3, lv4):
        self.lv1 = lv1
        self.lv2 = lv2
        self.lv3 = lv3
        self.lv4 = lv4

    @classmethod
    def from_c(cls, sec_level):
        return cls(lv1 = sec_level.lv1,
                   lv2 = sec_level.lv2,
                   lv3 = sec_level.lv3,
                   lv4 = sec_level.lv4)

    def to_c(self):
        sec_level     = driver.ble_gap_sec_levels_t()
        sec_level.lv1 = self.lv1
        sec_level.lv2 = self.lv2
        sec_level.lv3 = self.lv3
        sec_level.lv4 = self.lv4
        return sec_level

    def __repr__(self):
        return "%s(lv1=%r, lv2=%r, lv3=%r, lv4=%r)" % (self.__class__.__name__,
                self.lv1, self.lv2, self.lv3, self.lv4)

class BLEGapSecKeyDist(object):
    def __init__(self, enc_key=False, id_key=False, sign_key=False, link_key=False):
        self.enc_key    = enc_key
        self.id_key     = id_key
        self.sign_key   = sign_key
        self.link_key   = link_key

    @classmethod
    def from_c(cls, kdist):
        return cls(enc_key       = kdist.enc,
                   id_key        = kdist.id,
                   sign_key      = kdist.sign,
                   link_key      = kdist.link)

    def to_c(self):
        kdist       = driver.ble_gap_sec_kdist_t()
        kdist.enc   = self.enc_key
        kdist.id    = self.id_key
        kdist.sign  = self.sign_key
        kdist.link  = self.link_key
        return kdist

    def __repr__(self):
        return "%s(enc_key=%r, id_key=%r, sign_key=%r, link_key=%r)" % (self.__class__.__name__,
                self.enc_key, self.id_key, self.sign_key, self.link_key)

class BLEGapSecParams(object):
    def __init__(self, bond, mitm, le_sec_pairing, keypress_noti, io_caps, oob, min_key_size, max_key_size, kdist_own, kdist_peer):
        self.bond           = bond
        self.mitm           = mitm
        self.le_sec_pairing = le_sec_pairing
        self.keypress_noti  = keypress_noti
        self.io_caps        = io_caps
        self.oob            = oob
        self.min_key_size   = min_key_size
        self.max_key_size   = max_key_size
        self.kdist_own      = kdist_own
        self.kdist_peer     = kdist_peer

    @classmethod
    def from_c(cls, sec_params):
        return cls(bond             = sec_params.bond,
                   mitm             = sec_params.mitm,
                   le_sec_pairing   = sec_params.lesc,
                   keypress_noti    = sec_params.keypress,
                   io_caps          = sec_params.io_caps,
                   oob              = sec_params.oob,
                   min_key_size     = sec_params.min_key_size,
                   max_key_size     = sec_params.max_key_size,
                   kdist_own        = BLEGapSecKeyDist.from_c(sec_params.kdist_own),
                   kdist_peer       = BLEGapSecKeyDist.from_c(sec_params.kdist_peer))

    def to_c(self):
        sec_params              = driver.ble_gap_sec_params_t()
        sec_params.bond         = self.bond
        sec_params.mitm         = self.mitm
        sec_params.lesc         = self.le_sec_pairing
        sec_params.keypress     = self.keypress_noti
        sec_params.io_caps      = self.io_caps
        sec_params.oob          = self.oob
        sec_params.min_key_size = self.min_key_size
        sec_params.max_key_size = self.max_key_size
        sec_params.kdist_own    = self.kdist_own.to_c()
        sec_params.kdist_peer   = self.kdist_peer.to_c()
        return sec_params

    def __repr__(self):
        return "%s(bond=%r, mitm=%r, le_sec_pairing=%r, keypress_noti=%r, io_caps=%r, oob=%r, min_key_size=%r, max_key_size=%r, kdist_own=%r, kdist_peer=%r)" % (
                self.__class__.__name__, self.bond, self.mitm, self.le_sec_pairing, self.keypress_noti, self.io_caps,
                self.oob, self.min_key_size, self.max_key_size, self.kdist_own, self.kdist_peer,)

class BLEGapSecKeyset(object):
    def __init__(self):
        self.sec_keyset                 = driver.ble_gap_sec_keyset_t()
        keys_own                        = driver.ble_gap_sec_keys_t()
        self.sec_keyset.keys_own        = keys_own

        keys_peer                       = driver.ble_gap_sec_keys_t()
        keys_peer.p_enc_key             = driver.ble_gap_enc_key_t()
        keys_peer.p_enc_key.enc_info    = driver.ble_gap_enc_info_t()
        keys_peer.p_enc_key.master_id   = driver.ble_gap_master_id_t()
        keys_peer.p_id_key              = driver.ble_gap_id_key_t()
        keys_peer.p_id_key.id_info      = driver.ble_gap_irk_t()
        keys_peer.p_id_key.id_addr_info = driver.ble_gap_addr_t()
        #keys_peer.p_sign_key            = driver.ble_gap_sign_info_t()
        #keys_peer.p_pk                  = driver.ble_gap_lesc_p256_pk_t()
        self.sec_keyset.keys_peer       = keys_peer


    @classmethod
    def from_c(cls, sec_params):
        raise NotImplemented()

    def to_c(self):
        return self.sec_keyset


################### Events ####################


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

    def get(self, block=True, timeout=None):
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

class GapEvtAdvReport(GapEvt):
    evt_id = driver.BLE_GAP_EVT_ADV_REPORT

    def __init__(self, conn_handle, peer_addr, rssi, adv_type, adv_data):
        # TODO: What? Adv event has conn_handle? Does not compute
        super(GapEvtAdvReport, self).__init__(conn_handle)
        self.peer_addr     = peer_addr
        self.rssi          = rssi
        self.adv_type      = adv_type
        self.adv_data      = adv_data

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
        self.offset         = offset
        if isinstance(data, str):
            self.data       = map(ord, data)
        else:
            self.data       = data

    @classmethod
    def from_c(cls, event):
        hvx_evt = ble_event.evt.gattc_evt.params.hvx
        return cls(conn_handle  = event.evt.gattc_evt.conn_handle,
                   status       = BLEGattStatusCode(ble_event.evt.gattc_evt.gatt_status),
                   error_handle = ble_event.evt.gattc_evt.error_handle,
                   attr_handle  = hvx_evt.handle,
                   hvx_type     = BLEGattHVXType(hvx_evt.type),
                   data         = util.uint8_array_to_list(hvx_evt.data, hvx_evt.len))

    def __repr__(self):
        data = ''.join(map(chr, self.data))
        return "%s(conn_handle=%r, status=%r, error_handle=%r, attr_handle=%r, offset=%r, data=%r)" % (
                self.__class__.__name__, self.conn_handle,
                self.status, self.error_handle, self.attr_handle, self.evt_id, data)

def event_decode(event):
    if   event.header.evt_id == GapEvtAdvReport.evt_id:         return GapEvtAdvReport.from_c(event)
    elif event.header.evt_id == GapEvtConnected.evt_id:         return GapEvtConnected.from_c(event)
    elif event.header.evt_id == GapEvtDisconnected.evt_id:      return GapEvtDisconnected.from_c(event)

    elif event.header.evt_id == GapEvtSecParamsRequest.evt_id:  return GapEvtSecParamsRequest.from_c(event)
    elif event.header.evt_id == GapEvtAuthKeyRequest.evt_id:    return GapEvtAuthKeyRequest.from_c(event)
    elif event.header.evt_id == GapEvtConnSecUpdate.evt_id:     return GapEvtConnSecUpdate.from_c(event)
    elif event.header.evt_id == GapEvtAuthStatus.evt_id:        return GapEvtAuthStatus.from_c(event)
    #elif event.header.evt_id == driver.BLE_GAP_EVT_SEC_INFO_REQUEST:
    #    logger.info('BLE_GAP_EVT_SEC_INFO_REQUEST')
    #    return True
    #elif event.header.evt_id == driver.BLE_GAP_EVT_SEC_REQUEST:
    #    logger.info('BLE_GAP_EVT_SEC_REQUEST')
    #    return True

    #elif evt_id == BLEEvtID.gap_evt_timeout:
    #    timeout_evt = event.evt.gap_evt.params.timeout

    #    for obs in self.observers:
    #        obs.on_gap_evt_timeout(ble_driver   = self,
    #                               conn_handle  = event.evt.gap_evt.conn_handle,
    #                               src          = BLEGapTimeoutSrc(timeout_evt.src))

    elif event.header.evt_id == GattcEvtReadResponse.evt_id:    return GattcEvtReadResponse.from_c(event)
    elif event.header.evt_id == GattcEvtHvx.evt_id:             return GapEvtHvx.from_c(event)
