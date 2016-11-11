import logging
import Queue
import time
from enum import IntEnum

from pc_ble_driver_py.ble_driver import driver, util, BLEEvtID, BLEGattStatusCode, BLEDriverObserver

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

    def _isinstance_of_event(self, event):
        if self._events == None:
            return True
        for _class in self._events:
            if isinstance(event, _class):
                return True
        return False

    def on_event(self, ble_driver, event):
        if not self._isinstance_of_event(event):
            return
        self._queue.put(event)

    def get(self, event_type=None, block=True, timeout=None):
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

class GapEvtDisconnected(GapEvt):
    evt_id = driver.BLE_GAP_EVT_DISCONNECTED

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

class GapAuthKeyType(IntEnum):
    BLE_GAP_AUTH_KEY_TYPE_NONE      = driver.BLE_GAP_AUTH_KEY_TYPE_NONE
    BLE_GAP_AUTH_KEY_TYPE_PASSKEY   = driver.BLE_GAP_AUTH_KEY_TYPE_PASSKEY
    BLE_GAP_AUTH_KEY_TYPE_OOB       = driver.BLE_GAP_AUTH_KEY_TYPE_OOB

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
        return cls(conn_handle     = event.evt.gattc_evt.conn_handle,
                   status          = BLEGattStatusCode(event.evt.gattc_evt.gatt_status),
                   error_handle    = event.evt.gattc_evt.error_handle,
                   attr_handle     = read_rsp.handle,
                   offset          = read_rsp.offset,
                   data            = util.uint8_array_to_list(read_rsp.data, read_rsp.len))

    def __repr__(self):
        data = ''.join(map(chr, self.data))
        return "%s(conn_handle=%r, status=%r, error_handle=%r, attr_handle=%r, offset=%r, data=%r)" % (
                self.__class__.__name__, self.conn_handle, self.status,
                self.error_handle, self.attr_handle, self.offset, data)


def event_decode(event):
    if   event.header.evt_id == GattcEvtReadResponse.evt_id:    return GattcEvtReadResponse.from_c(event)
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
