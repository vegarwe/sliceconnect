import logging
import wrapt
from types      import NoneType

from pc_ble_driver_py.ble_driver import driver, util, BLEEvtID, BLEGattStatusCode, NordicSemiErrorCheck, BLEDriver, BLEDriverObserver
from nrf_event import decode

logger = logging.getLogger('fjase')


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


class RawBLEDriverObserver(object):
    def on_event(self, ble_driver, ble_event):
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
    def ble_gap_authenticate(self, conn_handle, sec_params):
        assert isinstance(sec_params, BLEGapSecParams), 'Invalid argument type'
        return driver.sd_ble_gap_authenticate(self.rpc_adapter, conn_handle, sec_params.to_c())

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_gap_sec_params_reply(self, conn_handle, sec_status, sec_params, sec_keyset):
        assert isinstance(sec_params, (BLEGapSecParams, NoneType)), 'Invalid argument type'
        assert isinstance(sec_keyset, BLEGapSecKeyset), 'Invalid argument type'
        if sec_params:
            sec_params = sec_params.to_c()
        return driver.sd_ble_gap_sec_params_reply(self.rpc_adapter,
                conn_handle, sec_status, sec_params, sec_keyset.to_c())

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_gap_auth_key_reply(self, conn_handle, key_type, key):
        key_buf = util.list_to_uint8_array(key)
        return driver.sd_ble_gap_auth_key_reply(self.rpc_adapter,
                conn_handle, key_type, key_buf.cast())

    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def ble_gap_encrypt(self, conn_handle, ediv, rand, ltk, lesc, auth):
        #assert isinstance(sec_params, (BLEGapSecParams, NoneType)), 'Invalid argument type'
        #assert isinstance(sec_keyset, BLEGapSecKeyset), 'Invalid argument type'
        #print 'ediv %r' % master_id.ediv
        #print 'rand %r' % util.uint8_array_to_list(master_id.rand, 8)
        #print 'ltk  %r' % util.uint8_array_to_list(enc_info.ltk, enc_info.ltk_len)
        #print 'len  %r' % enc_info.ltk_len
        #print 'lesc %r' % enc_info.lesc
        #print 'auth %r' % enc_info.auth

        rand_arr            = util.list_to_uint8_array(rand)
        ltk_arr             = util.list_to_uint8_array(ltk)
        master_id           = driver.ble_gap_master_id_t()
        master_id.ediv      = ediv
        master_id.rand      = rand_arr.cast()
        enc_info            = driver.ble_gap_enc_info_t()
        enc_info.ltk_len    = len(ltk)
        enc_info.ltk        = ltk_arr.cast()
        enc_info.lesc       = lesc
        enc_info.auth       = auth
        return driver.sd_ble_gap_encrypt(self.rpc_adapter, conn_handle, master_id, enc_info)


    @NordicSemiErrorCheck
    @wrapt.synchronized(BLEDriver.api_lock)
    def read(self, conn_handle, read_handle, offset=0):
        return driver.sd_ble_gattc_read(self.rpc_adapter, conn_handle, read_handle, offset)




    def log_message_handler(self, adapter, severity, log_message):
        with open('log.txt', 'a') as logfile:
            logfile.write('%s\n' % (log_message))

    def ble_evt_handler(self, adapter, ble_event):
        try:
            self._sync_extended_evt_handler(adapter, ble_event)
        except Exception as e:
            logger.error("Exception: {}".format(str(e)))
            for line in traceback.extract_tb(sys.exc_info()[2]):
                logger.error(line)
            logger.error("")
        #super(BLEDriver, self).sync_ble_evt_handler(adapter, ble_event)
        BLEDriver.sync_ble_evt_handler(self, adapter, ble_event)

    @wrapt.synchronized(BLEDriver.observer_lock)
    def _sync_extended_evt_handler(self, adapter, ble_event):
        logger.info('ble_event %r', ble_event.header.evt_id)

        if len(self.extended_observers) == 0:
            return

        ble_event = decode(ble_event)
        if ble_event is None:
            return

        for obs in self.extended_observers:
            obs.on_event(self, ble_event)
