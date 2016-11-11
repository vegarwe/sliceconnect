import logging
import wrapt
from types      import NoneType

from pc_ble_driver_py.ble_driver import driver, util, BLEEvtID, BLEGattStatusCode, NordicSemiErrorCheck, BLEDriver, BLEDriverObserver
from nrf_event import *

logger = logging.getLogger('fjase')


class RawBLEDriverObserver(object):
    def on_event(self, ble_driver, event):
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

    def ble_evt_handler(self, adapter, event):
        try:
            self._sync_extended_evt_handler(adapter, event)
        except Exception as e:
            logger.exception("Event handling failed")
        #super(BLEDriver, self).sync_ble_evt_handler(adapter, event)
        BLEDriver.sync_ble_evt_handler(self, adapter, event)

    @wrapt.synchronized(BLEDriver.observer_lock)
    def _sync_extended_evt_handler(self, adapter, event):
        logger.info('event %r', event.header.evt_id)

        if len(self.extended_observers) == 0:
            return

        event = event_decode(event)
        if event is None:
            return

        for obs in self.extended_observers:
            obs.on_event(self, event)
