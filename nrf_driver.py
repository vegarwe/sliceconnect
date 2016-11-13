import logging
import wrapt
from threading  import Lock
from types      import NoneType

from nrf_event import *
from nrf_types import *
from pc_ble_driver_py.ble_driver import driver, util, NordicSemiErrorCheck

logger = logging.getLogger('fjase') # TODO: Find better logger


class NrfDriverObserver(object):
    def on_event(self, nrf_driver, event):
        pass

class NrfDriver(object):
    observer_lock   = Lock()
    api_lock        = Lock()

    def __init__(self, serial_port, baud_rate=115200, auto_flash=False):
        super(NrfDriver, self).__init__()
        self.observers = list()

        # TODO: Is this the best way?
        #if auto_flash:
        #    try:
        #        flasher = Flasher(serial_port=serial_port)
        #    except Exception:
        #        logger.error("Unable to find serial port")
        #        raise

        #    if flasher.fw_check() == False:
        #        logger.info("Flashing board with firmware")
        #        flasher.fw_flash()

        #    flasher.reset()
        #    time.sleep(1)

        phy_layer           = driver.sd_rpc_physical_layer_create_uart(serial_port,
                                                                       baud_rate,
                                                                       driver.SD_RPC_FLOW_CONTROL_NONE,
                                                                       driver.SD_RPC_PARITY_NONE);
        link_layer          = driver.sd_rpc_data_link_layer_create_bt_three_wire(phy_layer, 100)
        transport_layer     = driver.sd_rpc_transport_layer_create(link_layer, 100)
        self.rpc_adapter    = driver.sd_rpc_adapter_create(transport_layer)


    @wrapt.synchronized(api_lock)
    @classmethod
    def enum_serial_ports(cls):
        MAX_SERIAL_PORTS = 64
        c_descs = [ driver.sd_rpc_serial_port_desc_t() for i in range(MAX_SERIAL_PORTS)]
        c_desc_arr = util.list_to_serial_port_desc_array(c_descs)

        arr_len = driver.new_uint32()
        driver.uint32_assign(arr_len, MAX_SERIAL_PORTS)

        err_code = driver.sd_rpc_serial_port_enum(c_desc_arr, arr_len)
        if err_code != driver.NRF_SUCCESS:
            raise NordicSemiException('Failed to {}. Error code: {}'.format(func.__name__, err_code))

        dlen = driver.uint32_value(arr_len)

        descs   = util.serial_port_desc_array_to_list(c_desc_arr, dlen)
        return map(SerialPortDescriptor.from_c, descs)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def open(self):
        return driver.sd_rpc_open(self.rpc_adapter,
                                  self.status_handler,
                                  self.ble_evt_handler,
                                  self.log_message_handler)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def close(self):
        return driver.sd_rpc_close(self.rpc_adapter)


    @wrapt.synchronized(observer_lock)
    def observer_register(self, observer):
        self.observers.append(observer)


    @wrapt.synchronized(observer_lock)
    def observer_unregister(self, observer):
        self.observers.remove(observer)


    def ble_enable_params_setup(self):
        return BLEEnableParams(vs_uuid_count      = 1,
                               service_changed    = False,
                               periph_conn_count  = 1,
                               central_conn_count = 1,
                               central_sec_count  = 1)


    def adv_params_setup(self):
        return BLEGapAdvParams(interval_ms = 40,
                               timeout_s   = 180)


    def scan_params_setup(self):
        return BLEGapScanParams(interval_ms = 200,
                                window_ms   = 150,
                                timeout_s   = 10)


    def conn_params_setup(self):
        return BLEGapConnParams(min_conn_interval_ms = 15,
                                max_conn_interval_ms = 30,
                                conn_sup_timeout_ms  = 4000,
                                slave_latency        = 0)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_enable(self, ble_enable_params=None):
        if not ble_enable_params:
            ble_enable_params = self.ble_enable_params_setup()
        assert isinstance(ble_enable_params, BLEEnableParams), 'Invalid argument type'
        return driver.sd_ble_enable(self.rpc_adapter, ble_enable_params.to_c(), None)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_adv_start(self, adv_params=None):
        if not adv_params:
            adv_params = self.adv_params_setup()
        assert isinstance(adv_params, BLEGapAdvParams), 'Invalid argument type'
        return driver.sd_ble_gap_adv_start(self.rpc_adapter, adv_params.to_c())


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_conn_param_update(self, conn_handle, conn_params):
        assert isinstance(conn_params, (BLEGapConnParams, NoneType)), 'Invalid argument type'
        if conn_params:
            conn_params=conn_params.to_c()
        return driver.sd_ble_gap_conn_param_update(self.rpc_adapter, conn_handle, conn_params)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_adv_stop(self):
        return driver.sd_ble_gap_adv_stop(self.rpc_adapter)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_scan_start(self, scan_params=None):
        if not scan_params:
            scan_params = self.scan_params_setup()
        assert isinstance(scan_params, BLEGapScanParams), 'Invalid argument type'
        return driver.sd_ble_gap_scan_start(self.rpc_adapter, scan_params.to_c())


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_scan_stop(self):
        return driver.sd_ble_gap_scan_stop(self.rpc_adapter)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_connect(self, address, scan_params=None, conn_params=None):
        assert isinstance(address, BLEGapAddr), 'Invalid argument type'

        if not scan_params:
            scan_params = self.scan_params_setup()
        assert isinstance(scan_params, BLEGapScanParams), 'Invalid argument type'

        if not conn_params:
            conn_params = self.conn_params_setup()
        assert isinstance(conn_params, BLEGapConnParams), 'Invalid argument type'

        return driver.sd_ble_gap_connect(self.rpc_adapter, 
                                                address.to_c(),
                                                scan_params.to_c(),
                                                conn_params.to_c())


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_disconnect(self, conn_handle, hci_status_code = BLEHci.remote_user_terminated_connection):
        assert isinstance(hci_status_code, BLEHci), 'Invalid argument type'
        return driver.sd_ble_gap_disconnect(self.rpc_adapter, 
                                                   conn_handle,
                                                   hci_status_code.value)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_adv_data_set(self, adv_data = BLEAdvData(), scan_data = BLEAdvData()):
        assert isinstance(adv_data, BLEAdvData),    'Invalid argument type'
        assert isinstance(scan_data, BLEAdvData),   'Invalid argument type'
        (adv_data_len,  p_adv_data)     = adv_data.to_c()
        (scan_data_len, p_scan_data)    = scan_data.to_c()

        return driver.sd_ble_gap_adv_data_set(self.rpc_adapter,
                                              p_adv_data,
                                              adv_data_len,
                                              p_scan_data,
                                              scan_data_len)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_authenticate(self, conn_handle, sec_params):
        assert isinstance(sec_params, BLEGapSecParams), 'Invalid argument type'
        return driver.sd_ble_gap_authenticate(self.rpc_adapter, conn_handle, sec_params.to_c())

    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_sec_params_reply(self, conn_handle, sec_status, sec_params, sec_keyset):
        assert isinstance(sec_params, (BLEGapSecParams, NoneType)), 'Invalid argument type'
        assert isinstance(sec_keyset, BLEGapSecKeyset), 'Invalid argument type'
        if sec_params:
            sec_params = sec_params.to_c()
        return driver.sd_ble_gap_sec_params_reply(self.rpc_adapter,
                conn_handle, sec_status, sec_params, sec_keyset.to_c())

    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gap_auth_key_reply(self, conn_handle, key_type, key):
        key_buf = util.list_to_uint8_array(key)
        return driver.sd_ble_gap_auth_key_reply(self.rpc_adapter,
                conn_handle, key_type, key_buf.cast())

    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
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
    @wrapt.synchronized(api_lock)
    def ble_vs_uuid_add(self, uuid_base):
        assert isinstance(uuid_base, BLEUUIDBase), 'Invalid argument type'
        uuid_type = driver.new_uint8()

        err_code = driver.sd_ble_uuid_vs_add(self.rpc_adapter,
                                             uuid_base.to_c(),
                                             uuid_type)
        if err_code == driver.NRF_SUCCESS:
            uuid_base.type = driver.uint8_value(uuid_type)
        return err_code


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gattc_write(self, conn_handle, write_params):
        assert isinstance(write_params, BLEGattcWriteParams), 'Invalid argument type %r' % write_params
        return driver.sd_ble_gattc_write(self.rpc_adapter,
                                         conn_handle,
                                         write_params.to_c())


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gattc_prim_srvc_disc(self, conn_handle, srvc_uuid, start_handle):
        assert isinstance(srvc_uuid, (BLEUUID, NoneType)), 'Invalid argument type'
        return driver.sd_ble_gattc_primary_services_discover(self.rpc_adapter,
                                                             conn_handle,
                                                             start_handle,
                                                             srvc_uuid.to_c() if srvc_uuid else None)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gattc_char_disc(self, conn_handle, start_handle, end_handle):
        handle_range                = driver.ble_gattc_handle_range_t()
        handle_range.start_handle   = start_handle
        handle_range.end_handle     = end_handle
        return driver.sd_ble_gattc_characteristics_discover(self.rpc_adapter,
                                                            conn_handle,
                                                            handle_range)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gattc_desc_disc(self, conn_handle, start_handle, end_handle):
        handle_range                = driver.ble_gattc_handle_range_t()
        handle_range.start_handle   = start_handle
        handle_range.end_handle     = end_handle
        return driver.sd_ble_gattc_descriptors_discover(self.rpc_adapter,
                                                        conn_handle,
                                                        handle_range)


    @NordicSemiErrorCheck
    @wrapt.synchronized(api_lock)
    def ble_gattc_read(self, conn_handle, read_handle, offset=0):
        return driver.sd_ble_gattc_read(self.rpc_adapter, conn_handle, read_handle, offset)


    def status_handler(self, adapter, status_code, status_message):
        pass


    def log_message_handler(self, adapter, severity, log_message):
        # TODO: Better file name (and location)
        with open('log.txt', 'a') as logfile:
            logfile.write('%s\n' % (log_message))

    def ble_evt_handler(self, adapter, event):
        try:
            self._sync_evt_handler(adapter, event)
        except Exception as e:
            logger.exception("Event handling failed")

    @wrapt.synchronized(observer_lock)
    def _sync_evt_handler(self, adapter, event):
        logger.info('event %r', event.header.evt_id)

        if len(self.observers) == 0:
            return

        event = event_decode(event)
        if event is None:
            return

        for obs in self.observers:
            obs.on_event(self, event)
