import abc
import logging
import Queue
import time
#import struct
#import binascii

from pc_ble_driver_py.exceptions    import NordicSemiException, IllegalStateException
from pc_ble_driver_py.ble_driver    import BLEDriverObserver, BLEUUIDBase, BLEUUID, BLEGapAddr, BLEGapConnParams, NordicSemiException
from pc_ble_driver_py.ble_adapter   import BLEAdapter, BLEAdapterObserver, EvtSync

from fjase_ble_driver import FjaseBLEDriver, FjaseBLEDriverObserver


logger = logging.getLogger('fjase')
logger.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
logger.addHandler(sh)

class Fjase(object):
    def __init__(self, serial_port, baud_rate=115200):
        self.baud_rate          = baud_rate
        self.serial_port        = serial_port
        self.fjase_adapter      = None

    def open(self):
        logger.debug("Connecting to adapter")
        if self.fjase_adapter:
            raise IllegalStateException('DFU Adapter is already open')

        driver           = FjaseBLEDriver(serial_port    = self.serial_port,
                                     baud_rate      = self.baud_rate)
        adapter          = BLEAdapter(driver)
        self.fjase_adapter = FjaseAdapter(adapter       = adapter)
        self.fjase_adapter.open()

    def close(self):
        logger.debug("Disconnecting adapter")
        if not self.fjase_adapter:
            raise IllegalStateException('DFU Adapter is already closed')
        self.fjase_adapter.close()
        self.fjase_adapter = None

class FjaseAdapter(FjaseBLEDriverObserver, BLEDriverObserver, BLEAdapterObserver):

    def __init__(self, adapter):
        super(FjaseAdapter, self).__init__()
        self.evt_sync           = EvtSync(['connected', 'disconnected'])
        self.conn_handle        = None
        self.adapter            = adapter
        self.notifications_q    = Queue.Queue()
        self.adapter.observer_register(self)
        self.adapter.driver.observer_register(self)
        self.adapter.driver.extended_observer_register(self)


    def open(self):
        self.adapter.driver.open()
        self.adapter.driver.ble_enable()

    def connect(self, target_device_addr):
        logger.info('BLE: Connecting...')
        conn_params = BLEGapConnParams(min_conn_interval_ms = 15,
                                       max_conn_interval_ms = 30,
                                       conn_sup_timeout_ms  = 4000,
                                       slave_latency        = 0)
        self.adapter.connect(address = target_device_addr, conn_params = conn_params)
        self.conn_handle = self.evt_sync.wait('connected')
        if self.conn_handle is None:
            raise NordicSemiException('Timeout. Device not found.')
        #logger.debug('BLE: Service Discovery...')
        #self.adapter.service_discovery(conn_handle=self.conn_handle)
        #logger.debug('BLE: Service Discovery done')

        #params = BLEGattcWriteParams(BLEGattWriteOperation.write_req,
        #                                   BLEGattExecWriteFlag.unused,
        #                                   handle,
        #                                   cccd_list,
        #                                   0)

        logger.debug('BLE: Read...')
        self.adapter.driver.read(self.conn_handle, 0x0003)
        #self.adapter.driver.write_req(
        logger.debug('BLE: Read done')
        time.sleep(1)
        #logger.debug('BLE: Enabling Notifications')
        #self.adapter.enable_notification(conn_handle=self.conn_handle, uuid=DFUAdapter.CP_UUID)
        #return self.target_device_name, self.target_device_addr

    def scan_start(self, timeout=1):
        logger.info('BLE: Scanning...')
        self.adapter.driver.ble_gap_scan_start()
        time.sleep(timeout)
        self.adapter.driver.ble_gap_scan_stop()

    def close(self):
        if self.conn_handle is not None:
            logger.info('BLE: Disconnecting from target')
            self.adapter.disconnect(self.conn_handle)
            self.evt_sync.wait('disconnected')
        self.adapter.driver.close()


    def on_gap_evt_connected(self, ble_driver, conn_handle, peer_addr, own_addr, role, conn_params):
        self.evt_sync.notify(evt = 'connected', data = conn_handle)
        logger.info('BLE: Connected to {}'.format(peer_addr))


    def on_gap_evt_disconnected(self, ble_driver, conn_handle, reason):
        self.evt_sync.notify(evt = 'disconnected', data = conn_handle)
        self.conn_handle = None
        logger.info('BLE: Disconnected')

    def on_gap_evt_adv_report(self, ble_driver, conn_handle, peer_addr, rssi, adv_type, adv_data):
        print "Hello", ble_driver, peer_addr.addr_type, peer_addr.addr, rssi, adv_type, adv_data


    def on_notification(self, ble_adapter, conn_handle, uuid, data):
        if self.conn_handle         != conn_handle: return
        print uuid, data
        #if DFUAdapter.CP_UUID.value != uuid.value:  return
        logger.debug(data)
        self.notifications_q.put(data)

    def on_gattc_evt_read_rsp(self, ble_driver, conn_handle, status, error_handle, attr_handle, offset, data):
        logger.info("Got read response conn_handle %s status %s err_handle %s attr_handle %s offset %s data: %r",
                conn_handle, status, error_handle, attr_handle, offset, ''.join(map(chr, data)))

def main():
	ble_backend = Fjase(serial_port="COM4")
	ble_backend.open()
	#ble_backend.fjase_adapter.scan_start(timeout=.3)
        ble_backend.fjase_adapter.connect(
                BLEGapAddr(BLEGapAddr.Types.random_static, [0xD6, 0x60, 0xC4, 0xA9, 0x6B, 0x5F]))
                #BLEGapAddr(BLEGapAddr.Types.random_static, [0xFE, 0xE4, 0x5D, 0xE9, 0x02, 0x19]))
                #BLEGapAddr(BLEGapAddr.Types.random_static, [0xEA, 0x81, 0xE3, 0xD0, 0x09, 0xC2]))
                #BLEGapAddr(BLEGapAddr.Types.random_static, [0xFB, 0x5E, 0xB7, 0xBD, 0xEC, 0x39]))
        ble_backend.close()

if __name__ == '__main__':
	main()
