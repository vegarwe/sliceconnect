import logging

from pc_ble_driver_py.ble_driver    import BLEGattcWriteParams, BLEGattWriteOperation, BLEGattExecWriteFlag

from nrf_event import *
from fjase_ble_driver import RawBLEDriverObserver

logger = logging.getLogger('fjase')


class GattClient(RawBLEDriverObserver):

    def __init__(self, adapter, conn_handle):
        super(GattClient, self).__init__()
        self.conn_handle    = conn_handle
        self.adapter        = adapter
        self.driver         = adapter.driver
        self.driver.extended_observer_register(self)

    def write(self, attr_handle, value, offset=0):
        write_params = BLEGattcWriteParams(BLEGattWriteOperation.write_req,
                                           BLEGattExecWriteFlag.unused,
                                           attr_handle,
                                           value,
                                           offset)
        self.adapter.ble_gattc_write(self.conn_handle, write_params)

    def service_discovery(self):
        self.driver.ble_gattc_prim_srvc_disc(conn_handle, uuid, 0x0001)

        while True:
            response = self.evt_sync[conn_handle].wait(evt = BLEEvtID.gattc_evt_prim_srvc_disc_rsp)

            if response['status'] == BLEGattStatusCode.success:
                self.db_conns[conn_handle].services.extend(response['services'])
            elif response['status'] == BLEGattStatusCode.attribute_not_found:
                break
            else:
                return response['status']

            if response['services'][-1].end_handle == 0xFFFF:
                break
            else:
                self.driver.ble_gattc_prim_srvc_disc(conn_handle,
                                                     uuid,
                                                     response['services'][-1].end_handle + 1)

        print response, self.db_conns[conn_handle]

        for s in self.db_conns[conn_handle].services:
            print s.start_handle, s.end_handle
            self.driver.ble_gattc_char_disc(conn_handle, s.start_handle, s.end_handle)
            while True:
                response = self.evt_sync[conn_handle].wait(evt = BLEEvtID.gattc_evt_char_disc_rsp)

                if response['status'] == BLEGattStatusCode.success:
                    map(s.char_add, response['characteristics'])
                elif response['status'] == BLEGattStatusCode.attribute_not_found:
                    break
                else:
                    return response['status']

                self.driver.ble_gattc_char_disc(conn_handle,
                                                response['characteristics'][-1].handle_decl + 1,
                                                s.end_handle)

            for ch in s.chars:
                self.driver.ble_gattc_desc_disc(conn_handle, ch.handle_value, ch.end_handle)
                while True:
                    response = self.evt_sync[conn_handle].wait(evt = BLEEvtID.gattc_evt_desc_disc_rsp)

                    if response['status'] == BLEGattStatusCode.success:
                        ch.descs.extend(response['descriptions'])
                    elif response['status'] == BLEGattStatusCode.attribute_not_found:
                        break
                    else:
                        return response['status']

                    if response['descriptions'][-1].handle == ch.end_handle:
                        break
                    else:
                        self.driver.ble_gattc_desc_disc(conn_handle,
                                                        response['descriptions'][-1].handle + 1,
                                                        ch.end_handle)
        return BLEGattStatusCode.success

    def on_event(self, ble_driver, event):
        pass
        logger.info('high level event %r', event)
        #if   isinstance(event, GapEvtConnected):
        #    self.conn_handles.append(event.conn_handle)
        #elif isinstance(event, GapEvtDisconnected):
        #    self.conn_handle.remove(event.conn_handle)
