import logging

from nrf_event import *
from nrf_types import *
from nrf_driver import NrfDriverObserver
from nrf_event_sync     import EventSync

logger = logging.getLogger(__name__)


class GattClient(NrfDriverObserver):

    def __init__(self, adapter, conn_handle):
        super(GattClient, self).__init__()
        self.conn_handle    = conn_handle
        self.adapter        = adapter
        self.driver         = adapter.driver
        self.driver.observer_register(self)

    def gap_authenticate(self, bond=True, mitm=True, le_sec_pairing=False, keypress_noti=False, io_caps=None,
                         oob=False, min_key_size=16, max_key_size=16, kdist_own=None, kdist_peer=None):
        # TODO Create BLEGapSecKeyDist static values with defaults
        if not io_caps:
            io_caps = GapIoCaps.None
        if not kdist_own:
            kdist_own = BLEGapSecKeyDist()
        if not kdist_peer:
            kdist_peer = BLEGapSecKeyDist(enc_key=True)
        sec_params = BLEGapSecParams(bond           = bond,
                                     mitm           = mitm,
                                     le_sec_pairing = le_sec_pairing,
                                     keypress_noti  = keypress_noti,
                                     io_caps        = io_caps,
                                     oob            = oob,
                                     min_key_size   = min_key_size,
                                     max_key_size   = max_key_size,
                                     kdist_own      = kdist_own,
                                     kdist_peer     = kdist_peer)
        self.driver.ble_gap_authenticate(self.conn_handle, sec_params)

    def read(self, attr_handle):
        with EventSync(self.adapter, [GattcEvtReadResponse]) as evt_sync:
            self.adapter.ble_gattc_read(self.conn_handle, attr_handle)
            return evt_sync.get()

    def write(self, attr_handle, value, offset=0):
        write_params = BLEGattcWriteParams(BLEGattWriteOperation.write_req,
                                           BLEGattExecWriteFlag.unused,
                                           attr_handle,
                                           value,
                                           offset)
        self.adapter.ble_gattc_write(self.conn_handle, write_params)
        # TODO: Wait for HCI_NUM_COMPLETE or WRITE_RESPONSE?

    def service_discovery(self, uuid=None):
        classes = [GattcEvtReadResponse,
                   GattcEvtCharacteristicDiscoveryResponse,
                   GattcEvtDescriptorDiscoveryResponse]
        with EventSync(self.adapter, GattcEvtPrimaryServicecDiscoveryResponse) as evt_sync:
            self.driver.ble_gattc_prim_srvc_disc(self.conn_handle, uuid, 0x0001)
            services = []
            while True:
                event = evt_sync.get()

                if isinstance(event, GattcEvtPrimaryServicecDiscoveryResponse):
                    services.extend(event.services)
                elif event.status == BLEGattStatusCode.attribute_not_found:
                    break
                else:
                    return event.status

                if event.services[-1].end_handle == 0xFFFF:
                    break
                else:
                    self.driver.ble_gattc_prim_srvc_disc(self.conn_handle, uuid, event.services[-1].end_handle + 1)

        classes = [GattcEvtReadResponse,
                   GattcEvtCharacteristicDiscoveryResponse,
                   GattcEvtDescriptorDiscoveryResponse]
        with EventSync(self.adapter, classes) as evt_sync:
            for service in services:
                self.driver.ble_gattc_char_disc(self.conn_handle, service.start_handle, service.end_handle)
                while True:
                    event = evt_sync.get()

                    if event.status == BLEGattStatusCode.success:
                        map(service.char_add, event.characteristics)
                    elif event.status == BLEGattStatusCode.attribute_not_found:
                        break
                    else:
                        return event.status

                    self.driver.ble_gattc_char_disc(self.conn_handle,
                                                    event.characteristics[-1].handle_decl + 1,
                                                    service.end_handle)

                for char in service.chars:
                    self.driver.ble_gattc_desc_disc(self.conn_handle, char.handle_value, char.end_handle)
                    while True:
                        event = evt_sync.get()

                        if event.status == BLEGattStatusCode.success:
                            char.descs.extend(event.descriptions)
                        elif event.status == BLEGattStatusCode.attribute_not_found:
                            break
                        else:
                            return event.status

                        if event.descriptions[-1].handle == char.end_handle:
                            break
                        else:
                            self.driver.ble_gattc_desc_disc(self.conn_handle,
                                                            event.descriptions[-1].handle + 1,
                                                            char.end_handle)

    def on_event(self, nrf_driver, event):
        pass
        if   isinstance(event, GapEvtConnected):
            pass #    self.conn_handles.append(event.conn_handle)
        elif isinstance(event, GapEvtDisconnected):
            pass #    self.conn_handle.remove(event.conn_handle)
        elif isinstance(event, GattcEvtPrimaryServicecDiscoveryResponse):
            for service in event.services:
                logger.debug('New service uuid: %s, start handle: %02x, end handle: %02x',
                    service.uuid, service.start_handle, service.end_handle)
        elif isinstance(event, GattcEvtDescriptorDiscoveryResponse):
            for descriptor in event.descriptions:
                logger.debug('New descriptor uuid: %s, handle: %02x', descriptor.uuid, descriptor.handle)
        elif isinstance(event, GattcEvtCharacteristicDiscoveryResponse):
            for characteristic in event.characteristics:
                logger.debug('New characteristic uuid: %s, declaration handle: %02x, value handle: %02x',
                        characteristic.uuid, characteristic.handle_decl, characteristic.handle_value)
