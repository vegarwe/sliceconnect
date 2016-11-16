#
# Copyright (c) 2016 Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice, this
#   list of conditions and the following disclaimer in the documentation and/or
#   other materials provided with the distribution.
#
#   3. Neither the name of Nordic Semiconductor ASA nor the names of other
#   contributors to this software may be used to endorse or promote products
#   derived from this software without specific prior written permission.
#
#   4. This software must only be used in or with a processor manufactured by Nordic
#   Semiconductor ASA, or in or with a processor manufactured by a third party that
#   is used in combination with a processor manufactured by Nordic Semiconductor.
#
#   5. Any software provided in binary or object form under this license must not be
#   reverse engineered, decompiled, modified and/or disassembled.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

import logging
import wrapt
import Queue
from threading      import Lock

from nrf_event      import *
from nrf_driver     import NrfDriverObserver, NrfDriver
from nrf_event_sync import EventSync

logger = logging.getLogger(__name__)


class NrfAdapterObserver(object):
    def on_gap_evt_adv_report(self, adapter, event):
        pass

class NrfAdapter(NrfDriverObserver):
    observer_lock = Lock()

    def __init__(self, driver):
        super(NrfAdapter, self).__init__()
        self.conn_handles   = []
        self.observers      = []
        self.driver         = driver
        self.driver.observer_register(self)

        # Do poor mans inheritance TODO: Remove
        self.ble_gap_scan_start         = self.driver.ble_gap_scan_start
        self.ble_gap_scan_stop          = self.driver.ble_gap_scan_stop
        self.ble_gap_connect            = self.driver.ble_gap_connect
        self.ble_gap_encrypt            = self.driver.ble_gap_encrypt
        self.ble_gap_sec_params_reply   = self.driver.ble_gap_sec_params_reply
        self.ble_gap_auth_key_reply     = self.driver.ble_gap_auth_key_reply
        self.ble_gattc_read             = self.driver.ble_gattc_read
        self.ble_gattc_write            = self.driver.ble_gattc_write


    @classmethod
    def open_serial(cls, serial_port, baud_rate):
        adapter = cls(NrfDriver(serial_port=serial_port, baud_rate=baud_rate))
        adapter.open()
        return adapter

    def open(self):
        self.driver.open()
        self.driver.ble_enable()

    def close(self):
        with EventSync(self.driver, GapEvtDisconnected) as evt_sync:
            for conn_handle in self.conn_handles[:]:
                logger.info('BLE: Disconnecting conn_handle %r', conn_handle)
                self.driver.ble_gap_disconnect(conn_handle)
                evt_sync.get(timeout=1.2) # TODO: If we know the conn_params we can be more informed about timeout
        self.driver.observer_unregister(self)
        self.driver.close()

    def on_event(self, nrf_driver, event):
        if   isinstance(event, GapEvtConnected):
            self.conn_handles.append(event.conn_handle)
        elif isinstance(event, GapEvtDisconnected):
            try:
                self.conn_handles.remove(event.conn_handle)
            except ValueError:
                pass
        elif isinstance(event, GapEvtAdvReport):
            # TODO: Maintain list of seen devices
            self._on_gap_evt_adv_report(nrf_driver, event)

    @wrapt.synchronized(observer_lock)
    def observer_register(self, observer):
        self.observers.append(observer)


    @wrapt.synchronized(observer_lock)
    def observer_unregister(self, observer):
        self.observers.remove(observer)

    @wrapt.synchronized(observer_lock)
    def _on_gap_evt_adv_report(self, nrf_driver, event):
        for obs in self.observers:
            obs.on_gap_evt_adv_report(self, event)
