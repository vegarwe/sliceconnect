import Queue
import time

from nrf_driver     import NrfDriverObserver


class EventSync(NrfDriverObserver):
    def __init__(self, adapter, event_filter=None, callback=None):
        super(NrfDriverObserver, self).__init__()
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

    def on_event(self, nrf_driver, event):
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

