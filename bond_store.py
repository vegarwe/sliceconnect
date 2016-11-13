import json
import os

from nrf_types import BLEGapAddr


DATA_STORE = os.path.join(os.path.expanduser('~'), 'bonds.json')


class Bond(object):
    def __init__(self, peer_addr, own_addr, ediv, rand, ltk, lesc, auth):
        self.peer_addr  = peer_addr
        self.own_addr   = own_addr
        self.ediv       = ediv
        self.rand       = rand
        self.ltk        = ltk
        self.lesc       = lesc
        self.auth       = auth

    @classmethod
    def from_json(cls, bonds):
        parsed = []
        for addr_str, bond_dict in bonds.iteritems():
            addr = BLEGapAddr.from_string(str(addr_str)) # TODO(vw): str(...) needed to handle unicode, but why???
            parsed.append(cls(addr, bond_dict['own'],
                    bond_dict['ediv'], bond_dict['rand'], bond_dict['ltk'], bond_dict['lesc'], bond_dict['auth']))
        return parsed


def _read_data_store():
    try:
        with open(DATA_STORE) as data_file:
            return json.load(data_file)
    except ValueError:
        return {}
    except IOError:
        return {}

def store_bond(own_addr, peer_addr, ediv, rand, ltk, lesc, auth):
    print 'own  %s' % own_addr
    print 'peer %s' % peer_addr
    print 'ediv %r' % ediv
    print 'rand %r' % rand
    print 'ltk  %r' % ltk
    print 'lesc %r' % lesc
    print 'auth %r' % auth

    peer_addr_str   = str(peer_addr)
    own_addr_str    = str(own_addr)

    data_store = _read_data_store()
    if data_store.has_key(peer_addr_str):
        data_store[peer_addr_str]['ediv'] = ediv
        data_store[peer_addr_str]['rand'] = rand
        data_store[peer_addr_str]['ltk' ] = ltk
        data_store[peer_addr_str]['lesc'] = lesc
        data_store[peer_addr_str]['auth'] = auth
        data_store[peer_addr_str]['own' ] = own_addr_str
    else:
        data_store[peer_addr_str] = {'ediv': ediv,
                                     'rand': rand,
                                     'ltk' : ltk,
                                     'lesc': lesc,
                                     'auth': auth,
                                     'own' : own_addr_str}

    with open(DATA_STORE, 'w') as store:
        json.dump(data_store, store)

def delete(addr_str):
    data_store = _read_data_store()
    data_store.pop(addr_str, None)
    with open(DATA_STORE, 'w') as store:
        json.dump(data_store, store)

def get_bonds():
    bonds = Bond.from_json(_read_data_store())
    return {str(bond.peer_addr): bond for bond in bonds}

def get_bond(addr):
    addr_str = addr
    for bond in Bond.from_json(_read_data_store()):
        if bond.peer_addr == addr:
            return bond
    return None
