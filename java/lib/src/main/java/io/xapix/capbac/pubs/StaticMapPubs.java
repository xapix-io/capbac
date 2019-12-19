package io.xapix.capbac.pubs;


import io.xapix.capbac.CapBACPubs;

import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

public class StaticMapPubs implements CapBACPubs {
    private Map<URL, ECPublicKey> map;

    public StaticMapPubs(Map<URL, ECPublicKey> map) {
        this.map = map;
    }

    @Override
    public ECPublicKey get(URL id) {
        return map.get(id);
    }
}
