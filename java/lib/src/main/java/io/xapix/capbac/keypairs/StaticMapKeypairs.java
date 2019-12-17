package io.xapix.capbac.keypairs;

import io.xapix.capbac.*;

import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.util.Map;

import io.xapix.capbac.CapBAC;

public class StaticMapKeypairs implements CapBACKeypairs {
    private Map<URL, ECPrivateKey> map;

    public StaticMapKeypairs(Map<URL, ECPrivateKey> map) {
        this.map = map;
    }

    @Override
    public ECPrivateKey get(URL id) throws CapBAC.BadID {
        if (!map.containsKey(id)) {
            throw new CapBAC.BadID();
        }
        return map.get(id);
    }
}
