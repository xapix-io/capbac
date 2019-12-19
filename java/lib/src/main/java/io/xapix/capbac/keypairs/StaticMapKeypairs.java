package io.xapix.capbac.keypairs;

import io.xapix.capbac.*;

import java.net.URL;
import java.security.interfaces.ECPrivateKey;
import java.util.Map;

public class StaticMapKeypairs implements CapBACKeypairs {
    private Map<URL, ECPrivateKey> map;

    public StaticMapKeypairs(Map<URL, ECPrivateKey> map) {
        this.map = map;
    }

    @Override
    public ECPrivateKey get(URL id) {
        return map.get(id);
    }
}
