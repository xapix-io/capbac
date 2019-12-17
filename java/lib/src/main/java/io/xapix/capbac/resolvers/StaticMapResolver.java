package io.xapix.capbac.resolvers;

import io.xapix.capbac.CapBAC;
import io.xapix.capbac.CapBACResolver;

import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

public class StaticMapResolver implements CapBACResolver {
    private Map<URL, ECPublicKey> map;

    public StaticMapResolver(Map<URL, ECPublicKey> map) {
        this.map = map;
    }

    @Override
    public ECPublicKey resolve(URL id) throws CapBAC.BadID {
        if (!map.containsKey(id)) {
            throw new CapBAC.BadID();
        }
        return map.get(id);
    }
}
