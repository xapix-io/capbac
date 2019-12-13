package io.xapix.capbac;

import io.xapix.capbac.proto.CapBACProto;

public interface CapBACInvocation {
    CapBACProto.Invocation encode();
}
