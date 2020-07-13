module CapBAC
  class BadSign < StandardError; end
  class Expired < StandardError; end
  class Untrusted < StandardError; end
  class BadInvoker < StandardError; end
  class BadIssuer < StandardError; end
  class UnknownPub < StandardError; end
  class BadURL < StandardError; end
  class Malformed < StandardError; end
end
