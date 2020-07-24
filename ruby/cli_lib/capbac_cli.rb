# frozen_string_literal: true

require 'capbac'
require 'capbac/version'
require 'commander/import'
require 'optparse/uri'
require 'uri'

class RegexpTrustChecker < CapBAC::TrustChecker
  def initialize(regex)
    @check_regex = regex
  end

  def trusted?(id)
    !!@check_regex.match(id.to_s)
  end
end

class HashPubs < CapBAC::Pubs
  def initialize(pubs)
    @pubs = {}
    pubs.each do |pub|
      pair = pub.split('=')
      @pubs[URI.parse(pair[0])] = File.read(pair[1])
    end
  end

  def get(id)
    @pubs[id]
  end
end

# :name is optional, otherwise uses the basename of this executable
program :name, 'CapBAC CLI'
program :version, CapBAC::VERSION
program :description, 'Stupid command that prints foo or bar.'

command :forge do |c|
  c.option '--capability CAPABILITY', String
  c.option '--subject SUBJECT', URI
  c.option '--me ME', URI
  c.option '--sk SK', String
  c.option '--exp [EXP]', Integer
  c.action do |_args, options|
    holder = CapBAC::Holder.new(options.me, File.read(options.sk))
    ios = IO.new STDOUT.fileno
    cert = holder.forge(subject: options.subject, capability: options.capability)
    ios.write cert
    ios.close
  end
end

command :delegate do |c|
  c.option '--capability CAPABILITY', String
  c.option '--subject SUBJECT', URI
  c.option '--me ME', URI
  c.option '--sk SK', String
  c.option '--exp [EXP]', Integer
  c.action do |_args, options|
    holder = CapBAC::Holder.new(options.me, File.read(options.sk))
    cert = holder.delegate(STDIN.read, subject: options.subject, capability: options.capability)
    ios = IO.new STDOUT.fileno
    ios.write cert
    ios.close
  end
end

command :invoke do |c|
  c.option '--action ACTION', String
  c.option '--cert CERT', String
  c.option '--me ME', URI
  c.option '--sk SK', String
  c.option '--exp EXP', Integer
  c.action do |_args, options|
    holder = CapBAC::Holder.new(options.me, File.read(options.sk))
    inv = holder.invoke(cert: File.read(options.cert), action: options.action, exp: options.exp)
    ios = IO.new STDOUT.fileno
    ios.write inv
    ios.close
  end
end

command 'certificate-validate' do |c|
  pubs = []
  c.option '--now NOW', Integer
  c.option '--trust-ids REGEX', Regexp
  c.option('--pub PUB', String) { |x| pubs << x }
  c.action do |_args, options|
    trust_checker = RegexpTrustChecker.new(options.trust_ids)
    pubs = HashPubs.new(pubs)
    validator = CapBAC::Validator.new(trust_checker, pubs)
    begin
      validator.validate_cert(STDIN.read, options.now)
    rescue CapBAC::Malformed => e
      say e
      exit 11
    rescue CapBAC::BadURL => e
      say e
      exit 12
    rescue CapBAC::UnknownPub => e
      say e
      exit 12
    rescue CapBAC::BadIssuer => e
      say e
      exit 13
    rescue CapBAC::BadInvoker => e
      say e
      exit 13
    rescue CapBAC::Untrusted => e
      say e
      exit 13
    rescue CapBAC::Expired
      say 'Expired'
      exit 14
    rescue CapBAC::BadSign
      say 'Bad sign'
      exit 15
    end
  end
end

command 'invocation-validate' do |c|
  pubs = []
  c.option '--now NOW', Integer
  c.option '--trust-ids REGEX', Regexp
  c.option('--pub PUB', String) { |x| pubs << x }
  c.action do |_args, options|
    trust_checker = RegexpTrustChecker.new(options.trust_ids)
    pubs = HashPubs.new(pubs)
    validator = CapBAC::Validator.new(trust_checker, pubs)
    begin
      validator.validate_invocation(STDIN.read, options.now)
    rescue CapBAC::Malformed => e
      say e
      exit 11
    rescue CapBAC::BadURL => e
      say e
      exit 12
    rescue CapBAC::UnknownPub => e
      say e
      exit 12
    rescue CapBAC::BadIssuer => e
      say e
      exit 13
    rescue CapBAC::BadInvoker => e
      say e
      exit 13
    rescue CapBAC::Untrusted => e
      say e
      exit 13
    rescue CapBAC::Expired
      say 'Expired'
      exit 14
    rescue CapBAC::BadSign
      say 'Bad sign'
      exit 15
    end
  end
end

command 'key-pair' do |c|
  c.action do |_args, _options|
    say CapBAC::KeyPair.new.generate!
  end
end
