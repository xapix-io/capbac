# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'capbac/version'

Gem::Specification.new do |spec|
  spec.name          = 'capbac_cli'
  spec.version       = CapBAC::VERSION
  spec.authors       = ['Kirill Chernyshov']
  spec.email         = ['delaguardo@gmail.com']
  spec.summary       = ''
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.files         = Dir['lib/**/*', 'src/**/*.rs', 'Cargo.toml', 'LICENSE', 'README.md']
  spec.require_paths = ['lib']

  spec.add_dependency 'capbac', CapBAC::VERSION
  spec.add_dependency 'thor', '>= 0.20.3', '< 1.0.0'
end
