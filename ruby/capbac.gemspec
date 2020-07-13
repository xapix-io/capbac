# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'capbac/version'

Gem::Specification.new do |spec|
  spec.name          = 'capbac'
  spec.version       = CapBAC::VERSION
  spec.authors       = ['delaguardo']
  spec.summary       = ''
  spec.files         = Dir['lib/**/*', 'src/**/*.rs', 'Cargo.toml', 'LICENSE', 'README.md']
  spec.require_paths = ['lib']
  spec.extensions << 'ext/Rakefile'
  spec.add_runtime_dependency 'thermite', '~> 0.13.0'

  spec.add_development_dependency 'bundler', '~> 2.0'
  spec.add_development_dependency 'rake', '~> 13.0.1'
  spec.add_development_dependency 'rubocop', '~> 0.87.1'
  spec.add_development_dependency 'rubygems-tasks', '~> 0.2.5'
end
