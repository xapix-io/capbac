# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = 'capbac'
  spec.version       = '0.1.0'
  spec.author        = ['delaguardo']
  spec.summary       = ''
  spec.files         = Dir['lib/**/*', 'src/**/*.rs', 'Cargo.toml', 'LICENSE', 'README.md']
  spec.require_paths = ['lib']
  spec.add_dependency 'ffi'
  spec.extensions << 'ext/Rakefile'
  spec.add_runtime_dependency 'thermite', '~> 0'
end
