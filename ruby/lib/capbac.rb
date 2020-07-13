# frozen_string_literal: true

require 'thermite/fiddle'
require 'capbac/trust_checker'
require 'capbac/pubs'
require 'capbac/exceptions'

toplevel_dir = File.dirname(File.dirname(__FILE__))
Thermite::Fiddle.load_module(
  'init_capbac',
  cargo_project_path: toplevel_dir,
  ruby_project_path: toplevel_dir
)
