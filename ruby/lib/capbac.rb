# frozen_string_literal: true

require 'rutie'
require 'capbac/trust_checker'
require 'capbac/pubs'
require 'capbac/exceptions'

Rutie.new(:capbac_ruby).init 'Init_capbac', __dir__
