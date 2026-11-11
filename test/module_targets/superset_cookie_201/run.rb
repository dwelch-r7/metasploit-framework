#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../superset_cookie/run'

if $PROGRAM_NAME == __FILE__
  abort 'Usage: bundle exec ruby test/module_targets/superset_cookie_201/run.rb' unless ARGV.empty?
  exit SupersetCookieRunner.new.run(['superset_cookie_201'])
end
