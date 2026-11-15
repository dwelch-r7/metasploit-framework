# frozen_string_literal: true

require 'msfenv'
require 'msf/core'
require 'msf/base'
require 'digest'
require 'json'

source, output = ARGV
fixture = JSON.parse(File.read(File.join(__dir__, 'cases.json')))
namespace = Module.new
namespace.module_eval(File.binread(source), source)
component = namespace.const_get(:MetasploitModule)
payload = Class.new(Msf::Payload) { include component }.new
payload.datastore['LHOST'] = fixture.fetch('callback').fetch('host')
payload.datastore['LPORT'] = fixture.fetch('callback').fetch('port')
srand(fixture.fetch('generation_seed'))
code = "<?php\n" + payload.generate
methods = fixture.fetch('execution_methods')
order = code.scan(/['"](#{Regexp.union(methods)})['"]/).flatten.uniq
raise ArgumentError, 'Seeded default execution helper differs from the captured fixture' unless order.first == fixture.fetch('default_execution_method')

File.binwrite(output, code)
File.write("#{output}.json", JSON.pretty_generate(
  source: File.expand_path(source), source_sha256: Digest::SHA256.file(source).hexdigest,
  payload_sha256: Digest::SHA256.hexdigest(code), ruby_version: RUBY_VERSION,
  generation_seed: fixture.fetch('generation_seed'), execution_order: order,
  php_helper_sha256: Digest::SHA256.file('lib/msf/core/payload/php.rb').hexdigest,
  bundle_lock_sha256: Digest::SHA256.file('Gemfile.lock').hexdigest
))
