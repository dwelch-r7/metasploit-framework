#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative '../superset/native_gate'

# Extend the native gate without registering or calling an exploit owner.
class SupersetRceNativeGate < SupersetNativeGate
  private

  def inputs
    super.merge(Dir[File.join(__dir__, '*')].select { |path| File.file?(path) }.sort.to_h do |path|
      [path.delete_prefix("#{ROOT}/"), Digest::SHA256.file(path).hexdigest]
    end)
  end

  def required(argv, name, **options)
    output = super
    return output unless name == 'native-controls'

    super(['python3', '-B', File.join(__dir__, 'native_probe.py'), File.join(@directory, 'runtime.json')], 'native-rce-controls', timeout: 300)
    native = JSON.parse(File.read(File.join(@directory, 'native-rce-result.json')))
    raise Error, 'Native RCE controls did not pass and restore state' unless native.values_at('status', 'restored', 'framework_calls') == ['native_passed', true, 0]

    @result['native_rce'] = native
    output
  end
end

if $PROGRAM_NAME == __FILE__
  raise ArgumentError, 'Only the source-pinned 2.0.0 native profile is prepared' unless ARGV.empty?

  exit(SupersetRceNativeGate.new.run ? 0 : 1)
end
