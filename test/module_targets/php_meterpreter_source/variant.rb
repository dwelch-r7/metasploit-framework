# frozen_string_literal: true

require 'digest'
require 'fileutils'
require 'json'
require 'metasploit-payloads'
require 'open3'

# Explicit source comparisons; these never qualify the installed payload bundle.
class PhpMeterpreterSourceVariant
  BASELINE = 'e031bea39090ccc1c3086474c971c00368006e9105aa198d783f94225b36740d'
  CANDIDATE = 'e17550cce49a90f2a0922242b8697095d35d2c689df0ef3916fb4f104c23f7a1'

  def save
    File.write(File.join(@directory, 'php-source-variant.json'), JSON.pretty_generate(@journal)) if @journal
  end

  def gem_state
    path = File.join(MetasploitPayloads.data_directory, 'meterpreter', 'meterpreter.php')
    {
      path: path,
      encrypted_sha256: Digest::SHA256.file(path).hexdigest,
      source_sha256: Digest::SHA256.hexdigest(MetasploitPayloads::Crypto.decrypt(ciphertext: File.binread(path))),
      manifest_errors: MetasploitPayloads.manifest_errors.map { |entry| { path: entry[:path], error: entry[:error].class.name } }
    }
  end

  def prepare
    runtime = JSON.parse(File.read(ENV.fetch('MODULE_TARGET_RUNTIME')))
    @directory = runtime.fetch('artifacts')
    @mode = ENV.fetch('PHP_METERPRETER_SOURCE_MODE')
    raise ArgumentError, 'Expected baseline or candidate source mode' unless %w[baseline candidate].include?(@mode)

    config = File.join(@directory, 'msf-config')
    raise ArgumentError, 'Source comparison requires an isolated Framework configuration' unless ENV.fetch('MSF_CFGROOT_CONFIG') == config

    @journal = { mode: @mode, stock_qualification: false, installed_before: gem_state }
    raise ArgumentError, 'Installed payload source differs from the reviewed baseline' unless @journal[:installed_before][:source_sha256] == BASELINE && @journal[:installed_before][:manifest_errors].empty?

    @override = File.join(config, 'payloads', 'meterpreter', 'meterpreter.php')
    raise ArgumentError, 'The isolated payload override already exists' if File.exist?(@override) || File.symlink?(@override)

    staging = File.join(@directory, 'payload-source-build')
    source = File.join(staging, 'php', 'meterpreter', 'meterpreter.php')
    FileUtils.mkdir_p(File.dirname(source))
    File.binwrite(source, MetasploitPayloads::Crypto.decrypt(ciphertext: File.binread(@journal[:installed_before][:path])))
    if @mode == 'candidate'
      patch = File.expand_path('stream_framing.patch', __dir__)
      argv = ['patch', '--batch', '--forward', '-d', staging, '-p1', '-i', patch]
      output, error, status = Open3.capture3(*argv)
      @journal[:patch] = { argv: argv, exit: status.exitstatus, stdout: output, stderr: error, sha256: Digest::SHA256.file(patch).hexdigest }
      raise ArgumentError, "Candidate source patch failed: #{error}" unless status.success?
    end
    @expected = @mode == 'candidate' ? CANDIDATE : BASELINE
    raise ArgumentError, 'Prepared payload source has an unexpected digest' unless Digest::SHA256.file(source).hexdigest == @expected

    FileUtils.mkdir_p(File.dirname(@override))
    FileUtils.cp(source, @override)
    File.chmod(0o600, @override)
    @created = true
    @journal[:prepared] = { source: source, path: @override, sha256: @expected }
    save
  end

  def bind(example)
    state = example.instance_variable_get(:@rc)
    return if state[:payload_runtime_variant]

    actual = example.rc_json("{path:MetasploitPayloads.path('meterpreter','meterpreter.php'),sha256:Digest::SHA256.hexdigest(MetasploitPayloads.read('meterpreter','meterpreter.php'))}")
    raise ArgumentError, 'Framework did not read the prepared source override' unless actual == { 'path' => @override, 'sha256' => @expected }

    state[:payload_runtime_variant] = actual.merge('mode' => @mode, 'kind' => 'explicit_php_source_override', 'stock_qualification' => false)
    state[:source_consumer_observer] = example.rc_json("begin;load 'test/module_targets/php_meterpreter_source/observe.rb';PhpSourceConsumerObservation.install(framework,#{@directory.inspect});end")
    example.rc_save
  end

  def cleanup
    return unless @journal

    if @created
      raise ArgumentError, 'The payload override changed unexpectedly before cleanup' unless File.file?(@override) && !File.symlink?(@override) && Digest::SHA256.file(@override).hexdigest == @expected

      File.unlink(@override)
      @journal[:override_removed] = !File.exist?(@override)
    end
    @journal[:installed_after] = gem_state
    raise ArgumentError, 'Installed payload bytes or manifest changed' unless @journal[:installed_after] == @journal[:installed_before]
  ensure
    save
  end
end
