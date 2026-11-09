require 'acceptance_spec_helper'
require 'rbconfig'

RSpec.describe 'Native TFTP discovery target' do
  include_context 'module target'

  before(:all) do
    argv = [RbConfig.ruby, 'test/module_targets/tftp/native_probe.rb']
    stdout, stderr, status = Open3.capture3(*argv)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-tftp-before.json'), stdout)
    File.write(File.join(target_runtime.fetch('artifacts'), 'native-tftp-command.json'), JSON.pretty_generate(argv: argv, stderr: stderr, exitstatus: status.exitstatus))
    expect(status.success?).to be(true), stderr
    @native_files = JSON.parse(stdout).fetch('files')
    @readable_names = @native_files.select { |_name, result| result.key?('octet') }.keys
    @denied_names = @native_files.select { |_name, result| result.key?('response') }.keys
    expect(@readable_names.length).to eq(5)
    expect(@denied_names.length).to eq(2)
    expect(target_runtime.fetch('transports')).to eq('tftp' => 'udp', 'unrelated' => 'udp')
  end

  it 'finds all actually readable names on successive scans without claiming denied files' do
    2.times do
      expect(scan_names('tftp', @readable_names + @denied_names)).to match_array(@readable_names)
    end
  end

  it 'supports an explicit real local interface on successive scans' do
    2.times do
      expect(scan_names('tftp', @readable_names + @denied_names, 'CHOST' => listener_host)).to match_array(@readable_names)
    end
  end

  it 'does not find absent or unreadable files' do
    expect(scan_names('tftp', @denied_names)).to be_empty
  end

  it 'handles an actual empty dictionary without invented results' do
    expect(scan_names('tftp', [])).to be_empty
  end

  it 'normalizes surrounding whitespace and ignores invalid blank names as discoveries' do
    unicode = @readable_names.find { |name| !name.ascii_only? }
    expect(unicode).not_to be_nil
    expect(scan_names('tftp', ["  #{@readable_names.first}  ", '', "\t#{unicode}\t"])).to match_array([@readable_names.first, unicode])
  end

  it 'does not identify unrelated genuine UDP DNS as a TFTP file' do
    expect(scan_names('unrelated', [@readable_names.first])).to be_empty
  end

  def scan_names(service, names, options = {})
    @dictionary_sequence = (@dictionary_sequence || 0) + 1
    example = RSpec.current_example.id.gsub(/[^a-zA-Z0-9_-]/, '_')
    path = File.join(target_runtime.fetch('artifacts'), "dictionary-#{example}-#{@dictionary_sequence}.txt")
    File.write(path, names.empty? ? '' : "#{names.join("\n")}\n")
    output = run_target_module('auxiliary/scanner/tftp/tftpbrute', service, { 'DICTIONARY' => path }.merge(options))
    endpoint = target_runtime.fetch('module_endpoints').fetch(service)
    # Console capture preserves bytes; the fixture filenames are valid UTF-8.
    output.scan(/Found ([^\r\n]+) on #{Regexp.escape(endpoint.fetch('host'))}$/).flatten.map do |name|
      name = name.dup.force_encoding(Encoding::UTF_8)
      expect(name.valid_encoding?).to be(true)
      name
    end
  end
end
