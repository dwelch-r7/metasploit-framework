require 'rspec'
require 'json'
require 'base64'
require 'digest'

RSpec.describe 'Jenkins CLI ampersand file reads' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'auxiliary', reference_name: 'gather/jenkins_cli_ampersand_arbitrary_file_read') }

  let(:fixture_directory) { File.join(FILE_FIXTURES_PATH, 'modules/auxiliary/jenkins_cli') }
  let(:captures) { JSON.parse(File.read(File.join(fixture_directory, 'responses.json'))).fetch('captures') }
  let(:reference) { JSON.parse(File.read(File.join(fixture_directory, 'java_reference.json'))).fetch('values') }
  let(:host) { '192.0.2.53' }

  before do
    mod.datastore['AutoCheck'] = false
    mod.datastore['FILE_PATH'] = '/opt/module-target/two.txt'
    mod.datastore['ENCODING'] = 'UTF-8'
    mod.datastore['LOCALITY'] = 'en_US'
    allow(mod).to receive(:rhost).and_return(host)
    allow(mod).to receive(:print_good)
    allow(mod).to receive(:print_status)
    allow(mod).to receive(:print_bad)
    allow(mod).to receive(:vprint_error)
    allow(mod).to receive(:elog)
    allow(mod).to receive(:store_loot).and_return('/tmp/module-target-loot')
  end

  describe 'request encoding' do
    it 'retains the native Java encoding of ordinary arguments' do
      expect(mod.data_generator).to eq([reference.fetch('request_default')].pack('H*'))
    end

    it 'encodes a padded single-line request with complete frames' do
      mod.datastore['FILE_PATH'] = captures.fetch('one_padded').fetch('file_path')

      expect(mod.data_generator(pad: true)).to eq([reference.fetch('request_padded')].pack('H*'))
    end

    it 'uses full-width lengths for the native long path' do
      request = reference.fetch('request_long')
      mod.datastore['FILE_PATH'] = request_path(request)

      expect(mod.data_generator).to eq([request].pack('H*'))
    end

    it 'counts encoded bytes rather than characters in a Unicode path' do
      mod.datastore['FILE_PATH'] = captures.fetch('unicode').fetch('file_path')

      expect(mod.data_generator).to eq([reference.fetch('request_unicode')].pack('H*'))
    end

    it 'sizes the encoding-name field instead of assuming UTF-8 length' do
      mod.datastore['ENCODING'] = 'ISO-8859-1'

      expect(mod.data_generator).to eq([reference.fetch('request_alternate_encoding')].pack('H*'))
    end

    it 'matches Java modified UTF encoding for null and supplementary characters' do
      expect(mod.cli_utf("A\u0000\u{1f600}")).to eq([reference.fetch('nul_supplementary')].pack('H*'))
    end

    it 'accepts the maximum Java UTF field without wrapping its length' do
      expect(Digest::SHA256.hexdigest(mod.cli_utf('a' * 65_535))).to eq(reference.fetch('maximum_sha256'))
    end

    it 'rejects a Java UTF field beyond the native limit' do
      mod.datastore['FILE_PATH'] = 'a' * 65_535

      expect { mod.data_generator }.to raise_error(Msf::Auxiliary::Failed, /65,535/)
    end

    it 'rejects malformed UTF-8 before constructing a request' do
      expect { mod.cli_utf("\xff".b) }.to raise_error(Msf::Auxiliary::Failed, /UTF-8/)
    end
  end

  describe 'captured file responses' do
    {
      'one_padded' => [true, 'module-target-single-line'],
      'two' => [false, "module-target-first-line\nmodule-target-second-line"],
      'unicode' => [false, "module-target-café-漢字\nmodule-target-unicode-second"],
      'lts_two' => [false, "module-target-first-line\nmodule-target-second-line"]
    }.each do |name, (padded, expected)|
      it "stores the exact disclosed bytes from #{name} without frame headers" do
        mod.datastore['FILE_PATH'] = captures.fetch(name).fetch('file_path')
        mod.instance_variable_set(:@content_body, captured_response(name))

        mod.process_result(padded)

        expect(mod).to have_received(:store_loot).with('jenkins.file', 'text/plain', host, expected, mod.datastore['FILE_PATH'])
      end
    end

    %w[empty missing denied fixed_unpadded fixed_padded lts_fixed_padded].each do |name|
      it "does not invent file data from #{name}" do
        mod.datastore['FILE_PATH'] = captures.fetch(name).fetch('file_path')
        mod.instance_variable_set(:@content_body, captured_response(name))

        mod.process_result(captures.fetch(name).fetch('padded'))

        expect(mod).not_to have_received(:store_loot)
      end
    end

    it 'concatenates stderr chunks before interpreting file data' do
      response = derived_response('two') do |operation, data|
        if operation == 8 && data.include?('ERROR: Too many arguments:')
          [[8, data.byteslice(0, 9)], [8, data.byteslice(9..-1)]]
        else
          [[operation, data]]
        end
      end
      mod.instance_variable_set(:@content_body, response)

      mod.process_result(false)

      expect(mod).to have_received(:store_loot).with('jenkins.file', 'text/plain', host, "module-target-first-line\nmodule-target-second-line", mod.datastore['FILE_PATH'])
    end

    it 'preserves leading/trailing spaces and parentheses in disclosed text' do
      response = derived_response('two') do |operation, data|
        [[operation, data.gsub('module-target-first-line', '  first (value)  ').gsub('module-target-second-line', ' second) ')]]
      end
      mod.instance_variable_set(:@content_body, response)

      mod.process_result(false)

      expect(mod).to have_received(:store_loot).with('jenkins.file', 'text/plain', host, "  first (value)  \n second) ", mod.datastore['FILE_PATH'])
    end

    it 'does not treat stdout text as an argument-error disclosure' do
      response = derived_response('two') { |operation, data| [[operation == 8 ? 7 : operation, data]] }
      mod.instance_variable_set(:@content_body, response)

      mod.process_result(false)

      expect(mod).not_to have_received(:store_loot)
    end

    it 'requires the native argument-error exit status' do
      response = captured_response('two').dup
      response[-4, 4] = [0].pack('N')
      mod.instance_variable_set(:@content_body, response)

      mod.process_result(false)

      expect(mod).not_to have_received(:store_loot)
    end

    it 'rejects the patched literal echo when the console pathname has a binary encoding tag' do
      path = captures.fetch('unicode').fetch('file_path')
      mod.datastore['FILE_PATH'] = path.b
      response = derived_response('fixed_padded') do |operation, data|
        [[operation, data.gsub('/opt/module-target/two.txt', path.b)]]
      end
      mod.instance_variable_set(:@content_body, response)

      mod.process_result(true)

      expect(mod).not_to have_received(:store_loot)
    end

    it 'retains a real first line equal to the pathname when another file line was disclosed' do
      path = mod.datastore['FILE_PATH']
      response = derived_response('two') do |operation, data|
        [[operation, data.gsub('module-target-first-line', "@#{path}")]]
      end
      mod.instance_variable_set(:@content_body, response)

      mod.process_result(false)

      expect(mod).to have_received(:store_loot).with('jenkins.file', 'text/plain', host, "@#{path}\nmodule-target-second-line", path)
    end

    it 'preserves the configured pathname bytes and encoding tag' do
      path = captures.fetch('unicode').fetch('file_path')
      mod.datastore['FILE_PATH'] = path.b
      response = derived_response('fixed_padded') do |operation, data|
        [[operation, data.gsub('/opt/module-target/two.txt', path.b)]]
      end
      mod.instance_variable_set(:@content_body, response)

      mod.process_result(true)

      expect([mod.datastore['FILE_PATH'].encoding, mod.datastore['FILE_PATH'].bytes]).to eq([Encoding::ASCII_8BIT, path.bytes])
    end
  end

  describe 'malformed protocol responses' do
    {
      'missing transport ready byte' => ->(bytes) { bytes.byteslice(1..-1) },
      'truncated header' => ->(bytes) { bytes.byteslice(0, 4) },
      'truncated payload' => ->(bytes) { bytes.byteslice(0, bytes.bytesize - 1) },
      'missing exit frame' => ->(bytes) { bytes.byteslice(0, bytes.bytesize - 9) },
      'duplicate exit frame' => ->(bytes) { bytes + bytes.byteslice(-9, 9) },
      'negative frame length' => ->(_bytes) { "\x00\xff\xff\xff\xff\x08".b },
      'unknown opcode' => ->(bytes) { bytes.dup.tap { |copy| copy.setbyte(5, 255) } },
      'invalid text bytes' => ->(bytes) { bytes.sub('module-target-first-line', "\xffodule-target-first-line".b) }
    }.each do |name, mutation|
      it "rejects #{name} instead of parsing partial human-readable text" do
        mod.instance_variable_set(:@content_body, mutation.call(captured_response('two')))

        expect { mod.process_result(false) }.to raise_error(Msf::Auxiliary::Failed)
      end
    end
  end

  describe 'duplex request state' do
    it 'propagates a failed request thread instead of silently reporting no data' do
      allow(mod).to receive(:upload_request).and_raise(Msf::Auxiliary::Failed, 'Expected upload failure')
      allow(mod).to receive(:download_request)

      expect { mod.run }.to raise_error(Msf::Auxiliary::Failed, /Expected upload failure/)
    end

    it 'does not reuse content left by a preceding execution' do
      mod.instance_variable_set(:@content_body, captured_response('two'))
      allow(mod).to receive(:upload_request)
      allow(mod).to receive(:download_request)

      mod.run

      expect(mod).not_to have_received(:store_loot)
    end
  end

  def captured_response(name)
    Base64.strict_decode64(captures.fetch(name).fetch('body_base64'))
  end

  def derived_response(name)
    frames = captures.fetch(name).fetch('frames').flat_map do |frame|
      yield frame.fetch('opcode'), Base64.strict_decode64(frame.fetch('data_base64'))
    end
    "\x00".b + frames.map { |operation, data| [data.bytesize, operation].pack('NC') + data }.join
  end

  def request_path(hex)
    bytes = [hex].pack('H*')
    # The second ARG frame is the filename, after the eleven-byte help frame.
    bytes.byteslice(18, bytes.bytesize - 18).split("\x00", 2).first.delete_prefix('@')
  end
end
