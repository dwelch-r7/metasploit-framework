require 'spec_helper'
require 'tmpdir'
require_relative '../../support/acceptance/child_process'

RSpec.describe Acceptance::ConsoleDriver do
  subject(:driver) { described_class.new }

  let(:metadata) { "{\n  \"module\": {\"path\": \"modules/auxiliary/example.rb\"}\n}\n" }
  let(:source) { File.join(directory, 'modules_metadata.json') }
  let(:destination) { File.join(directory, 'cached-metadata.json') }

  around do |example|
    Dir.mktmpdir('module-target-metadata-spec-') do |path|
      @directory = path
      example.run
    end
  end

  let(:directory) { @directory }

  before do
    File.binwrite(source, metadata)
    allow(File).to receive(:binread).and_call_original
    allow(driver).to receive(:sleep)
  end

  after do
    driver.close
    ObjectSpace.undefine_finalizer(driver)
  end

  it 'publishes the exact validated bytes and preserves the source timestamp' do
    timestamp = Time.utc(2026, 11, 9, 12)
    File.utime(timestamp, timestamp, source)

    driver.send(:cache_metadata_file, source, destination)

    expect([File.binread(destination), File.mtime(destination)]).to eq([metadata, timestamp])
  end

  it 'retries an empty in-progress write before publishing valid JSON' do
    allow(File).to receive(:binread).with(source).and_return('', metadata)

    driver.send(:cache_metadata_file, source, destination)

    expect(File.binread(destination)).to eq(metadata)
  end

  it 'does not re-read the source after validating its bytes' do
    allow(File).to receive(:binread).with(source) do
      File.binwrite(source, '')
      metadata
    end

    driver.send(:cache_metadata_file, source, destination)

    expect(File.binread(destination)).to eq(metadata)
  end

  it 'keeps a prior complete destination when malformed input exceeds the bound' do
    File.binwrite(source, '')
    File.binwrite(destination, metadata)

    expect { driver.send(:cache_metadata_file, source, destination, timeout: 0) }
      .to raise_error(Acceptance::ChildProcessError, /Metadata snapshot did not become ready/)
    expect(File.binread(destination)).to eq(metadata)
  end

  it 'retries a source briefly absent during replacement' do
    reads = 0
    allow(File).to receive(:binread).with(source) do
      reads += 1
      raise Errno::ENOENT, source if reads == 1

      metadata
    end

    driver.send(:cache_metadata_file, source, destination)

    expect(File.binread(destination)).to eq(metadata)
  end

  it 'propagates permission errors without treating them as incomplete writes' do
    allow(File).to receive(:binread).with(source).and_raise(Errno::EACCES)

    expect { driver.send(:cache_metadata_file, source, destination) }.to raise_error(Errno::EACCES)
  end
end
