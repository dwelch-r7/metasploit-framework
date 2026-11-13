require 'spec_helper'
require_relative '../../../test/module_targets/freeswitch_execution/package_verify'

RSpec.describe FreeSwitchExecutionPackages do
  let(:configuration) { described_class::CONFIGURATION }

  it 'accepts an intact package without differences' do
    expect(described_class.verify('', configuration)).to eq([])
  end

  it 'records missing metadata explicitly excluded by the actual slim configuration' do
    output = "missing     /usr/share/doc/curl/changelog.gz\nmissing     /usr/share/locale/en_GB/LC_MESSAGES/wget.mo\n"
    expect(described_class.verify(output, configuration)).to eq(['/usr/share/doc/curl/changelog.gz', '/usr/share/locale/en_GB/LC_MESSAGES/wget.mo'])
  end

  it 'rejects a missing executable' do
    expect { described_class.verify("missing     /usr/bin/curl\n", configuration) }.to raise_error(ArgumentError, /Unexpected missing installed package file/)
  end

  it 'rejects an executable checksum mismatch' do
    expect { described_class.verify("??5??????   /usr/bin/curl\n", configuration) }.to raise_error(ArgumentError, /Unexpected package verification difference/)
  end

  it 'honors the later copyright inclusion over the documentation exclusion' do
    expect { described_class.verify("missing     /usr/share/doc/curl/copyright\n", configuration) }.to raise_error(ArgumentError, /Unexpected missing installed package file/)
  end

  it 'rejects an exclusion configuration that could hide executable loss' do
    expect { described_class.verify("missing     /usr/bin/curl\n", configuration + "path-exclude /usr/bin/*\n") }.to raise_error(ArgumentError, /Unexpected native dpkg exclusion configuration/)
  end
end
