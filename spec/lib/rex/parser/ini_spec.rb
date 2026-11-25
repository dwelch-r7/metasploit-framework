require 'tempfile'

RSpec.describe Rex::Parser::Ini do
  let(:ini_contents) { <<EOF
# global comment
global setting = blah
[foo]
a = b
[bar]
b = c

[baf]
c = d
EOF
  }

  let(:ini) { described_class.from_s(ini_contents) }

  describe '#to_file' do
    it 'raises a TypeError when neither an argument nor a stored path is available' do
      expect { ini.to_file }.to raise_error(TypeError, 'no implicit conversion of nil into String')
    end

    it 'writes to an explicit Pathname' do
      Tempfile.create('framework-ini') do |file|
        ini.to_file(Pathname.new(file.path))
        expect(File.binread(file.path)).to eq(ini.to_s)
      end
    end

    it 'falls back to its stored path' do
      Tempfile.create('framework-ini') do |file|
        instance = described_class.new(file.path)
        instance.from_s(ini_contents)
        instance.to_file
        expect(File.binread(file.path)).to eq(instance.to_s)
      end
    end
  end

  describe '#from_file' do
    it 'raises an ArgumentError when no path is available' do
      expect { ini.from_file }.to raise_error(ArgumentError, /No file path specified\.\z/)
    end
  end

  it 'keeps parser helpers protected' do
    expect(described_class.protected_instance_methods).to include(:path=, :read_groups, :read_groups_string)
  end

  context "#each_group" do
    it "enumerates the groups" do
      groups = []
      ini.each_group { |group| groups << group }
      expect(groups).to eq(%w(foo bar baf))
    end
  end

  context "#each_key" do
    it "enumerates the groups" do
      groups = []
      ini.each_key.map { |group| groups << group }
      expect(groups).to eq(%w(foo bar baf))
    end
  end
end
