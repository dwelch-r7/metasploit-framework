require 'spec_helper'
require 'msf/core/encoded_payload'
require 'rex/peparsey'
require 'tempfile'
require 'zip'

RSpec.describe Msf::EncodedPayload, 'executable generation' do
  include_context 'Msf::Simple::Framework#modules loading'

  let(:payload) do
    load_and_create_module(
      module_type: 'payload',
      reference_name: 'linux/x86/exec',
      ancestor_reference_names: ['singles/linux/x86/exec']
    )
  end

  let(:payload_bytes) { "\x90\x90\xccMODULE_TARGET_PAYLOAD".b }
  subject(:encoded_payload) { described_class.new(framework, payload, {}) }

  before do
    encoded_payload.generate(payload_bytes)
  end

  describe '#encoded_exe' do
    {
      'Linux x86' => ['linux', ARCH_X86, 1, 3],
      'Linux x64' => ['linux', ARCH_X64, 2, 62],
      'Linux ARM little endian' => ['linux', ARCH_ARMLE, 1, 40],
      'Linux AArch64' => ['linux', ARCH_AARCH64, 2, 183],
      'BSD x86' => ['bsd', ARCH_X86, 1, 3],
      'Solaris x86' => ['solaris', ARCH_X86, 1, 3]
    }.each do |name, (platform, arch, elf_class, machine)|
      it "generates a default-format #{name} ELF with the encoded bytes" do
        executable = encoded_payload.encoded_exe(arch: arch, platform: Msf::Module::PlatformList.new(platform))
        expect(executable&.byteslice(0, 4)).to eq("\x7fELF".b)
        expect(executable.getbyte(4)).to eq(elf_class)
        expect(executable.byteslice(18, 2).unpack1('v')).to eq(machine)
        expect(executable).to end_with(payload_bytes)
      end
    end

    {
      'x86' => [ARCH_X86, 0x014c],
      'x64' => [ARCH_X64, 0x8664],
      'AArch64' => [ARCH_AARCH64, 0xaa64]
    }.each do |name, (arch, machine)|
      it "generates a default-format Windows #{name} PE" do
        executable = encoded_payload.encoded_exe(arch: arch, platform: Msf::Module::PlatformList.new('win'))
        expect(executable&.byteslice(0, 2)).to eq('MZ')
        expect(Rex::PeParsey::Pe.new_from_string(executable).hdr.file.Machine).to eq(machine)
      end
    end

    {
      'x64' => [ARCH_X64, "\xcf\xfa\xed\xfe".b, 0x01000007],
      'AArch64' => [ARCH_AARCH64, "\xcf\xfa\xed\xfe".b, 0x0100000c]
    }.each do |name, (arch, magic, cpu_type)|
      it "generates a default-format OSX #{name} Mach-O" do
        executable = encoded_payload.encoded_exe(arch: arch, platform: Msf::Module::PlatformList.new('osx'))
        expect(executable&.byteslice(0, 4)).to eq(magic)
        expect(executable.byteslice(4, 4).unpack1('V')).to eq(cpu_type)
        expect(executable).to include(payload_bytes)
      end
    end

    it 'uses the payload architecture and platform when no options are supplied' do
      executable = encoded_payload.encoded_exe
      expect(executable&.byteslice(0, 4)).to eq("\x7fELF".b)
      expect(executable.byteslice(18, 2).unpack1('v')).to eq(3)
      expect(executable).to end_with(payload_bytes)
    end

    it 'uses the supplied executable template' do
      template = File.binread(File.join(Msf::Config.data_directory, 'templates', 'template_x64_linux.bin'))
      template[9, 7] = 'MSFOPTS'
      Tempfile.create('encoded-executable-template') do |file|
        file.binmode
        file.write(template)
        file.flush
        executable = encoded_payload.encoded_exe(arch: ARCH_X64, platform: Msf::Module::PlatformList.new('linux'), template: file.path)
        expect(executable&.byteslice(9, 7)).to eq('MSFOPTS')
        expect(executable).to end_with(payload_bytes)
      end
    end

    it 'propagates the error for a missing supplied template' do
      path = File.join(Msf::Config.data_directory, 'templates', 'module-target-nonexistent-template.bin')
      expect do
        encoded_payload.encoded_exe(arch: ARCH_X64, platform: Msf::Module::PlatformList.new('linux'), template: path)
      end.to raise_error(Errno::ENOENT)
    end

    it 'retains the nil sentinel for an unsupported platform' do
      expect(encoded_payload.encoded_exe(arch: ARCH_X86, platform: Msf::Module::PlatformList.new('java'))).to be_nil
    end

    context 'with an already packaged ELF' do
      let(:payload_bytes) { File.binread(File.join(Msf::Config.data_directory, 'templates', 'template_x86_linux.bin')) }

      it 'preserves the existing bytes' do
        expect(encoded_payload.encoded_exe).to eq(payload_bytes)
      end
    end

    context 'with an already packaged Mach-O' do
      let(:payload_bytes) { File.binread(File.join(Msf::Config.data_directory, 'templates', 'template_x64_darwin.bin')) }

      it 'preserves the existing bytes' do
        expect(encoded_payload.encoded_exe).to eq(payload_bytes)
      end
    end
  end

  describe '#encoded_war' do
    it 'packages a native executable in the requested JSP file' do
      war = encoded_payload.encoded_war(app_name: 'module_target_app', jsp_name: 'module_target_native')
      jsp = nil
      Zip::File.open_buffer(war) { |archive| jsp = archive.read('module_target_native.jsp') }
      executable_hex = jsp[/String\s+\w+\s*=\s*"([0-9a-f]+)";/, 1]
      expect(executable_hex).not_to be_nil
      executable = [executable_hex].pack('H*')
      expect(executable).to start_with("\x7fELF".b)
      expect(executable).to end_with(payload_bytes)
    end
  end
end
