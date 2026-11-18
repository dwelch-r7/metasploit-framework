require 'msfenv'
require 'msf/base'
require 'base64'
require 'json'
require 'rex/text'

RSpec.describe Msf::Auxiliary::Osticket do
  subject(:mod) { Msf::Auxiliary.new.extend(described_class) }

  let(:captures) { JSON.parse(File.binread(File.expand_path('../../../../file_fixtures/osticket/pdf-images.json', __dir__))) }
  let(:capture) { captures.fetch('b64') }
  let(:stream) { Base64.strict_decode64(capture.fetch('bgr_base64')) }
  let(:expected_file) { Base64.strict_decode64(capture.fetch('expected_base64')) }
  let(:marker) { "\x1b$)C".b }

  before do
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_good)
    allow(mod).to receive(:vprint_warning)
  end

  def image_pdf(image_object)
    "%PDF-1.4\n".b + image_object + "\n%%EOF\n".b
  end

  describe '#extract_files_from_pdf' do
    let(:pdf) { image_pdf(Base64.strict_decode64(capture.fetch('image_object_base64'))) }

    it 'decodes the genuine Base64 image despite filter-chain bytes after its padded value' do
      expect(mod.extract_files_from_pdf(pdf, encoding: 'b64')).to eq([expected_file])
    end

    it 'retains the legacy auto-detected return when no encoding is supplied' do
      expect(mod.extract_files_from_pdf(pdf)).to eq([stream.byteslice(marker.bytesize..).delete("\x00")])
    end

    it 'does not remove null bytes or the old padding sentinel from decoded binary content' do
      # A contract variant of the captured image; this is not a native binary-file capture.
      binary = "Binary:\x00\x80\xff@C>==\x00\x00".b
      image = mod.swap_rgb_bgr(marker + Base64.strict_encode64(binary) + "\x0f\x80".b)
      object = "1 0 obj\n<< /Subtype /Image /Filter /FlateDecode >>\nstream\n".b + Zlib::Deflate.deflate(image) + "\nendstream\nendobj".b

      expect(mod.extract_files_from_pdf(image_pdf(object), encoding: 'b64')).to eq([binary])
    end
  end

  describe '#extract_data_from_bmp_stream' do
    it 'decodes the captured Base64 bytes without their trailing non-Base64 filter data' do
      expect(mod.extract_data_from_bmp_stream(stream, encoding: 'b64')).to eq(expected_file)
    end

    it 'leaves Base64-looking plaintext unchanged when plain encoding was selected' do
      plaintext = Base64.strict_encode64(expected_file)

      expect(mod.extract_data_from_bmp_stream(marker + plaintext, encoding: 'plain')).to eq(plaintext)
    end

    it 'retains the legacy auto-detection of a complete Base64 value' do
      expect(mod.extract_data_from_bmp_stream(marker + Base64.strict_encode64(expected_file))).to eq(expected_file)
    end

    it 'decodes a one-byte file instead of treating it as short plaintext' do
      expect(mod.extract_data_from_bmp_stream(marker + 'YQ==' + "\x0f".b, encoding: 'b64')).to eq('a')
    end

    it 'stops at the first padded Base64 value before any filter suffix' do
      expect(mod.extract_data_from_bmp_stream(marker + 'YQ==QUJD', encoding: 'b64')).to eq('a')
    end

    it 'decodes an unpadded multiple-of-three byte file before the captured filter suffix' do
      expect(mod.extract_data_from_bmp_stream(marker + 'YWJj' + "\x0f\x80".b, encoding: 'b64')).to eq('abc')
    end

    it 'does not include an incomplete final quartet as file bytes' do
      expect(mod.extract_data_from_bmp_stream(marker + 'YWJjY' + "\x0f".b, encoding: 'b64')).to eq('abc')
    end

    it 'decompresses explicitly requested raw-deflate Base64 data' do
      deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
      compressed = deflater.deflate(expected_file, Zlib::FINISH)
      deflater.close

      expect(mod.extract_data_from_bmp_stream(marker + Base64.strict_encode64(compressed) + "\x0f".b, encoding: 'b64zlib')).to eq(expected_file)
    end

    it 'retains the partial native Deflate result without claiming complete file recovery' do
      compressed = captures.fetch('b64zlib_truncated')

      expect(mod.extract_data_from_bmp_stream(Base64.strict_decode64(compressed.fetch('bgr_base64')), encoding: 'b64zlib'))
        .to eq(Base64.strict_decode64(compressed.fetch('received_file_prefix_base64')))
    end

    it 'does not inflate a raw-deflate file when only Base64 decoding was selected' do
      deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
      compressed = deflater.deflate(expected_file, Zlib::FINISH)
      deflater.close

      expect(mod.extract_data_from_bmp_stream(marker + Base64.strict_encode64(compressed), encoding: 'b64')).to eq(compressed)
    end

    it 'rejects a missing marker' do
      expect(mod.extract_data_from_bmp_stream(Base64.strict_encode64(expected_file), encoding: 'b64')).to be_nil
    end

    it 'rejects marker-only input' do
      expect(mod.extract_data_from_bmp_stream(marker, encoding: 'b64')).to be_nil
    end

    it 'does not return filter padding when an encoded value is absent' do
      expect(mod.extract_data_from_bmp_stream(marker + "\x0f\x80".b, encoding: 'b64')).to be_nil
    end

    it 'does not return undecoded bytes when requested raw-deflate decoding fails' do
      expect(mod.extract_data_from_bmp_stream(marker + Base64.strict_encode64(expected_file), encoding: 'b64zlib')).to be_nil
    end

    it 'retains the actual truncated native plain-file prefix without claiming full-file recovery' do
      plain = captures.fetch('plain')

      expect(mod.extract_data_from_bmp_stream(Base64.strict_decode64(plain.fetch('bgr_base64')), encoding: 'plain'))
        .to eq(Base64.strict_decode64(plain.fetch('received_file_prefix_base64')))
    end
  end
end
