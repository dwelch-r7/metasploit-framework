require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/dukapress/acceptance'

RSpec.describe 'Native DukaPress file disclosure', acceptance: true, order: :defined do
  include_context 'native DukaPress target'

  if DukapressProfiles.fetch.fetch('mode') == 'affected'
    it 'identifies the affected release on both checks without creating loot' do
      2.times { expect(duka_refuse(action: 'check')).to include('appears to be vulnerable') }
    end

    it 'retrieves the real system password file twice at the selected traversal depth' do
      2.times { duka_download('/etc/passwd') }
    end

    it 'preserves UTF-8, NUL and non-UTF-8 content bytes on both runs' do
      2.times { duka_download(DukapressProfiles::FILES.fetch('owned').fetch('path')) }
    end

    it 'handles a Unicode pathname with whitespace and a relative pathname' do
      duka_download(DukapressProfiles::FILES.fetch('unicode').fetch('path'))
      duka_download(DukapressProfiles::FILES.fetch('owned').fetch('path').delete_prefix('/'))
    end

    it 'does not claim a download for missing, empty or natively refused quoted paths, or insufficient depth' do
      %w[missing empty quoted].each do |name|
        expect(duka_refuse({ 'FILEPATH' => DukapressProfiles::FILES.fetch(name).fetch('path') })).to include('Nothing was downloaded.')
      end
      expect(duka_refuse({ 'FILEPATH' => '/etc/passwd', 'DEPTH' => 1 })).to include('Nothing was downloaded.')
    end

    it 'does not create loot from a missing installation' do
      expect(duka_refuse({ 'TARGETURI' => '/module-target-missing/' })).to include('Nothing was downloaded.')
    end
  else
    it 'does not report the fixed, absent or unrelated target as affected on either check' do
      2.times do
        output = duka_refuse(action: 'check')
        expect(output).not_to include('appears to be vulnerable')
        expected = DukapressProfiles.fetch.fetch('mode') == 'fixed' ? /not exploitable/i : /cannot reliably check exploitability/i
        expect(output).to match(expected)
      end
    end

    it 'does not save a file from either public scanner run' do
      2.times { expect(duka_refuse).to include('Nothing was downloaded.') }
    end
  end
end
