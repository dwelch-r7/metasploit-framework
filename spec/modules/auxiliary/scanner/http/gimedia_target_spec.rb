require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/gimedia/acceptance'

RSpec.describe 'Native GI-Media Library file disclosure', acceptance: true, order: :defined do
  include_context 'native GI-Media Library target'

  if GimediaProfiles.fetch.fetch('mode') == 'affected'
    it 'identifies the affected release on both checks without creating loot' do
      2.times { expect(gimedia_refuse(action: 'check')).to include('appears to be vulnerable') }
    end

    it 'retrieves the real system password file twice at the selected traversal depth' do
      2.times { gimedia_download('/etc/passwd') }
    end

    it 'preserves UTF-8, NUL and non-UTF-8 content bytes on both runs' do
      2.times { gimedia_download(GimediaProfiles::FILES.fetch('owned').fetch('path')) }
    end

    it 'handles Unicode, whitespace, a quoted pathname and a relative pathname' do
      gimedia_download(GimediaProfiles::FILES.fetch('unicode').fetch('path'))
      gimedia_download(GimediaProfiles::FILES.fetch('quoted').fetch('path'))
      gimedia_download(GimediaProfiles::FILES.fetch('owned').fetch('path').delete_prefix('/'))
    end

    it 'reads the default WordPress configuration at the default depth twice' do
      2.times { gimedia_download('wp-config.php', 'DEPTH' => 3) }
    end

    it 'does not claim a download for missing or empty files, or insufficient depth' do
      %w[missing empty].each do |name|
        expect(gimedia_refuse({ 'FILEPATH' => GimediaProfiles::FILES.fetch(name).fetch('path') })).to include('Nothing was downloaded.')
      end
      expect(gimedia_refuse({ 'FILEPATH' => '/etc/passwd', 'DEPTH' => 1 })).to include('Nothing was downloaded.')
    end

    it 'does not create loot from a missing installation' do
      expect(gimedia_refuse({ 'TARGETURI' => '/module-target-missing/' })).to include('Nothing was downloaded.')
    end
  else
    it 'does not report the fixed, absent or unrelated target as affected on either check' do
      2.times do
        output = gimedia_refuse(action: 'check')
        expect(output).not_to include('appears to be vulnerable')
        expected = GimediaProfiles.fetch.fetch('mode') == 'fixed' ? /not exploitable/i : /cannot reliably check exploitability/i
        expect(output).to match(expected)
      end
    end

    it 'does not save a file from either public scanner run' do
      2.times { expect(gimedia_refuse).to include('Nothing was downloaded.') }
    end
  end
end
