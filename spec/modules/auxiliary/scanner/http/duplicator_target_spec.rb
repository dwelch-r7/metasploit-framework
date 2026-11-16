require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/duplicator/acceptance'

RSpec.describe 'Native Duplicator file disclosure', acceptance: true, order: :defined do
  include_context 'native Duplicator target'

  if DuplicatorProfiles.fetch.fetch('mode') == 'affected'
    it 'identifies the affected release on both public checks without loot' do
      2.times { expect(duplicator_refuse(action: 'check')).to include('appears to be vulnerable') }
    end

    it 'retrieves the real system password file twice at the selected depth' do
      2.times { duplicator_download('/etc/passwd') }
    end

    it 'preserves UTF-8, NUL and non-UTF-8 content bytes on both runs' do
      2.times { duplicator_download(DuplicatorProfiles::FILES.fetch('owned').fetch('path')) }
    end

    it 'reads Unicode and whitespace paths and an ordinary relative path' do
      duplicator_download(DuplicatorProfiles::FILES.fetch('unicode').fetch('path'))
      duplicator_download(DuplicatorProfiles::FILES.fetch('owned').fetch('path').delete_prefix('/'))
    end

    it 'reads the real WordPress configuration at depth one twice' do
      2.times { duplicator_download('wp-config.php', 'DEPTH' => 1) }
    end

    it 'reads an ordinary confined backup at depth zero twice' do
      2.times { duplicator_download('module-target-backup.txt', 'DEPTH' => 0) }
    end

    it 'saves an actual empty attachment twice' do
      2.times { duplicator_download(DuplicatorProfiles::FILES.fetch('empty').fetch('path')) }
    end

    it 'does not save native missing-file or quoted-path refusals or insufficient depth' do
      %w[missing quoted].each { |name| duplicator_refuse({ 'FILEPATH' => DuplicatorProfiles::FILES.fetch(name).fetch('path') }) }
      duplicator_refuse({ 'FILEPATH' => '/etc/passwd', 'DEPTH' => 0 })
    end
  else
    it 'does not report a fixed, absent or unrelated target as affected on either check' do
      2.times do
        output = duplicator_refuse(action: 'check')
        expect(output).not_to include('appears to be vulnerable')
        expected = DuplicatorProfiles.fetch.fetch('mode') == 'fixed' ? /not exploitable/i : /cannot reliably check exploitability/i
        expect(output).to match(expected)
      end
    end

    it 'does not save a file from either public scanner run' do
      2.times { duplicator_refuse({ 'FILEPATH' => '/etc/passwd' }) }
    end
  end
end
