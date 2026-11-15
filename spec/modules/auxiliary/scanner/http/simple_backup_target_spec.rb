require 'acceptance_spec_helper'
require_relative '../../../../../test/module_targets/simple_backup/acceptance'

RSpec.describe 'Native Simple Backup file disclosure', acceptance: true, order: :defined do
  include_context 'native Simple Backup target'

  if SimpleBackupProfiles.fetch.fetch('mode') == 'affected'
    it 'identifies the affected release on both checks without creating loot' do
      2.times { expect(simple_backup_refuse(action: 'check')).to include('appears to be vulnerable') }
    end

    it 'retrieves the real system password file twice at the selected traversal depth' do
      2.times { simple_backup_download('/etc/passwd') }
    end

    it 'preserves UTF-8, NUL and non-UTF-8 content bytes on both runs' do
      2.times { simple_backup_download(SimpleBackupProfiles::FILES.fetch('owned').fetch('path')) }
    end

    it 'handles Unicode, whitespace, a quoted pathname and a relative pathname' do
      simple_backup_download(SimpleBackupProfiles::FILES.fetch('unicode').fetch('path'))
      simple_backup_download(SimpleBackupProfiles::FILES.fetch('quoted').fetch('path'))
      simple_backup_download(SimpleBackupProfiles::FILES.fetch('owned').fetch('path').delete_prefix('/'))
    end

    it 'reads the WordPress configuration from the backup directory twice' do
      2.times { simple_backup_download('wp-config.php', 'DEPTH' => 1) }
    end

    it 'reads an ordinary confined backup twice at depth zero' do
      2.times { simple_backup_download('module-target-backup.txt', 'DEPTH' => 0) }
    end

    it 'does not claim a download for missing or empty files, or insufficient depth' do
      %w[missing empty].each do |name|
        expect(simple_backup_refuse({ 'FILEPATH' => SimpleBackupProfiles::FILES.fetch(name).fetch('path') })).to include('Nothing was downloaded.')
      end
      expect(simple_backup_refuse({ 'FILEPATH' => '/etc/passwd', 'DEPTH' => 1 })).to include('Nothing was downloaded.')
    end

    it 'preserves the native disclosure through an ordinary rewritten nonexistent URL prefix' do
      simple_backup_download('/etc/passwd', 'TARGETURI' => "#{simple_backup_prefix}/module-target-missing/")
    end
  else
    it 'does not report the fixed, absent or unrelated target as affected on either check' do
      2.times do
        output = simple_backup_refuse(action: 'check')
        expect(output).not_to include('appears to be vulnerable')
        expected = SimpleBackupProfiles.fetch.fetch('mode') == 'fixed' ? /not exploitable/i : /cannot reliably check exploitability/i
        expect(output).to match(expected)
      end
    end

    if SimpleBackupProfiles.fetch.fetch('mode') == 'fixed'
      it 'preserves legitimate confined backup downloads on both runs' do
        2.times { simple_backup_download('module-target-backup.txt', 'DEPTH' => 0) }
      end
    end

    it 'does not save a file from either public scanner run' do
      2.times { expect(simple_backup_refuse).to include('Nothing was downloaded.') }
    end
  end
end
