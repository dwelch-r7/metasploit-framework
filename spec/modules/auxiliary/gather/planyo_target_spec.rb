require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/planyo/acceptance'

RSpec.describe 'Native Planyo file collection', acceptance: true, order: :defined do
  include_context 'native Planyo target'

  profile = PlanyoProfiles.fetch
  if %w[affected inactive].include?(profile.fetch('mode'))
    %w[default text binary empty special].each do |name|
      it "saves the exact native #{name} file on both runs" do
        2.times { planyo_download(name) }
      end
    end

    %w[missing denied].each do |name|
      it "refuses the native #{name} file twice without creating loot" do
        2.times do
          expect(planyo_refuse('FILEPATH' => PlanyoProfiles::FILES.fetch(name).fetch('path'))).to match(/HTTP status: 500.*LFI/)
        end
      end
    end

    if ENV.fetch('PLANYO_PROFILE', 'planyo') == 'planyo'
      it 'preserves literal percent, plus, query and quote characters twice' do
        2.times { planyo_download('encoded_literal') }
      end

      it 'refuses a wrong WordPress installation path twice' do
        2.times { expect(planyo_refuse('TARGETURI' => '/module-target-missing/')).to include('Server not online or not detected as wordpress') }
      end

      it 'rejects a blank filename twice before attempting collection' do
        2.times { expect(planyo_refuse('FILEPATH' => '')).to include('Please supply the name of the file you want to download') }
      end
    end
  else
    it 'refuses collection twice without saving any loot' do
      expected = case profile.fetch('mode')
                 when 'fixed' then /This version of plugin is not vulnerable/
                 when 'absent' then /readme.txt or it could not be found/
                 else /Server not online or not detected as wordpress/
                 end
      2.times { expect(planyo_refuse).to match(expected) }
    end
  end
end
