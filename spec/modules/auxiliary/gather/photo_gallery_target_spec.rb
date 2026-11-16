require 'acceptance_spec_helper'
require_relative '../../../../test/module_targets/photo_gallery/acceptance'

RSpec.describe 'Native Photo Gallery credential gathering', acceptance: true, order: :defined do
  include_context 'native Photo Gallery target'

  profile = PhotoGalleryProfiles.fetch
  if profile.fetch('mode') == 'affected'
    it 'proves injection on repeated checks without saving credentials' do
      2.times { expect(pg_refusal(action: 'check')).to match(/The target is vulnerable/i) }
    end

    it 'saves the default complete credential set on both runs' do
      2.times { pg_success(count: 5) }
    end

    it 'saves all complete native credentials on both runs' do
      2.times { pg_success({ 'COUNT' => 0 }, count: 0) }
    end

    it 'limits saved credentials with AutoCheck disabled' do
      2.times { pg_success({ 'COUNT' => 2, 'AutoCheck' => false }, count: 2) }
    end

    it 'saves all native credentials twice with AutoCheck disabled' do
      2.times { pg_success({ 'COUNT' => 0, 'AutoCheck' => false }, count: 0) }
    end

    if ENV.fetch('PHOTO_GALLERY_PROFILE', 'photo_gallery') == 'photo_gallery'
      it 'gathers all credentials twice through a nondefault shortcode' do
        2.times { pg_success({ 'COUNT' => 0, 'SHORTCODE_ID' => 42 }, count: 0) }
      end

      it 'gathers all credentials twice when the gallery hides titles' do
        2.times { pg_success({ 'COUNT' => 0, 'SHORTCODE_ID' => 43 }, count: 0) }
      end

      it 'honors the selected installation path through check and AutoCheck' do
        options = { 'TARGETURI' => '/module-target-missing/' }
        expect(pg_refusal(options, action: 'check')).to match(/cannot reliably check exploitability/i)
        expect(pg_refusal(options)).to include('Auxiliary aborted due to failure:')
      end

      it 'does not treat a real PostgreSQL endpoint as a safe WordPress target' do
        2.times { expect(pg_refusal(action: 'check', service: 'reporting_db')).to match(/cannot reliably check exploitability/i) }
      end
    end
  else
    it 'returns a reason-bearing inconclusive check for the unavailable injection' do
      2.times { expect(pg_refusal(action: 'check')).to match(/cannot reliably check exploitability/i) }
    end

    it 'aborts both AutoCheck runs without saving credentials or loot' do
      2.times { expect(pg_refusal).to include('Auxiliary aborted due to failure:') }
    end

    it 'refuses both unprotected runs without saving credentials or loot' do
      2.times { expect(pg_refusal({ 'AutoCheck' => false })).to include('Auxiliary aborted due to failure:') }
    end
  end
end
