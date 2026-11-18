require 'msfenv'
require 'msf/base'
require 'json'
require 'rex/text'

RSpec.describe Msf::Auxiliary::Osticket do
  subject(:mod) { Msf::Auxiliary.new.extend(described_class) }

  let(:captures) { JSON.parse(File.binread(File.expand_path('../../../../file_fixtures/osticket/ticket-identity.json', __dir__))) }
  let(:listing) { response(captures.fetch('staff_listing').fetch('html')) }
  let(:staff_ticket) { response(captures.fetch('staff_ticket').fetch('html')) }
  let(:client_ticket) { response(captures.fetch('client_ticket').fetch('html')) }
  let(:empty_listing) { response('<table id="tickets"></table>') }

  before do
    allow(mod).to receive(:vprint_status)
    allow(mod).to receive(:vprint_good)
    allow(mod).to receive(:vprint_error)
  end

  def response(html, code: 200)
    Rex::Proto::Http::Response.new(code).tap { |res| res.body = html }
  end

  describe '#find_ticket_id' do
    it 'associates the requested number with its own link instead of an earlier ticket row' do
      allow(mod).to receive(:send_request_cgi).and_return(listing)

      expect(mod.find_ticket_id('/', '/scp', '201891', 'fixture-cookie', 0)).to eq('9')
    end

    it 'retains the first ticket identity when it is actually requested' do
      allow(mod).to receive(:send_request_cgi).and_return(listing)

      expect(mod.find_ticket_id('/', '/scp', '320794', 'fixture-cookie', 0)).to eq('1')
    end

    it 'does not accept a visible ticket number prefix' do
      allow(mod).to receive(:send_request_cgi).and_return(listing)

      expect(mod.find_ticket_id('/', '/scp', '20189', 'fixture-cookie', 0)).to be_nil
    end

    it 'does not accept an empty visible ticket number' do
      allow(mod).to receive(:send_request_cgi).and_return(listing)

      expect(mod.find_ticket_id('/', '/scp', '', 'fixture-cookie', 0)).to be_nil
    end

    it 'does not search when the listing request has no response' do
      allow(mod).to receive(:send_request_cgi).and_return(nil)

      expect(mod.find_ticket_id('/', '/scp', '201891', 'fixture-cookie', 9)).to be_nil
      expect(mod).to have_received(:send_request_cgi).once
    end

    it 'does not resolve a non-successful ticket listing' do
      allow(mod).to receive(:send_request_cgi).and_return(response(listing.body, code: 403))

      expect(mod.find_ticket_id('/', '/scp', '201891', 'fixture-cookie', 0)).to be_nil
    end

    it 'matches the actual staff ticket heading during the bounded fallback' do
      allow(mod).to receive(:send_request_cgi).and_return(empty_listing, nil, nil, nil, nil, nil, nil, nil, nil, staff_ticket)

      expect(mod.find_ticket_id('/', '/scp', '201891', 'fixture-cookie', 9)).to eq('9')
    end

    it 'matches the actual client ticket heading during the bounded fallback' do
      allow(mod).to receive(:send_request_cgi).and_return(empty_listing, nil, client_ticket)

      expect(mod.find_ticket_id('/', '', '325258', 'fixture-cookie', 2)).to eq('2')
    end

    it 'does not treat a number mentioned in ticket content as the displayed staff identity' do
      # Derived from the native heading by adding unrelated reply content.
      page = response(staff_ticket.body + '<div class="thread-entry">Requested ticket #999999</div>')
      allow(mod).to receive(:send_request_cgi).and_return(empty_listing, page)

      expect(mod.find_ticket_id('/', '/scp', '999999', 'fixture-cookie', 1)).to be_nil
    end

    it 'does not treat a number mentioned in ticket content as the displayed client identity' do
      # Derived from the native heading by adding unrelated reply content.
      page = response(client_ticket.body + '<div class="thread-entry">Requested ticket #999999</div>')
      allow(mod).to receive(:send_request_cgi).and_return(empty_listing, page)

      expect(mod.find_ticket_id('/', '', '999999', 'fixture-cookie', 1)).to be_nil
    end

    it 'rejects a different internal ID even when the heading has the requested visible number' do
      allow(mod).to receive(:send_request_cgi).and_return(empty_listing, staff_ticket)

      expect(mod.find_ticket_id('/', '/scp', '201891', 'fixture-cookie', 1)).to be_nil
    end

    it 'does not mistake a ticket listing returned by an inaccessible ID for a ticket detail page' do
      allow(mod).to receive(:send_request_cgi).and_return(empty_listing, listing)

      expect(mod.find_ticket_id('/', '/scp', '201891', 'fixture-cookie', 1)).to be_nil
    end

    it 'preserves the installed URL prefix for matching and requests' do
      # Native listing variant: the same deployment installed below /support.
      page = response(listing.body.gsub('/scp/tickets.php', '/support/scp/tickets.php'))
      allow(mod).to receive(:send_request_cgi).and_return(page)

      expect(mod.find_ticket_id('/support/', '/scp', '201891', 'fixture-cookie', 0)).to eq('9')
      expect(mod).to have_received(:send_request_cgi).with(hash_including('uri' => '/support/scp/tickets.php'))
    end
  end
end
