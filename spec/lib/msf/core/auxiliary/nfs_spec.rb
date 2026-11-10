# -*- coding: binary -*-

require 'spec_helper'
require 'json'

RSpec.describe Msf::Auxiliary::Nfs do
  subject do
    mod = Msf::Module.new
    mod.extend(Msf::Auxiliary::Nfs)
    mod
  end

  context '#can_mount?' do
    it 'deals with astericks' do
      expect(subject.can_mount?(['*'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with empty' do
      expect(subject.can_mount?([''], true, 'my.hostname', '1.1.1.1')).to be false
    end

    it 'deals with my IP' do
      expect(subject.can_mount?(['1.1.1.1'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with not my IP' do
      expect(subject.can_mount?(['2.2.2.2'], true, 'my.hostname', '1.1.1.1')).to be false
    end

    it 'correctly handles lists' do
      expect(subject.can_mount?(['2.2.2.2/255.255.255.0', '1.1.1.1/255.255.255.0'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with my IP with subnet' do
      expect(subject.can_mount?(['1.1.1.1/255.255.255.0'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with not my IP with subnet' do
      expect(subject.can_mount?(['2.2.2.2/255.255.255.0'], true, 'my.hostname', '1.1.1.1')).to be false
    end

    it 'deals with my IP with cidr' do
      expect(subject.can_mount?(['1.1.1.1/24'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'deals with not my IP with cidr' do
      expect(subject.can_mount?(['2.2.2.2/24'], true, 'my.hostname', '1.1.1.1')).to be false
    end

    it 'exact hostname' do
      expect(subject.can_mount?(['my.hostname'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'bad hostname' do
      expect(subject.can_mount?(['not.my.hostname'], true, 'foo.bar', '1.1.1.1')).to be false
    end

    it 'hostname with wildcard' do
      expect(subject.can_mount?(['*.hostname'], true, 'my.hostname', '1.1.1.1')).to be true
    end

    it 'bad hostname with wildcard' do
      expect(subject.can_mount?(['*.not.my.hostname'], true, 'foo.bar', '1.1.1.1')).to be false
    end

    context 'with captured UNFS3 0.11.0 exports' do
      let(:exports) do
        fixture = File.expand_path('../../../../fixtures/msf/core/auxiliary/nfs/unfs3_export.json', __dir__)
        JSON.parse(File.read(fixture)).fetch('exports').to_h
      end

      it 'recognizes the unrestricted public export with an outside address and nonblank hostname' do
        expect(subject.can_mount?(exports.fetch('/exports/open'), true, 'client.example', '192.0.2.3')).to be true
      end

      it 'recognizes the unrestricted read-only export without implying write access' do
        expect(subject.can_mount?(exports.fetch('/exports/read-only'), true, 'client.example', '192.0.2.3')).to be true
      end

      it 'keeps the captured restricted export unavailable to the outside address' do
        expect(subject.can_mount?(exports.fetch('/exports/denied'), true, 'client.example', '192.0.2.3')).to be false
      end

      it 'preserves the explicit heuristic bypass for a denied export' do
        expect(subject.can_mount?(exports.fetch('/exports/denied'), false, 'client.example', '192.0.2.3')).to be true
      end

      it 'does not infer unrestricted access from an empty group list' do
        expect(subject.can_mount?([], true, 'client.example', '192.0.2.3')).to be false
      end

      it 'preserves legacy matching of a blank group and blank hostname' do
        expect(subject.can_mount?([''], true, '', '192.0.2.3')).to be true
      end

      it 'does not treat a derived near-match as the native unrestricted marker' do
        expect(subject.can_mount?(['<anon clnt>x'], true, 'client.example', '192.0.2.3')).to be false
      end
    end
  end
end
