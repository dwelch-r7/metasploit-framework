require 'spec_helper'
require 'msfenv'
require 'msf/base'
require 'timeout'

RSpec.describe Msf::Handler do
  subject(:handler) do
    klass = Class.new(Msf::Payload)
    klass.include described_class
    klass.framework = framework
    klass.new
  end

  let(:events) { double('Events', on_session_open: nil, on_exploit_success: nil) }
  let(:session_manager) { double('Session manager', register: nil) }
  let(:framework) { double('Framework', datastore: Msf::DataStore.new, sessions: session_manager, events: events) }
  let(:session) { double('Session', bootstrap: nil, alive: true, process_autoruns: nil) }
  let(:event) { handler.send(:session_waiter_event) }

  before do
    handler.send(:pending_connections=, 1)
    allow(handler).to receive(:on_session)
    allow(handler).to receive(:assoc_exploit).and_return(nil)
  end

  after do
    Array(@waiters).each do |waiter|
      waiter.kill if waiter.alive?
      waiter.join
    end
  end

  def register(current = session)
    handler.send(:register_session, current)
  end

  # Coordinate on the real event's first timeout rather than sleeping until an
  # estimated bootstrap deadline. Afterwards the worker has only its pending
  # registration wait to enter, so a sleeping thread has reached that wait.
  def extended_waiters(count = 1)
    timed_out = Queue.new
    allow(event).to receive(:wait).and_wrap_original do |original, *arguments|
      original.call(*arguments)
    rescue Timeout::Error
      timed_out << Thread.current
      raise
    end
    @waiters = Array.new(count) do
      Thread.new { handler.wait_for_session(0.01) }.tap { |waiter| waiter.report_on_exception = false }
    end
    Timeout.timeout(2) { count.times { timed_out.pop } }
    Timeout.timeout(2) { Thread.pass until @waiters.all? { |waiter| waiter.status == 'sleep' } }
    @waiters
  end

  describe '#register_session' do
    it 'releases the pending connection after successful registration' do
      register

      expect(handler.send(:pending_connections)).to eq(0)
    end

    it 'counts a successfully opened session' do
      register

      expect(handler.send(:sessions)).to eq(1)
    end

    it 'notifies the handler and framework of a successful session' do
      register

      expect(events).to have_received(:on_session_open).with(session)
      expect(handler).to have_received(:on_session).with(session)
    end

    it 'returns the successfully registered session to a waiter' do
      register

      expect(handler.wait_for_session(0.01)).to equal(session)
    end

    it 'still registers session types without a bootstrap method' do
      plain_session = double('Session without bootstrap')
      register(plain_session)

      expect(handler.wait_for_session(0.01)).to equal(plain_session)
    end

    context 'when bootstrap closes the session' do
      before do
        allow(session).to receive(:alive).and_return(false)
      end

      it 'releases the pending connection' do
        register

        expect(handler.send(:pending_connections)).to eq(0)
      end

      it 'does not count the closed session as successful' do
        register

        expect(handler.send(:sessions)).to eq(0)
      end

      it 'does not publish a session-open event' do
        register

        expect(events).not_to have_received(:on_session_open)
      end

      it 'does not signal a failed result during the original grace period' do
        allow(event).to receive(:notify).and_call_original
        register

        expect(event).not_to have_received(:notify)
      end

      it 'does not enter an indefinite wait after the failed registration' do
        register

        expect(Timeout.timeout(1) { handler.wait_for_session(0.01) }).to be_nil
      end

      it 'releases a waiter that already extended its initial timeout' do
        waiter = extended_waiters.first
        register

        expect(waiter.join(1)).to equal(waiter)
        expect(waiter.value).to be_nil
      end

      it 'releases all extended waiters when the last connection fails' do
        waiters = extended_waiters(2)
        register

        expect(waiters.map { |waiter| waiter.join(1)&.value }).to eq([nil, nil])
        expect(waiters).not_to include(an_object_having_attributes(alive?: true))
      end
    end

    context 'when bootstrap raises EOFError' do
      let(:failure) { EOFError.new('The peer closed during session bootstrap') }

      before do
        allow(session).to receive(:bootstrap).and_raise(failure)
      end

      it 'preserves the bootstrap exception for the scheduler' do
        expect { register }.to raise_error(failure)
      end

      it 'releases the pending connection even though bootstrap raised' do
        begin
          register
        rescue EOFError
          nil
        end

        expect(handler.send(:pending_connections)).to eq(0)
      end

      it 'releases an already extended waiter without announcing success' do
        waiter = extended_waiters.first
        expect { register }.to raise_error(failure)

        expect(waiter.join(1)).to equal(waiter)
        expect(waiter.value).to be_nil
      end
    end

    context 'with more than one pending connection' do
      let(:closed_session) { double('Closed session', bootstrap: nil, alive: false) }

      before do
        handler.send(:pending_connections=, 2)
      end

      it 'continues waiting after one failure until another connection succeeds' do
        waiter = extended_waiters.first
        register(closed_session)
        expect(waiter.join(0.02)).to be_nil
        register(session)

        expect(waiter.join(1)&.value).to equal(session)
      end

      it 'returns no session when both pending connections fail' do
        waiter = extended_waiters.first
        register(closed_session)
        register(closed_session)

        expect(waiter.join(1)).to equal(waiter)
        expect(waiter.value).to be_nil
      end

      it 'permits a valid connection later in the original wait window' do
        entered = Queue.new
        allow(event).to receive(:wait).and_wrap_original do |original, *arguments|
          entered << true
          original.call(*arguments)
        end
        @waiters = [Thread.new { handler.wait_for_session(1) }]
        Timeout.timeout(2) { entered.pop }
        register(closed_session)
        register(session)

        expect(@waiters.first.join(1)&.value).to equal(session)
      end
    end
  end

  describe '#interrupt_wait_for_session' do
    it 'still releases an extended waiter on explicit interruption' do
      waiter = extended_waiters.first
      handler.interrupt_wait_for_session

      expect(waiter.join(1)).to equal(waiter)
      expect(waiter.value).to be_nil
    end
  end
end
