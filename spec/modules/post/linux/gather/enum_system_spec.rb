require 'rspec'

RSpec.describe 'Linux system cron collection' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject(:mod) { load_and_create_module(module_type: 'post', reference_name: 'linux/gather/enum_system') }

  let(:root_cron) { "# module-target-root-cron\n7 3 * * * /usr/bin/printf root-cron-proof > /dev/null\n" }
  let(:user_cron) { "# module-target-user-cron\n8 3 * * * /usr/bin/printf user-cron-proof > /dev/null\n" }

  before do
    allow(mod).to receive(:vprint_status)
  end

  describe '#get_crons' do
    context 'when running as root' do
      it 'returns the collected cron data for every account as text' do
        expect(mod).to receive(:execute).with('crontab -u root -l').and_return(root_cron)
        expect(mod).to receive(:execute).with('crontab -u labuser -l').and_return(user_cron)

        expect(mod.get_crons("root\nlabuser\n", 'root')).to eq(
          "*****Listing cron jobs for root*****\n#{root_cron}\n\n" \
          "*****Listing cron jobs for labuser*****\n#{user_cron}\n\n"
        )
      end

      it 'keeps an empty cron result in the account section' do
        expect(mod).to receive(:execute).with('crontab -u root -l').and_return('')

        expect(mod.get_crons("root\n", 'root')).to eq("*****Listing cron jobs for root*****\n\n\n")
      end

      it 'returns empty text without executing a command for an empty account list' do
        expect(mod).not_to receive(:execute)

        expect(mod.get_crons('', 'root')).to eq('')
      end

      it 'collects the supplied accounts even when the list omits root' do
        expect(mod).to receive(:execute).with('crontab -u labuser -l').and_return(user_cron)

        expect(mod.get_crons("labuser\n", 'root')).to eq("*****Listing cron jobs for labuser*****\n#{user_cron}\n\n")
      end

      it 'retains current-user collection when the account list is unavailable' do
        expect(mod).to receive(:execute).with('crontab -l').and_return(root_cron)

        expect(mod.get_crons(nil, 'root')).to eq("***** Listing cron jobs for root *****\n\n#{root_cron}")
      end
    end

    context 'when running as an unprivileged user' do
      it 'collects only the current account regardless of the supplied account list' do
        expect(mod).to receive(:execute).with('crontab -l').and_return(user_cron)

        expect(mod.get_crons("root\nlabuser\n", 'labuser')).to eq("***** Listing cron jobs for labuser *****\n\n#{user_cron}")
      end

      it 'keeps the current account section when no cron data is returned' do
        expect(mod).to receive(:execute).with('crontab -l').and_return('')

        expect(mod.get_crons(nil, 'labuser')).to eq("***** Listing cron jobs for labuser *****\n\n")
      end
    end
  end
end
