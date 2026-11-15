# frozen_string_literal: true

# One table drives native service selection and the unchanged acceptance cases.
module WordPressAdminProfiles
  GROUP = 'Native WordPress administrator upload targets'
  STAGED_PAYLOAD = 'php/meterpreter/reverse_tcp'
  STAGED_SEED = 7721

  def self.installation_examples(service)
    [
      "recognizes the actual #{service} administrator's upload access",
      "does not report #{service} upload access with wrong password",
      "does not report #{service} upload access with absent account",
      "does not report #{service} editor authentication alone as plugin-upload capability",
      "does not report #{service} subscriber authentication alone as plugin-upload capability",
      "executes the #{service} non-session PHP payload twice with explicit operator cleanup",
      "opens php/reverse_php twice on #{service} and removes each uploaded plugin",
      "opens #{STAGED_PAYLOAD} twice on #{service} and removes each uploaded plugin",
      "opens php/meterpreter_reverse_tcp twice on #{service} and removes each uploaded plugin"
    ]
  end

  def self.staged_example(service)
    "opens #{STAGED_PAYLOAD} twice on #{service} and removes each uploaded plugin"
  end

  def self.denied_example(service, user)
    "does not upload or execute with denied #{service}/#{user} credentials or permissions"
  end

  PROFILES = {
    'root' => {
      wordpress: { 'root' => '' }, unrelated: false,
      examples: installation_examples('root') - [staged_example('root')] + %w[module_admin module_editor module_subscriber].map { |user| denied_example('root', user) }
    },
    'prefix' => {
      wordpress: { 'prefix' => '/wordpress' }, unrelated: false,
      examples: installation_examples('prefix') - [staged_example('prefix')]
    },
    'locked' => {
      wordpress: { 'locked' => '' }, unrelated: false,
      examples: ['does not claim upload access when WordPress disables administrator file modifications', denied_example('locked', 'module_admin')]
    },
    'unrelated' => {
      wordpress: {}, unrelated: true,
      examples: ['does not identify unrelated HTTP as an administrator upload target', denied_example('unrelated', 'module_admin')]
    },
    'root_staged' => {
      wordpress: { 'root' => '' }, unrelated: false, seed: STAGED_SEED,
      examples: [staged_example('root')]
    },
    'prefix_staged' => {
      wordpress: { 'prefix' => '/wordpress' }, unrelated: false, seed: STAGED_SEED,
      examples: [staged_example('prefix')]
    }
  }.freeze

  def self.roles(profile)
    services = profile.fetch(:wordpress).keys
    services = ['db', *services] unless services.empty?
    services << 'unrelated' if profile.fetch(:unrelated)
    [*services, 'framework']
  end

  def self.fetch(name)
    PROFILES.fetch(name) { raise ArgumentError, "Unknown WordPress administrator profile: #{name}" }
  end
end
