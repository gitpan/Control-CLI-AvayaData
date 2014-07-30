#!/usr/bin/perl

use lib '.';
use strict;
use warnings;
use Test::More;
use IO::Interactive qw(is_interactive);

############################################################
# Overrides can be specified for variables in this section #
############################################################
my $TestMultiple	= 1;		# Set to 0 if you only want to test against one Avaya Data switch
my $ConnectionType	;
my $Timeout		= 10;		# seconds
my $ConnectionTimeout	= 15;		# seconds
my $ErrorMode		= 'return';	# always return, so we check outcome in this test script
my $InputLog		;# = 'avayadata.t.in';
my $OutputLog		;# = 'avayadata.t.out';
my $DumpLog		;# = 'avayadata.t.dump';
my $DebugLog		;# = 'avayadata.t.dbg';
my $Host		;
my $TcpPort		;
my $Username		;# = 'rwa';
my $Password		;# = 'rwa';
my $PublicKeyPath	;# = 'C:\Users\<user>\.ssh\id_dsa.pub';	# '/export/home/<user>/.ssh/id_dsa.pub'
my $PrivateKeyPath	;# = 'C:\Users\<user>\.ssh\id_dsa';	# '/export/home/<user>/.ssh/id_dsa'
my $Passphrase		;
my $Baudrate		;# = 9600;	# Baudrate to use for initial connection
my $UseBaudrate		;# = 'max';	# Baudrate to switch to during tests
my $Databits		= 8;	
my $Parity		= 'none';	
my $Stopbits		= 1;
my $Handshake		= 'none';
my $PromptCredentials	= 1;		# Test the module prompting for username/password 
my $Debug		= 0;
############################################################


sub prompt { # For interactive testing to prompt user
	my $varRef = shift;
	my $message = shift;
	my $default = shift;
	my $userInput;
	return if defined $$varRef; # Come out if variable already set
	print "\n", $message;
	chomp($$varRef = <STDIN>);
	print "\n";
	unless (length $$varRef) {
		if (defined $default) {
			$$varRef = $default;
			return;
		}
		done_testing();
		exit;
	}
}

sub attribute { # Read, test, print and return a attribute
	my ($cli, $attribute, $optional) = @_;
	my $displayValue;

	my $attribValue = $cli->attribute($attribute);
	if (!defined $attribValue) {
		$displayValue = '( undefined )';
	}
	elsif (!ref $attribValue) {
		$displayValue = '(' . $attribValue . ')';
	}
	elsif (ref $attribValue eq 'ARRAY') {
		if (scalar @$attribValue == 0 && $optional) {
			$displayValue = '( empty list )';
		}
		elsif (!defined $attribValue->[0] || ref $attribValue->[0] eq 'ARRAY') { # Port array
			foreach my $slot (0..$#{$attribValue}) {
				$displayValue .= "\nslot $slot: " . join(',', @{$attribValue->[$slot]}) if defined $attribValue->[$slot];
			}
			$displayValue = "( array ):" . $displayValue;
		}
		else { # Regular list
			$displayValue = '(list:' . join(',', @$attribValue) . ')';
		}
	}
	if ($optional) {
		ok( defined $displayValue, "Testing '$attribute' attribute $displayValue" );
	}
	else {
		ok( defined $attribValue && defined $displayValue, "Testing '$attribute' attribute $displayValue" );
	}
	return $attribValue;
}

BEGIN {
	use_ok( 'Control::CLI::AvayaData' ) || die "Bail out!";
}

my $modules =	((Control::CLI::AvayaData::useTelnet) ? "Net::Telnet $Net::Telnet::VERSION, ":'').
		((Control::CLI::AvayaData::useSsh)    ? "Net::SSH2 $Net::SSH2::VERSION, ":'').
		((Control::CLI::AvayaData::useSerial) ? ($^O eq 'MSWin32' ?
						"Win32::SerialPort $Win32::SerialPort::VERSION, ":
						"Device::SerialPort $Device::SerialPort::VERSION, "):
					      '');
chop $modules; # trailing space
chop $modules; # trailing comma

diag "Testing Control::CLI::AvayaData $Control::CLI::AvayaData::VERSION";
diag "Using Control::CLI $Control::CLI::VERSION";
diag "Available connection types to test with: $modules";

if (Control::CLI::AvayaData::useTelnet || Control::CLI::AvayaData::useSsh) {
	if (Control::CLI::AvayaData::useIPv6) {
		diag "Support for both IPv4 and IPv6";
	}
	else {
		diag "Only IPv4 support (install IO::Socket::IP for IPv6 support)";
	}
}

						##############################
unless (IO::Interactive::is_interactive) {	# Not an interactive session #
						##############################
	# Test Telnet constructor only
	my $cli = new Control::CLI::AvayaData(Use => 'TELNET', Errmode => 'return');
	ok( defined $cli, "Testing constructor for Telnet" );

	# Test isa
	isa_ok($cli, 'Control::CLI::AvayaData');

	diag "Once installed, to test connection to an Avaya Data device, please run test script avayadata.t manually and follow interactive prompts";
	done_testing();
	exit;
}

#####################################################
# For an interactive session we can test everything #
#####################################################

do {{ # Test loop, we keep testing until user satisfied

	my ($cli, $ok, $output, $output2, $result, $prompt, $lastPrompt, $more_prompt, $familyType, $acli, $masterCpu, $dualCpu, $cmd, $origBaudrate);
	my ($connectionType, $username, $password, $host, $tcpPort, $baudrate, $useBaudrate)
	 = ($ConnectionType, $Username, $Password, $Host, $TcpPort, $Baudrate, $UseBaudrate);

	# Test constructor
	prompt(\$connectionType, "Select connection type to test\n [enter string: telnet|ssh|<COM-port-name>; or just ENTER to end test]\n : ");
	$cli = new Control::CLI::AvayaData(
			Use			=> $connectionType,
			Prompt_Credentials	=> $PromptCredentials,	# optional, default = 0 (no)
		  	Timeout 		=> $Timeout,		# optional; default timeout = 10 secs
		  	Connection_timeout	=> $ConnectionTimeout,	# optional; default is not set
			Errmode 		=> $ErrorMode,		# optional; default = 'croak'
			Input_log		=> $InputLog,
			Output_log		=> $OutputLog,
			Dump_log		=> $DumpLog,
			Debug			=> $Debug,
			Debug_file		=> $DebugLog,
		);
	ok( defined $cli, "Testing constructor for '$connectionType'" );
	if (!defined $cli && $connectionType !~ /^(?i:TELNET|SSH)$/) {
		diag "Cannot open serial port provided";
		redo;
	}

	# Test isa
	isa_ok($cli, 'Control::CLI::AvayaData');

	# Test/Display connection type
	$connectionType = $cli->connection_type;
	ok( $connectionType, "Testing connection type = $connectionType" );

	# Test connection to switch
	if ($connectionType =~ /^(?i:TELNET|SSH)$/) {
		if (!defined $host) {
			my $complexInput;
			prompt(\$host, "Provide an Avaya Data device IP|hostname to test with (no config commands will be executed);\n [[username][:password]@]<host|IP> [port]; ENTER to end test]\n : ");
			if ($host =~ s/^(.+)@//) {
				($username, $password) = split(':', $1);
				undef $username unless length $username;
				undef $password unless length $password;
				print "Username = ", $username, "\n" if defined $username;
				print "Password = ", $password, "\n" if defined $password;
				$complexInput = 1;
			}
			if ($host =~ /^(\S+)\s+(\d+)$/) {
				($host, $tcpPort) = ($1, $2);
				$complexInput = 1;
			}
			if ($complexInput) {
				print "Host = ", $host, "\n" if defined $host;
				print "Port = ", $tcpPort, "\n" if defined $tcpPort;
				print "\n";
			}
		}
	}
	else {
		prompt(\$baudrate, "Specify baudrate to use for initial connection [just ENTER for 9600 baud]: ", 9600);
		prompt(\$useBaudrate, "Baudrate to use for tests ('max' to use fastest possible) [just ENTER to stay @ $baudrate baud]: ", $baudrate);
	}

	$ok = $cli->connect(
			Host			=>	$host,			# mandatory, telnet & ssh
			Port			=>	$tcpPort,		# optional, only telnet & ssh
			Username		=>	$username,		# optional (with PromptCredentials=1 will be prompted for, if required)
			Password		=>	$password,		# optional (with PromptCredentials=1 will be prompted for, if required)
			PublicKey		=>	$PublicKeyPath,		# optional, only ssh
			PrivateKey		=>	$PrivateKeyPath,	# optional, only ssh
			Passphrase		=>	$Passphrase,		# optional, only ssh  (with PromptCredentials=1 will be prompted for, if required)
			BaudRate		=>	$baudrate,		# optional, only serial
			DataBits		=>	$Databits,		# optional, only serial
			Parity			=>	$Parity,		# optional, only serial
			StopBits		=>	$Stopbits,		# optional, only serial
			Handshake		=>	$Handshake,		# optional, only serial
		);
	ok( $ok, "Testing connection & login" );
	unless ($ok) {
		diag $cli->errmsg;
		redo;
	}

	# Verify last prompt is recorded
	$lastPrompt = $cli->last_prompt;
	ok( $lastPrompt, "Checking last_prompt is set" );
	diag "First prompt after login : $lastPrompt";

	# Test automatic locking on device prompt
	$prompt = $cli->prompt;
	ok( $prompt !~ /^[\n\x0d]/, "Checking autoset prompt" );
	diag "Automatically set prompt (inside =-> <-=):\n=->$prompt<-=";

	# Test automatic locking on device more-prompt
	$more_prompt = $cli->more_prompt;
	ok( $more_prompt, "Checking autoset --more-- prompt" );
	diag "Automatically set --more-- prompt (inside =-> <-=):\n=->$more_prompt<-=";

	# Test family_type attribute
	$familyType = attribute($cli, 'family_type');
	isnt( $familyType, 'generic', "Testing that an Avaya Data product was detected" );
	if ($familyType eq 'generic') {
		$cli->disconnect;
		redo;
	}

	if ($connectionType =~ /^(?i:SERIAL)$/ && $useBaudrate ne $baudrate) {

		# We try and switch to a different baudrate
		$origBaudrate = $baudrate;
		$baudrate = $cli->change_baudrate($useBaudrate);
		ok( ($useBaudrate eq 'max' && $baudrate) || $baudrate == $useBaudrate, "Testing change_baudrate() method" );
		diag "Switched connection to $baudrate baud" if ($useBaudrate eq 'max' && $baudrate) || $baudrate == $useBaudrate;
		diag $cli->errmsg unless defined $baudrate;
	}

	# Test enabling more paging on device (except on PassportERS Standby CPUs)
	# - More paging is usually already enabled on device
	# - This test is to check that device_more_paging() behaves correctly before attribute 'model' is set 
	unless ($familyType eq 'PassportERS' && !$cli->attribute('is_master_cpu')) {
		$ok = $cli->device_more_paging(1);
		ok( $ok, "Testing device_more_paging(1) method");
		diag $cli->errmsg unless $ok;
	}

	# Test global attributes
	attribute($cli, 'model',1); # might be undefined if executed on a Standby CPU
	attribute($cli, 'sysname',1); # might be undefined if executed on a Standby CPU
	attribute($cli, 'base_mac',1); # might be undefined (if executed on a Standby CPU or some products)
	$acli = attribute($cli, 'is_acli');
	attribute($cli, 'sw_version');
	attribute($cli, 'fw_version',1); # might be undefined (VSP9000)
	attribute($cli, 'slots',1); # might be undefined on standalone BaystackERS / WLAN2300
	attribute($cli, 'ports',1); # might be undefined if executed on a Standby CPU

	# Test family_type specific attributes
	if ($familyType eq 'PassportERS') {
		$masterCpu = attribute($cli, 'is_master_cpu');
		$dualCpu = attribute($cli, 'is_dual_cpu');
		attribute($cli, 'cpu_slot');
		attribute($cli, 'is_ha',1); # might be undefined
		attribute($cli, 'stp_mode');
	}
	elsif ($familyType eq 'BaystackERS') {
		if ('Stack' eq attribute($cli, 'switch_mode')) {
			attribute($cli, 'base_unit');
			attribute($cli, 'unit_number');
		}
		attribute($cli, 'stp_mode');
	}

	# Test 'all' attribute
	attribute($cli, 'all');

	# Test entering privExec mode (not applicable on some product / CLI modes)
	$ok = $cli->enable;
	ok( $ok, "Testing enable() method" );
	unless ($ok) {
		diag $cli->errmsg;
		$cli->disconnect;
		redo;
	}

	# Verify last prompt is recorded
	$lastPrompt = $cli->last_prompt;
	ok( $lastPrompt, "Checking last_prompt is set" );
	diag "New prompt after enable (PrivExec) : $lastPrompt";

	unless ($familyType eq 'WLAN2300') { # Skip this test for WLAN2300 as it has no config context

		# Test entering config mode (not applicable on some product / CLI modes)
		if    ( ($familyType eq 'PassportERS' && !$acli) || $familyType eq 'Accelar') {
			$result = $cli->cmd(
					Command			=>	'config',
					Return_result		=>	1,
				);
		}
		elsif ( ($familyType eq 'PassportERS' && $acli) || $familyType eq 'BaystackERS') {
			$result = $cli->cmd_prompted(
					Command			=>	'config',
					Feed			=>	'terminal',
					Return_result		=>	1,
				);
		}
		elsif ($familyType eq 'SecureRouter') {
			$result = $cli->cmd(
					Command			=>	'config term',
					Return_result		=>	1,
				);
		}

		ok( defined $result, "Checking that cmd() returns a defined value for result" );
		ok( $result, "Testing entering config context" );
		diag $cli->errmsg unless defined $result;
		if ($result) { # If we made it into config mode

			# Test obtaining the config context
			$result = $cli->config_context;
			ok( $result, "Testing config_context method" );
			diag "Correctly detected config context:$result" if $result;
	
			# Test coming out of config mode
			if    ( ($familyType eq 'PassportERS' && !$acli) || $familyType eq 'Accelar') {
				$result = $cli->cmd(
						Command			=>	'box',
						Return_result		=>	1,
					);
			}
			else {
				$result = $cli->cmd(
						Command			=>	'end',
						Return_result		=>	1,
					);
			}
			ok( defined $result, "Checking that cmd() returns a defined value for result" );
			ok( $result, "Testing leaving config context" );
			diag $cli->errmsg unless defined $result;
		}
        }

	# Test sending a show command like 'show sys info', with more paging enabled
	if    ( ($familyType eq 'PassportERS' && !$acli) || $familyType eq 'Accelar') {
		$cmd = 'show sys info';
	}
	elsif ( ($familyType eq 'PassportERS' && $acli) || $familyType eq 'BaystackERS') {
		$cmd = 'show sys-info';
	}
	elsif ($familyType eq 'SecureRouter') {
		$cmd = 'show chassis';
	}
	elsif ($familyType eq 'WLAN2300') {
		$cmd = 'show system';
	}
	$output = $cli->cmd(
			Command			=>	$cmd,
			Return_reference	=>	0,
			Return_result		=>	0,
		);
	ok( defined $output, "Checking that cmd() returns a defined value for output" );
	ok( length $output, "Testing cmd() method with more paging enabled" );
	diag "Obtained output of command '$cmd':\n$output" if length $output;
	diag $cli->errmsg unless defined $output;

	# Test disabling more paging on device (except on PassportERS Standby CPUs)
	unless ($familyType eq 'PassportERS' && !$masterCpu) {
		$ok = $cli->device_more_paging(0);
		ok( $ok, "Testing device_more_paging(0) method");
		diag $cli->errmsg unless $ok;
	}

	if ($ok && !($familyType eq 'PassportERS' && !$masterCpu) ) { # If we disabled more paging above...

		# Test sending same show command as above ('show sys info'), with more paging disabled
		$output2 = $cli->cmd(
				Command			=>	$cmd,
				Return_reference	=>	0,
				Return_result		=>	0,
			);
		ok( defined $output2, "Checking that cmd() returns a defined value for output" );
		ok( length $output2, "Testing cmd() method with more paging disabled" );
		diag $cli->errmsg unless defined $output2;

		if (length $output2 && length $output) { # Compare both outputs if we have them
			ok( length($output) == length($output2), "Testing that 1st & 2nd output of same command is of same length");
			unless ( length $output == length $output2 ) {
				open(OUTPUT1, '>', 'output1.txt') and print OUTPUT1 $output;
				open(OUTPUT2, '>', 'output2.txt') and print OUTPUT2 $output2;
				close OUTPUT1;
				close OUTPUT2;
				diag "Outputs saved as 'output1.txt' & 'output2.txt'";
			}
		}
	}

	# Send an invalid command; test that device syntax error is captured by cmd() method
	$result = $cli->cmd(
			Command			=>	'non_existent_command_to_cause_error_on_host',
			Return_result		=>	1,
		);
	ok( defined $result, "Checking that cmd() returns a defined value for result" );
	ok( !$result, "Testing cmd() method return_result" );
	diag $cli->errmsg unless defined $result;
	$output = $cli->last_cmd_errmsg;
	ok( $output, "Testing last_cmd_errmsg() method" );
	diag "Correctly detected device error message:\n$output" if length $output;

	if ($dualCpu) { # Test ability to connect to other CPU
		$ok = $cli->device_peer_cpu(
			Username		=>	$username,	# might be needed if connecting via serial port, and no login was done to start with
			Password		=>	$password,	# might be needed if connecting via serial port, and no login was done to start with
		);
		ok( $ok, "Testing device_peer_cpu() method");
		diag $cli->errmsg unless $ok;

		if ($ok) { # Come back to 1st CPU
			$prompt = $cli->last_prompt;
			diag "Peer CPU prompt : $prompt";
			ok( $lastPrompt ne $prompt, "Testing that we have a different prompt on peer CPU");

			# Now logout
			$result = $cli->cmd(Command => 'logout', Reset_prompt => 1, Return_result => 1);
			ok( $result, "Testing logout from peer CPU");
			diag $cli->errmsg unless defined $result;
			if ($result) {
				$prompt = $cli->last_prompt;
				diag "Back to 1st CPU prompt : $prompt";
				ok( $lastPrompt eq $prompt, "Testing that we have again the original prompt");
			}
		}
		
	}

	if ($connectionType =~ /^(?i:SERIAL)$/ && defined $origBaudrate) {

		# We retore the baudrate we used initially
		$baudrate = $cli->change_baudrate($origBaudrate);
		ok( $baudrate == $origBaudrate, "Testing that the original $origBaudrate baud was restored" );
		diag "Restored original baudrate of $baudrate baud" if $baudrate == $origBaudrate;
		diag $cli->errmsg unless defined $baudrate;
	}

	# Disconnect from host, and resume loop for further tests
	$cli->disconnect;

}} while ($TestMultiple);

done_testing();
