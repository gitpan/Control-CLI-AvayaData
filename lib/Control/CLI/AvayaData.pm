package Control::CLI::AvayaData;

use strict;
use warnings;
use Exporter qw( import );
use Carp;
use Control::CLI qw(:all);

my $Package = "Control::CLI::AvayaData";
our $VERSION = '1.00';
our @ISA = qw(Control::CLI);
our %EXPORT_TAGS = (
		use	=> [qw(useTelnet useSsh useSerial useIPv6)],
		_rest	=> [qw(promptClear promptHide parseMethodArgs suppressMethodArgs passphraseRequired parse_errmode)],
	);
push @{$EXPORT_TAGS{all}}, @{$EXPORT_TAGS{$_}} foreach keys %EXPORT_TAGS;
Exporter::export_ok_tags('use');

########################################### Global Class Variables ###########################################

my %LoginPatterns = ( # Patterns to check for during device login (Telnet/Serial) and initial connection to CLI
	bell		=>	"\x07",
	banner		=>	'Enter Ctrl-Y to begin',
	menu		=>	'Use arrow keys to highlight option, press <Return> or <Enter> to select option',
	submenu		=>	'Press Ctrl-R to return to previous menu.  Press Ctrl-C to return to Main Menu',
	username	=>	'Enter Username: ',
	password	=>	"Enter Password: \e",
	lastlogin	=>	'Failed retries since last login:',
	localfail	=>	'Incorrect',
	radiusfail	=>	'Access Denied from RADIUS',
	radiustimeout1	=>	'no response from RADIUS servers',
	radiustimeout2	=>	'No reply from RADIUS server',
	srbanner	=>	"\((?:Secure Router|VSP4K)",
	xlrbanner	=>	"\x0d************************************\n",
	ersbanner	=>	"\x0d* Ethernet Routing Switch",
	passportbanner	=>	"\x0d* Passport",
	vspbanner	=>	"All Rights Reserved.\n\x0dVirtual Services Platform",
	consoleLogMsg1	=>	"connected via console port", #On serial port: GlobalRouter SW INFO user rwa connected via console port
	consoleLogMsg2	=>	"Blocked unauthorized ACLI access",
	more1		=>	'----More (q=Quit, space/return=Continue)----',
	more2		=>	'--More--',
);
my %Prm = ( # Hash containing list of named parameters returned by attributes
	bstk	=>	'BaystackERS',
	pers	=>	'PassportERS',
	xlr	=>	'Accelar',
	sr	=>	'SecureRouter',
	trpz	=>	'WLAN2300',
	cli	=>	'cli',
	nnc	=>	'nncli',
	generic	=>	'generic',
);
my %Attribute = (
	Global		=> [
			'family_type',
			'model',
			'is_nncli',
			'is_acli',
			'sw_version',
			'fw_version',
			'slots',
			'ports',
			'sysname',
			'base_mac',
			],

	$Prm{pers}	=> [
			'is_master_cpu',
			'is_dual_cpu',
			'cpu_slot',
			'is_ha',
			'stp_mode',
			],

	$Prm{bstk}	=> [
			'unit_number',
			'base_unit',
			'switch_mode',
			'stack_size',
			'stp_mode',
			],

	$Prm{xlr}	=> [
			'is_master_cpu',
			'is_dual_cpu',
			],

);
my @InitPromptOrder = ("$Prm{pers}_cli", "$Prm{pers}_nncli", $Prm{bstk}, 'generic');
my %InitPrompt = ( # Initial prompt pattern expected at login
	$Prm{bstk}		=>	'\x0d?(.{1,50}?)()(?:\((.+?)\))?[>#]$',
	"$Prm{pers}_cli"	=>	'\x0d?(.+):([1356])((?:\/[\w\d-]+)*)[>#] $',
	"$Prm{pers}_nncli"	=>	'\x0d?(.+):([12356])(?:\((.+?)\))?[>#]$',
	$Prm{xlr}		=>	'\x0d?(.+?)()((?:\/[\w\d-]+)*)[>#] $',
	$Prm{sr}		=>	'\x0d? *\x0d(.+?)()((?:\/[\w\d\s-]+(?: \(\d+\/\d+\))?)*)# $',
	$Prm{trpz}		=>	'(.+)[>#] $',
	$Prm{generic}		=>	'.*[\?\$%#>]\s?$',
);
my %Prompt = ( # Prompt pattern templates; SWITCHNAME gets replaced with actual switch prompt during login
	$Prm{bstk}		=>	'SWITCHNAME(?:\((.+?)\))?[>#]$',
	"$Prm{pers}_cli"	=>	'SWITCHNAME:[1356]((?:\/[\w\d-]+)*)[>#] $',
	"$Prm{pers}_nncli"	=>	'SWITCHNAME:[12356](?:\((.+?)\))?[>#]$',
	$Prm{xlr}		=>	'SWITCHNAME((?:\/[\w\d-]+)*)[>#] $',
	$Prm{sr}		=>	'\x0d? *\x0dSWITCHNAME((?:\/[\w\d\s-]+(?: \(\d+\/\d+\))?)*)# $',
	$Prm{trpz}		=>	'SWITCHNAME[>#] $',
	generic			=>	'.*[\?\$%#>]\s?$',
);
my %MorePrompt = ( # The following characters are automatically backslashed in more_prompt(): ().
	$Prm{bstk}		=>	'----More (q=Quit, space/return=Continue)----',
	"$Prm{pers}_cli"	=>	'\n\x0d?--More-- (q = quit) ',
	"$Prm{pers}_nncli"	=>	'\n\x0d?--More-- (q = quit) |--More--',
	$Prm{xlr}		=>	'--More-- (q = quit) ',
	$Prm{sr}		=>	'Press any key to continue (q : quit) :\x00|Press any key to continue (q : quit \| enter : next line) :\x00',
	$Prm{trpz}		=>	'press any key to continue, q to quit.',
	generic			=>	'----More (q=Quit, space/return=Continue)----|--More-- (q = quit) |Press any key to continue (q : quit) :\x00|press any key to continue, q to quit.',
);
my %ErrorPatterns = ( # Patterns which indicated the last command sent generated a syntax error on the host device
	$Prm{bstk}		=>	'(\s+\^\n% Invalid input detected at \'\^\' marker\.|% Cannot modify settings\n%.+|% Bad (?:port|unit) number\.|% MLT \d+ does not exist or it is not enabled)',
	$Prm{pers}		=>	'(.+? not found in path .+|(?:parameter|object) .+? is out of range|(?:\s+\^)?\n% Invalid input detected at \'\^\' marker\.|\x07Error ?: .+|Unable to .+|% Not allowed on secondary cpu\.|% Incomplete command\.)',
	$Prm{xlr}		=>	'(.+? not found in path .+|(?:parameter|object) .+? is out of range)',
	$Prm{sr}		=>	'(\s+\^\nError : Command .+? does not exist|Config is locked by some other user)',
	$Prm{trpz}		=>	'(\s+\^\nUnrecognized command:.+|Unrecognized command in this mode:.+)',
);
my $LoginReadAttempts = 10;		# Number of read attempts for readwait() method used in login()
my $CmdPromptReadAttempts = 5;		# Number of read attempts for readwait() method used in _cmd()
my $CmdTimeoutRatio = 0.1;		# In cmd() if read times out, a 2nd read is attempted with timeout * this ratio 

my $Space = " ";
my $CTRL_C = "\cC";
my $CTRL_U = "\cU";
my $CTRL_X = "\cX";
my $CTRL_Y = "\cY";
my $CTRL_Z = "\cZ";

my %Default = ( # Hash of default object seetings which can be modified on a per object basis
	morePaging		=>	0,	# For --more-- prompt, number of pages accepted before sending q to quit
						# 0 = accept all pages; 1 = send q after 1st page, i.e. only 1 page; etc
	progressDots		=>	0,	# After how many bytes received, an activity dot is printed; 0 = disabled
	return_result		=>	0,	# Whether cmd methods return true/false result or output of command
	cmd_confirm_prompt	=>	'[\(\[] *(?:[yY](?:es)? *[\\\/] *[nN]o?|[nN]o? *[\\\/] *[yY](?:es)?) *[\)\]] *[?:] *$',	# Y/N prompt
	cmd_initiated_prompt	=>	'[?:=][ \t]*$',	# Prompt for additional user info
	cmd_feed_timeout	=>	10,	# Command requests for data, we have none, after X times we give up 
	wake_console		=>	"\n",	# Sequence to send when connecting to console to wake device
	debug			=>	0,	# Default debug level; see levels below
);

# Debug levels can be set using the debug() method or via debug argument to new() constructor
# Debug levels defined:
# 	0	: No debugging
# 	1	: Basic debugging
# 	2	: Extended debugging of login() & cmd() methods
# 	3	: Turn on debug level 1 on parent Control::CLI
# 	4	: Turn on debug level 2 on parent Control::CLI

################################################ Class Methods ###############################################

sub _stripLastLine { # Remove incomplete (not ending with \n) last line, if any from the string ref provided
	my $dataRef = shift;

	if (chomp $$dataRef) { # Yes, string ended with \n
		$$dataRef .= "\n"; # Re-add it
		return '';
	}
	else { # No, string does not end with \n
		$$dataRef =~ s/(.*)$//;
		return $1;
	}
}

############################################# Constructors/Destructors #######################################

sub new {
	my $pkgsub = "${Package}-new:";
	my $invocant = shift;
	my $class = ref($invocant) || $invocant;
	my (%args, %cliArgs);
	my $debugLevel = $Default{debug};
	if (@_ == 1) { # Method invoked with just the connection type argument
		$cliArgs{use} = shift;
	}
	else {
		my @validArgs = ('use', 'timeout', 'connection_timeout', 'errmode', 'return_reference', 'prompt',
				'username_prompt', 'password_prompt', 'input_log', 'output_log', 'dump_log',
				'blocking', 'debug', 'debug_file', 'prompt_credentials', 'read_attempts',
				'read_block_size', 'output_record_separator', 'return_result', 'more_prompt', 'more_paging',
				'cmd_confirm_prompt', 'cmd_initiated_prompt', 'cmd_feed_timeout', 'wake_console');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
		my @suppressArgs = ('prompt', 'return_result', 'more_prompt', 'more_paging', 'cmd_confirm_prompt',
				'cmd_initiated_prompt', 'cmd_feed_timeout', 'wake_console', 'debug', 'debug_file');
		%cliArgs = suppressMethodArgs(\@_, \@suppressArgs);
	}
	my $self = $class->SUPER::new(%cliArgs) or return;
	$self->{errmsg} = ''; # Set this to empty string to start with (is undef in Control::CLI)
	$self->{$Package} = {
		# Lower Case ones can be set by user; Upper case ones are set internaly in the class
		morePaging		=>	$Default{morePaging},
		progressDots		=>	$Default{progressDots},
		prompt			=>	undef,
		prompt_qr		=>	undef,
		morePrompt		=>	undef,
		morePrompt_qr		=>	undef,
		last_cmd_success	=>	undef,
		last_cmd_errmsg		=>	undef,
		return_result		=>	$Default{return_result},
		cmd_confirm_prompt	=>	$Default{cmd_confirm_prompt},
		cmd_confirm_prompt_qr	=>	qr/$Default{cmd_confirm_prompt}/,
		cmd_initiated_prompt	=>	$Default{cmd_initiated_prompt},
		cmd_initiated_prompt_qr	=>	qr/$Default{cmd_initiated_prompt}/,
		cmd_feed_timeout	=>	$Default{cmd_feed_timeout},
		wake_console		=>	$Default{wake_console},
		debug			=>	$debugLevel,		# Set debug level for this class
		debugFilename		=>	'',
		debugFilehandle		=>	undef,
		PROMPTTYPE		=>	undef,
		ENABLEPWD		=>	undef,
		ORIGBAUDRATE		=>	undef,
		ATTRIB			=>	undef,
		ATTRIBFLAG		=>	undef,
		CONFIGCONTEXT		=>	undef,
	};
	foreach my $arg (keys %args) { # Accepted arguments on constructor
		if    ($arg eq 'prompt')			{ $self->prompt($args{$arg}) }
		elsif ($arg eq 'return_result')			{ $self->return_result($args{$arg}) }
		elsif ($arg eq 'more_prompt')			{ $self->more_prompt($args{$arg}) }
		elsif ($arg eq 'more_paging')			{ $self->more_paging($args{$arg}) }
		elsif ($arg eq 'cmd_confirm_prompt')		{ $self->cmd_confirm_prompt($args{$arg}) }
		elsif ($arg eq 'cmd_initiated_prompt')		{ $self->cmd_initiated_prompt($args{$arg}) }
		elsif ($arg eq 'cmd_feed_timeout')		{ $self->cmd_feed_timeout($args{$arg}) }
		elsif ($arg eq 'wake_console')			{ $self->wake_console($args{$arg}) }
		elsif ($arg eq 'debug')				{ $self->debug($args{$arg}) }
		elsif ($arg eq 'debug_file')			{ $self->debug_file($args{$arg}) }
	}
	return $self;
}


sub DESTROY {
	my $self = shift;
	return $self->_restoreDeviceBaudrate if $self->connection_type eq 'SERIAL';
}


############################################### Object methods ###############################################

sub connect { # All the steps necessary to connect to a CLI session on an Avaya Networking device
	my $pkgsub = "${Package}-connect:";
	my $self = shift;
	my (@suppressArgs, @args, %cliArgs, %loginArgs);

	if (@_ == 1) { # Method invoked in the shorthand form
		$cliArgs{host} = shift;
		if ($cliArgs{host} =~ /^(.+?)\s+(\d+)$/) {
			($cliArgs{host}, $cliArgs{port}) = ($1, $2);
		}
	}
	else {
		my @validArgs = ('host', 'port', 'username', 'password', 'publickey', 'privatekey', 'passphrase',
				 'prompt_credentials', 'baudrate', 'parity', 'databits', 'stopbits', 'handshake',
				 'errmode', 'connection_timeout', 'timeout', 'read_attempts', 'wake_console');
		@args = parseMethodArgs($pkgsub, \@_, \@validArgs);
		# Remove method arguments which Control::CLI::connect() method will not accept
		@suppressArgs = ('timeout', 'read_attempts', 'wake_console');
		%cliArgs = suppressMethodArgs(\@args, \@suppressArgs);
		# Remove method arguments which login() method will not accept
		@suppressArgs = ('host', 'port', 'publickey', 'privatekey', 'passphrase', 'baudrate', 'parity',
				  'databits', 'stopbits', 'handshake', 'connection_timeout');
		%loginArgs = suppressMethodArgs(\@args, \@suppressArgs);
	}
	unless ($self->{LOGINSTAGE}) { # If this is set, then the connection is already up..
		# Get the connection setup from parent class
		$self->SUPER::connect(%cliArgs) or return $self->error($pkgsub.$self->errmsg);
	}

	# Call login method from this class to get a CLI prompt
	return $self->login(%loginArgs);
}
		

sub disconnect { # Perform check on restoring buadrate on device before doing Control::CLI's disconnect
	my $self = shift;
	$self->_restoreDeviceBaudrate if $self->connection_type eq 'SERIAL';
	return $self->SUPER::disconnect;
}


sub login { # Handles steps necessary to get to CLI session, including menu, banner and Telnet/Serial login
	my $pkgsub = "${Package}-login:";
	my $self =shift;
	my ($outref, $outRetRef, $loginAttempted, $pattern, $patdepth, $deepest, $detectionFromPrompt);
	my ($familyType, $promptType, $capturedPrompt, $switchName, $cliType, $cpuSlot, $configContext);
	my $loginError = '';
	my $usernamePrompt = $self->username_prompt;
	my $passwordPrompt = $self->password_prompt;
	my @validArgs = ('username', 'password', 'prompt_credentials', 'timeout', 'errmode', 'return_reference', 'read_attempts', 'wake_console');
	my %args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	my $promptCredentials = defined $args{prompt_credentials} ? $args{prompt_credentials} : $self->{prompt_credentials};
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $returnRef = defined $args{return_reference} ? $args{return_reference} : $self->{return_reference};
	my $readAttempts = defined $args{read_attempts} ? $args{read_attempts} : $LoginReadAttempts;
	my $wakeConsole = defined $args{wake_console} ? $args{wake_console} : $self->{$Package}{wake_console};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	if ($self->{LOGINSTAGE}) {
		$familyType = $self->{$Package}{ATTRIB}{'family_type'}; # Might be already set from previous login attempt
	}
	else {	# Flush all attributes, as we assume we are connecting to a new device
		$self->{$Package}{ATTRIB} = undef;
		$self->{$Package}{ATTRIBFLAG} = undef;
	}

	# Handle resuming previous login attempt
	if ($self->{LOGINSTAGE} eq 'username' && $args{username}) { # Resume login from where it was left
		$self->print(line => $args{username}, errmode => 'return')
			or return $self->error("$pkgsub Unable to send username\n".$self->errmsg);
		$self->{LOGINSTAGE} = '';
		$loginAttempted = 1;
	}
	elsif ($self->{LOGINSTAGE} eq 'password' && $args{password}) { # Resume login from where it was left
		$self->print(line => $args{password}, errmode => 'return')
			or return $self->error("$pkgsub Unable to send password\n".$self->errmsg);
		$self->{LOGINSTAGE} = '';
		$loginAttempted = 1;
	}
	elsif (($self->connection_type eq 'SERIAL' || ($self->connection_type eq 'TELNET' && $self->port != 23)) && $wakeConsole) {
		$self->_debugMsg(2,"\nlogin() Sending wake_console sequence\n");
		$self->put(string => $wakeConsole, errmode => 'return') # Bring connection into life
			or return $self->error("$pkgsub Unable to send bring alive character sequence\n".$self->errmsg);
	}
	# Enter login loop..
	while (1) {
		# Wait until we have read in all available data
		$outref = $self->readwait(	read_attempts => $readAttempts,
						blocking => 1,
						timeout => $timeout,
						return_reference => 1,
						errmode => 'return',
		) or do {
			$self->error($loginError."$pkgsub Unable to read login prompt\n".$self->errmsg);
			return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
		};
		$self->_debugMsg(2,"\nlogin() Connection input to process:\n>", $outref, "<\n");

		# Preserve device login output if requested by caller
		$$outRetRef .= $$outref if wantarray;

		# Pattern matching; try and detect patterns, and record their depth in the input stream
		$pattern = '';
		$deepest = -1;
		foreach my $key (keys %LoginPatterns) {
			if (($patdepth = rindex($$outref, $LoginPatterns{$key})) >= 0) { # We have a match
				$self->_debugMsg(2,"\nlogin() Matched pattern $key @ depth $patdepth\n");
				unless ($familyType) { # Only if family type not already detected
					# If a banner is seen, try and extract attributes from it also
					if ($key eq 'banner' || $key eq 'menu') {
						$familyType = $Prm{bstk};
						$self->_debugMsg(2,"login() Detected family_type = $familyType\n");
						$self->_setAttrib('family_type', $familyType);
						$self->_setAttrib('is_nncli', 1);
						if ($key eq 'banner') {
							$$outref =~ /\*\*\* ((?:[^\*\n]+?) (?:Switch|Controller|Platform) (?:WC)?\d+.*?)\s+/ &&
								$self->_setModelAttrib($1);
							$$outref =~ /FW:([\d\.]+)\s+SW:v([\d\.]+)/ && do {
								$self->_setAttrib('fw_version', $1);
								$self->_setAttrib('sw_version', $2);
							};
						}
					}
					elsif ($key eq 'srbanner') {
						$familyType = $Prm{sr};
						$self->_debugMsg(2,"login() Detected family_type = $familyType\n");
						$self->_setAttrib('family_type', $familyType);
						$self->_setAttrib('is_nncli', 1);
						$$outref =~ /\((Secure Router \d+)\)/ && $self->_setModelAttrib($1);
						$$outref =~ /Version: (.+)/ && $self->_setAttrib('sw_version', $1);
					}
					elsif ($key eq 'xlrbanner') {
						$familyType = $Prm{xlr};
						$self->_debugMsg(2,"login() Detected family_type = $familyType\n");
						$self->_setAttrib('family_type', $familyType);
						$self->_setAttrib('is_nncli', 0);
						$$outref =~ /\* Software Release (?i:v|REL)?(.+?) / && do {
							$self->_setAttrib('sw_version', $1);
						};
					}
					elsif ($key eq 'ersbanner' || $key eq 'passportbanner') {
						$familyType = $Prm{pers};
						$self->_debugMsg(2,"login() Detected family_type = $familyType\n");
						$self->_setAttrib('family_type', $familyType);
						$self->_setAttrib('is_nncli', 0);
						$$outref =~ /\* Software Release (?i:v|REL)?(.+?) / && $self->_setAttrib('sw_version', $1);
					}
					elsif ($key eq 'vspbanner') {
						$familyType = $Prm{pers};
						$self->_debugMsg(2,"login() Detected family_type = $familyType\n");
						$self->_setAttrib('family_type', $familyType);
						$self->_setAttrib('is_nncli', 1);
						$$outref =~ /Software Release Build (.+?) / && $self->_setAttrib('sw_version', $1);
					}
				}
				if ($patdepth > $deepest) { # We have a deeper match, we keep it
					($pattern, $deepest) = ($key, $patdepth);
				}
			}
		}
		$self->_debugMsg(2,"\nlogin() Retaining pattern: $pattern\n") if $deepest > -1;

		# Now try and match other prompts expected to be seen at the very end of received input stream
		if ($$outref =~ /$usernamePrompt/) { # Handle Modular login prompt
			$self->_debugMsg(2,"\nlogin() Matched Login prompt\n\n");
			$pattern = 'username';
		}
		elsif ($$outref =~ /$passwordPrompt/) { # Handle Modular password prompt
			$self->_debugMsg(2,"\nlogin() Matched Password prompt\n\n");
			$pattern = 'password';
		}

		# Now handle any pattern matches we had above
		if ($pattern eq 'banner' || $pattern eq 'bell') { # We got the banner, send a CTRL-Y to get in
			$self->_debugMsg(2,"\nlogin() Processing Stackable Banner\n\n");
			$self->put(string => $CTRL_Y, errmode => 'return') or do {
				$self->error("$pkgsub Unable to send CTRL-Y sequence\n".$self->errmsg);
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			};
			next;
		}
		elsif ($pattern eq 'menu') { # We got the menu, send a 'c' and get into CLI
			$self->_debugMsg(2,"\nlogin() Processing Stackable Menu\n\n");
			$self->put(string => 'c', errmode => 'return') or do {
				$self->error("$pkgsub Unable to select 'Command Line Interface...'\n".$self->errmsg);
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			};
			next;
		}
		elsif ($pattern eq 'submenu') { # We are in a sub-menu page, send a 'CTRL_C' to get to main menu page
			$self->_debugMsg(2,"\nlogin() Processing Stackable Sub-Menu page\n\n");
			$self->put(string => $CTRL_C, errmode => 'return') or do {
				$self->error("$pkgsub Unable to go back to main menu page\n".$self->errmsg);
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			};
			next;
		}
		elsif ($pattern =~ /^more\d$/) { # We are connecting on the console port, and we are in the midst of more-paged output
			$self->_debugMsg(2,"\nlogin() Quitting residual more-paged output for serial port access\n");
			$self->put(string => 'q', errmode => 'return') or do {
				$self->error("$pkgsub Unable to quit more-paged output found after serial connect\n".$self->errmsg);
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			};
			next;
		}
		elsif ($pattern =~ /^consoleLogMsg\d$/) { # We are connecting on the console port, and this log message is spoiling our 1st prompt
			$self->_debugMsg(2,"\nlogin() Sending extra carriage return after password for serial port access\n");
			# On Modular VSPs Console port, immediately after login you get log message :SW INFO user rwa connected via console port
			# As this message is appended to the very 1st prompt, we are not able to lock on that initial prompt
			# So we feed an extra carriage return so that we can lock on a fresh new prompt
			$self->print(errmode => 'return') or do {
				$self->error("$pkgsub Unable to get new prompt after console log message\n".$self->errmsg);
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			};
			next;
		}
		elsif ($pattern eq 'lastlogin') { # Last login splash screen; skip it with RETURN key
			# This screen appears on ERS4800 release 5.8
			$self->_debugMsg(2,"\nlogin() Processing Last Login screen\n\n");
			$self->print(errmode => 'return') or do {
				$self->error("$pkgsub Unable to send Carriage Return\n".$self->errmsg);
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			};
			next;
		}
		elsif ($pattern eq 'username') { # Handle login prompt
			$self->_debugMsg(2,"\nlogin() Processing Login/Username prompt\n\n");
			if ($loginAttempted) {
				$self->{LOGINSTAGE} = 'username';
				$self->error("$pkgsub Incorrect Username or Password");
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			}
			unless ($args{username}) {
				if ($self->{TYPE} eq 'SSH') { # If an SSH connection, we already have the username
					$args{username} = $self->{USERNAME};
				}
				else {
					unless ($promptCredentials) {
						$self->{LOGINSTAGE} = 'username';
						$self->error("$pkgsub Username required");
						return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
					}
					$args{username} = promptClear('Username');
				}
			}
			$self->print(line => $args{username}, errmode => 'return') or do {
				$self->error("$pkgsub Unable to send username\n".$self->errmsg);
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			};
			$self->{LOGINSTAGE} = '';
			$loginAttempted = 1;
			next;
		}
		elsif ($pattern eq 'password') { # Handle password prompt
			$self->_debugMsg(2,"\nlogin() Processing Password prompt\n\n");
			unless ($args{password}) {
				unless ($promptCredentials) {
					$self->{LOGINSTAGE} = 'password';
					$self->error("$pkgsub Password required");
					return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
				}
				$args{password} = promptHide('Password');
			}
			$self->print(line => $args{password}, errmode => 'return') or do {
				$self->error("$pkgsub Unable to send password\n".$self->errmsg);
				return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
			};
			$self->{LOGINSTAGE} = '';
			next;
		}
		elsif ($pattern eq 'localfail') { # Login failure
			$self->error("$pkgsub Incorrect Username or Password");
			return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
		}
		elsif ($pattern eq 'radiusfail') { # Radius Login failure
			$self->error("$pkgsub Switch got access denied from RADIUS");
			return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
		}
		elsif ($pattern =~ /^radiustimeout\d$/) { # Radius timeout
			$loginError = "$pkgsub Switch got no response from RADIUS servers\n";
			next; # In this case don't error, as radius falback might still get us in
		}
		# Then try and match CLI prompts; this is the only exit point of the loop
		if ($familyType) { # A family type was already detected from banner
			if ($familyType eq $Prm{'pers'}) {
				foreach my $type ('cli', 'nncli') {
					$promptType = "${familyType}_${type}";
					if ($$outref =~ /^($InitPrompt{$promptType})/m) {
						($capturedPrompt, $switchName, $cpuSlot, $configContext) = ($1, $2, $3, $4);
						$cliType = $type;
						last;
					}
				}
			}
			else {
				if ($$outref =~ /^($InitPrompt{$familyType})/m) {
					($capturedPrompt, $switchName, $configContext) = ($1, $2, $4);
					$promptType = $familyType;
				}
			}
		}
		else { # A family type has not been detected yet; try and detect from received prompt
			foreach my $key (@InitPromptOrder) {
				if ($$outref =~ /^($InitPrompt{$key})/m) {
					($capturedPrompt, $switchName, $cpuSlot, $configContext) = ($1, $2, $3, $4);
					$promptType = $key;
					($familyType = $key) =~ s/_(\w+)$//;
					$cliType = $1;
					$detectionFromPrompt = 1;
					last;
				}
			}
		}
		if ($capturedPrompt) { # We have a prompt, we can exit
			$self->_debugMsg(2,"\nlogin() Got CLI prompt for family type $familyType !\n");
			$self->_setDevicePrompts($promptType, $switchName);
			$capturedPrompt =~ s/^\x0d//; # Remove initial carriage return if there
			$capturedPrompt =~ s/\x0d$//; # Remove trailing carriage return if there (possible if we match on not the last prompt, as we do /m matching above
			$self->{LASTPROMPT} = $capturedPrompt;
			$self->{$Package}{CONFIGCONTEXT} = $configContext;
			$self->{$Package}{PROMPTTYPE} = $promptType;
			$self->_debugMsg(1,"login() Prompt type = $self->{$Package}{PROMPTTYPE}\n");

			$self->_setAttrib('cpu_slot', $cpuSlot) if $familyType eq $Prm{'pers'};
			if ($familyType eq $Prm{'bstk'} || $familyType eq $Prm{'sr'} || (defined $cliType && $cliType eq 'nncli')) {
				$self->_setAttrib('is_nncli', 1);
			}
			else {
				$self->_setAttrib('is_nncli', 0);
			}
			if ($familyType eq 'generic' || ($detectionFromPrompt && $self->{LASTPROMPT} !~ /^@/) ) { # Can't tell, need extended discovery
				$familyType = $self->_discoverDevice($pkgsub, $timeout) or
					return wantarray ? (undef, $returnRef ? $outRetRef : $$outRetRef) : undef;
				if ($familyType eq 'generic' && ($self->{errmode} eq 'croak' || $self->{errmode} eq 'die')) {
					carp "\n$pkgsub Warning! Device type not detected; using generic\n";
				}
			}
			else { # Family type was detected, not just from the prompt
				if ($familyType eq $Prm{'pers'} || $familyType eq $Prm{'xlr'}) {
					$self->_setAttrib('is_master_cpu', $self->{LASTPROMPT} =~ /^@/ ? 0 : 1);
					$self->_setAttrib('is_dual_cpu', 1) if $self->{LASTPROMPT} =~ /^@/;
				}
				$self->_setAttrib('family_type', $familyType); # Set family type last
			}

			# Store credentials if these were used
			($self->{USERNAME}, $self->{PASSWORD}) = ($args{username}, $args{password}) if $loginAttempted;
			return wantarray ? (1, $returnRef ? $outRetRef : $$outRetRef) : 1;
		}
	}	
}


sub cmd { # Sends a CLI command to host and returns result or output data
	my $pkgsub = "${Package}-cmd:";
	my $self = shift;
	my (%args, $prompt);
	if (@_ == 1) { # Method invoked with just the command argument
		$args{command} = shift;
	}
	else {
		my @validArgs = ('command', 'prompt', 'reset_prompt', 'more_prompt', 'cmd_confirm_prompt', 'more_pages',
				 'timeout', 'errmode', 'return_reference', 'return_result', 'progress_dots' );
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	$args{command} = '' unless defined $args{command};
	my $morePages = defined $args{more_pages} ? $args{more_pages} : $self->{$Package}{morePaging};
	my $progressDots = defined $args{progress_dots} ? $args{progress_dots} : $self->{$Package}{progressDots};
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $returnRef = defined $args{return_reference} ? $args{return_reference} : $self->{return_reference};
	my $returnRes = defined $args{return_result} ? $args{return_result} : $self->{$Package}{return_result};
	if ($args{reset_prompt}) {
		$prompt = $InitPrompt{$self->{$Package}{PROMPTTYPE}};
	}
	else {
		$prompt = defined $args{prompt} ? $args{prompt} : $self->{$Package}{prompt_qr};
	}
	my $morePrompt = defined $args{more_prompt} ? $args{more_prompt} : $self->{$Package}{morePrompt_qr};
	my $ynPrompt = defined $args{cmd_confirm_prompt} ? $args{cmd_confirm_prompt} : $self->{$Package}{cmd_confirm_prompt_qr};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	return $self->_cmd($pkgsub, $returnRef, $returnRes, $args{command}, $timeout, $morePages, $prompt, $progressDots, $morePrompt, $ynPrompt);
}


sub cmd_prompted { # Sends a CLI command to host, feed additional data and return any output
	my $pkgsub = "${Package}-cmd_prompted:";
	my $self = shift;
	my ($cmd, @feedData, $errmode, $reset_prompt);
	my $morePages = $self->{$Package}{morePaging};
	my $progressDots = $self->{$Package}{progressDots};
	my $timeout = $self->{timeout};
	my $returnRef = $self->{return_reference};
	my $returnRes = $self->{$Package}{return_result};
	my $prompt = $self->{$Package}{prompt_qr};
	my $morePrompt = $self->{$Package}{morePrompt_qr};
	my $cmdPrompt = $self->{$Package}{cmd_initiated_prompt_qr};
	if (lc($_[0]) ne 'command') { # No command argument, assume list form
		$cmd = shift;
		@feedData = @_;
	}
	else { # Method invoked with multiple arguments form
		my @validArgs = ('command', 'feed', 'prompt', 'reset_prompt', 'more_prompt', 'cmd_initiated_prompt', 'more_pages',
				 'timeout', 'errmode', 'return_reference', 'return_result', 'progress_dots');
		my @args = parseMethodArgs($pkgsub, \@_, \@validArgs);
		for (my $i = 0; $i < $#args; $i += 2) {
			$cmd = $args[$i + 1] if $args[$i] eq 'command';
			push @feedData, $args[$i + 1] if $args[$i] eq 'feed';
			$prompt = $args[$i + 1] if $args[$i] eq 'prompt';
			$morePages = $args[$i + 1] if $args[$i] eq 'more_pages';
			$timeout = $args[$i + 1] if $args[$i] eq 'timeout';
			$returnRef = $args[$i + 1] if $args[$i] eq 'return_reference';
			$returnRes = $args[$i + 1] if $args[$i] eq 'return_result';
			$reset_prompt = $args[$i + 1] if $args[$i] eq 'reset_prompt';
			$morePrompt = $args[$i + 1] if $args[$i] eq 'more_prompt';
			$progressDots = $args[$i + 1] if $args[$i] eq 'progress_dots';
			$cmdPrompt = $args[$i + 1] if $args[$i] eq 'cmd_initiated_prompt';
			$errmode = parse_errmode($pkgsub, $args[$i + 1]) if $args[$i] eq 'errmode';
		}
	}
	$cmd = '' unless defined $cmd;
	$prompt = $InitPrompt{$self->{$Package}{PROMPTTYPE}} if $reset_prompt;
	local $self->{errmode} = $errmode if defined $errmode;

	return $self->_cmd($pkgsub, $returnRef, $returnRes, $cmd, $timeout, $morePages, $prompt, $progressDots, $morePrompt, 0, $cmdPrompt, @feedData);
}


sub attribute { # Read attributes for host device
	my $pkgsub = "${Package}-attribute:";
	my $self = shift;
	my (%args, $attribute);
	if (@_ == 1) { # Method invoked with just the command argument
		$attribute = shift;
	}
	else {
		my @validArgs = ('attribute', 'reload');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
		$attribute = $args{attribute};
	}

	my ($outref, $familyType);
	return unless $familyType = $self->{$Package}{ATTRIB}{'family_type'};

	if ($args{reload}) { # Force reload, either via forced login() or resetting ATTRIBFLAG
		if ($attribute eq 'family_type' || $attribute eq 'is_nncli' || $attribute eq 'is_acli'
		 || $attribute eq 'is_master_cpu' || $attribute eq 'cpu_slot') {
			$self->print or return;
			$self->login or return;
		}
		else { $self->{$Package}{ATTRIBFLAG}{$attribute} = undef }
	}
	# If the attribute is set already, return it at once and quit
	return $self->{$Package}{ATTRIB}{$attribute} if defined $self->{$Package}{ATTRIBFLAG}{$attribute};

	# Go no further if generic family type
	return if $familyType eq 'generic';

	# Otherwise go set the attribute
	if ($familyType eq $Prm{pers}) {
		$attribute eq 'is_ha' && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show ha-state\n");
			$outref = $self->_cmdPrivExec($pkgsub, 'show ha-state', 'show ha-state') or return;
			if ($$outref =~ /Current CPU State : Disabled State./) {
				$self->_setAttrib('is_ha', 0);
			}
			elsif ($$outref =~ /Current CPU State/) {
				$self->_setAttrib('is_ha', 1);
			}
			else { # For example on ERS8300 or ERS1600
				$self->_setAttrib('is_ha', undef);
			}
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		$attribute eq 'sw_version' && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show sys software\n");
			$outref = $self->_cmdPrivExec($pkgsub, 'show sys sw', 'show sys software') or return;
			$$outref =~ /Version : Build (?i:v|REL)?(.+?) / && $self->_setAttrib('sw_version', $1);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		$attribute eq 'fw_version' && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show boot info\n");
			$outref = $self->_cmdPrivExec($pkgsub, 'show bootconfig info', 'show boot config general') or return;
			if ($$outref =~ /Version:\s+(?i:v|REL)?(.+)/) {
				$self->_setAttrib('fw_version', $1);
			}
			else { # VSP9000 has no fw_version (when command executed on standby CPU)
				$self->_setAttrib('fw_version', undef);				
			}
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		$attribute eq 'stp_mode' && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show boot flags\n");
			$outref = $self->_cmdPrivExec($pkgsub, 'show bootconfig flags', 'show boot config flags') or return;
			if ($$outref =~ /flags spanning-tree-mode (mstp|rstp)/) {
				$self->_setAttrib('stp_mode', $1);
			}
			else {
				$self->_setAttrib('stp_mode', 'stpg');
			}
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		if ($self->{$Package}{ATTRIB}{'is_master_cpu'}) { # On Master CPU
			($attribute eq 'is_dual_cpu' || $attribute eq 'base_mac') && do {
				$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show sys info (4 pages)\n");
				$outref = $self->_cmdPrivExec($pkgsub, 'show sys info', 'show sys-info', 4) or return;
				$$outref =~ /SysDescr\s+: (.+?) \(/g && $self->_setModelAttrib($1);
				$$outref =~ /SysName\s+: (.+)/g && $self->_setAttrib('sysname', $1);
				$$outref =~ /BaseMacAddr\s+: (.+)/g && $self->_setBaseMacAttrib($1);
				if ($$outref =~ /CP.+ dormant /) {
					$self->_setAttrib('is_dual_cpu', 1);
				}
				else {
					$self->_setAttrib('is_dual_cpu', 0);
				}
				return $self->{$Package}{ATTRIB}{$attribute};
			};
			($attribute eq 'model' || $attribute eq 'sysname') && do {
				$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show sys info (1 page)\n");
				$outref = $self->_cmdPrivExec($pkgsub, 'show sys info', 'show sys-info', 1) or return;
				$$outref =~ /SysDescr\s+: (.+?) \(/g && $self->_setModelAttrib($1);
				$$outref =~ /SysName\s+: (.+)/g && $self->_setAttrib('sysname', $1);
				$$outref =~ /BaseMacAddr\s+: (.+)/g && $self->_setBaseMacAttrib($1); # Might not match on 8600 as on page 2
				return $self->{$Package}{ATTRIB}{$attribute};
			};
			($attribute eq 'slots' || $attribute eq 'ports') && do {
				$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show port info\n");
				$outref = $self->_cmdPrivExec($pkgsub, 'show ports info name', 'show interfaces gigabitEthernet high-secure') or return;
				$self->_setSlotPortAttrib($outref);
				return $self->{$Package}{ATTRIB}{$attribute};
			};
		}
	}
	elsif ($familyType eq $Prm{bstk}) {
		($attribute eq 'fw_version' || $attribute eq 'sw_version' || $attribute eq 'switch_mode' ||
		 $attribute eq 'unit_number' || $attribute eq 'base_unit' || $attribute eq 'stack_size' ||
		 $attribute eq 'model' || $attribute eq 'sysname' || $attribute eq 'base_mac') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show sys-info\n");
			$outref = $self->_cmdPrivExec($pkgsub, undef, 'show sys-info') or return;
			if ($$outref =~ /Operation Mode:\s+(Switch)/g) {
				$self->_setAttrib('switch_mode', $1);
				$self->_setAttrib('unit_number', undef);
				$self->_setAttrib('stack_size', undef);
				$self->_setAttrib('base_unit', undef);
			}
			elsif ($$outref =~ /Operation Mode:\s+(Stack), Unit # (\d)/g) {
				$self->_setAttrib('switch_mode', $1);
				$self->_setAttrib('unit_number', $2);
				$$outref =~ /Size Of Stack:         (\d)/gc; # Use /gc modifier to maintain position at every match
				$self->_setAttrib('stack_size', $1);
				$$outref =~ /Base Unit:             (\d)/gc; # With /gc modifiers, fileds have to be matched in the right order
				$self->_setAttrib('base_unit', $1);
			}
			$$outref =~ /MAC Address:\s+(.+)/gc && $self->_setBaseMacAttrib($1);
			$$outref =~ /sysDescr:\s+(.+?)(?:\n|\s{4})/gc && # Match up to end of line, or 4 or more spaces (old baystacks append FW/SW version here)
				$self->_setModelAttrib($1);
			$$outref =~ /FW:([\d\.]+)\s+SW:v([\d\.]+)/gc && do {
				$self->_setAttrib('fw_version', $1);
				$self->_setAttrib('sw_version', $2);
			};
			$$outref =~ /sysName: +(\S+)/gc && $self->_setAttrib('sysname', $1); # \S avoids match when field is blank
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		($attribute eq 'slots' || $attribute eq 'ports') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show interfaces\n");
			$outref = $self->_cmdPrivExec($pkgsub, undef, 'show interfaces') or return;
			$self->_setSlotPortAttrib($outref);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		$attribute eq 'stp_mode' && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show spanning-tree mode\n");
			$outref = $self->_cmdPrivExec($pkgsub, undef, 'show spanning-tree mode') or return;
			if ($$outref =~ /Current STP Operation Mode: (STPG|MSTP|RSTP)/) {
				$self->_setAttrib('stp_mode', lc($1));
			}
			else { # Older stackables will not know the command and only support stpg
				$self->_setAttrib('stp_mode', 'stpg');
			}
			return $self->{$Package}{ATTRIB}{$attribute};
		};
	}
	elsif ($familyType eq $Prm{sr}) {
		$attribute eq 'model' && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show chassis\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show chassis') or return;
			$$outref =~ /Chassis Model: (.+)/ && $self->_setModelAttrib($1);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		($attribute eq 'fw_version' || $attribute eq 'sw_version') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show version\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show version') or return;
			$$outref =~ /Runtime: (.+)/g && $self->_setAttrib('sw_version', $1);
			$$outref =~ /Boot: (.+?) / && $self->_setAttrib('fw_version', $1);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		($attribute eq 'slots' || $attribute eq 'ports') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show interface ethernets\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show interface ethernets') or return;
			$self->_setSlotPortAttrib($outref);
			$outref = $self->_cmd($pkgsub, 1, 0, 'show module configuration all') or return;
			$self->_setSlotPortAttrib($outref);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		$attribute eq 'sysname' && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show hostname\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show hostname') or return;
			$$outref =~ /HostName: (.+)/g && $self->_setAttrib('sysname', $1);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		$attribute eq 'base_mac' && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show system configuration\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show system configuration', undef, 1) or return;
			$$outref =~ /Mac Address\s+0x(.+)/g && $self->_setBaseMacAttrib($1);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
	}
	elsif ($familyType eq $Prm{trpz}) {
		($attribute eq 'model' || $attribute eq 'sysname' || $attribute eq 'base_mac') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show system\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show system') or return;
			$$outref =~ /Product Name:\s+(.+)/g && $self->_setModelAttrib($1);
			$$outref =~ /System Name:\s+(.+)/g && $self->_setAttrib('sysname', $1);
			$$outref =~ /System MAC:\s+(.+)/g && $self->_setBaseMacAttrib($1);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		($attribute eq 'fw_version' || $attribute eq 'sw_version') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show version\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show version') or return;
			$$outref =~ /Version: (.+?) REL/g && $self->_setAttrib('sw_version', $1);
			$$outref =~ /BootLoader:\s+(.+)/ && $self->_setAttrib('fw_version', $1);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		($attribute eq 'slots' || $attribute eq 'ports') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show port status\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show port status') or return;
			$self->_setSlotPortAttrib($outref);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
	}
	elsif ($familyType eq $Prm{xlr}) {
		($attribute eq 'model' || $attribute eq 'fw_version' || $attribute eq 'sw_version')&& do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show config\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show config', undef, 1) or return;
			$$outref =~ /# box type\s+: (.+)/g && $self->_setModelAttrib($1);
			$$outref =~ /# boot monitor version\s+: v?(.+)/g && $self->_setAttrib('fw_version', $1);
			$$outref =~ /# software version\s+: v?(.+)/g && $self->_setAttrib('sw_version', $1);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		($attribute eq 'is_dual_cpu' || $attribute eq 'sysname') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show sys info\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show sys info', undef, 3) or return;
			$$outref =~ /SysDescr\s+: (.+?) \(/g && $self->_setModelAttrib($1);
			$$outref =~ /SysName\s+: (.+)/g && $self->_setAttrib('sysname', $1);
			if ($$outref =~ /CPU.+ dormant /) {
				$self->_setAttrib('is_dual_cpu', 1);
			}
			else {
				$self->_setAttrib('is_dual_cpu', 0);
			}
			return $self->{$Package}{ATTRIB}{$attribute};
		};
		($attribute eq 'slots' || $attribute eq 'ports') && do {
			$self->_debugMsg(1,"\nSeeking attribute $attribute value by issuing command: show ports info arp\n");
			$outref = $self->_cmd($pkgsub, 1, 0, 'show ports info arp') or return;
			$self->_setSlotPortAttrib($outref);
			return $self->{$Package}{ATTRIB}{$attribute};
		};
	}
	return; # Undefined for unrecognized attributes
}


sub change_baudrate { # Change baud rate on device and on current connection, if serial
	my $pkgsub = "${Package}-change_baudrate:";
	my $self = shift;
	my (%args, $familyType, $userExec, $privExec);
	if (@_ == 1) { # Method invoked with just the command argument
		$args{baudrate} = shift;
	}
	else {
		my @validArgs = ('baudrate', 'timeout', 'errmode', 'local_side_only');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	if ($args{local_side_only}) { # Same functionality as Control::CLI::change_baudrate()
		return $self->SUPER::change_baudrate($args{baudrate});
	}

	return $self->error("$pkgsub Cannot change baudrate on Telnet/SSH") unless $self->connection_type eq 'SERIAL';
	return $self->error("$pkgsub No serial connection established yet") unless defined $self->baudrate; # If no active connection come out
	return $self->error("$pkgsub No baudrate specified!") unless defined $args{baudrate};
	unless ($familyType = $self->{$Package}{ATTRIB}{'family_type'}) {
		return $self->error("$pkgsub Family type of remote device is not detected");
	}
	# Now, depending on family type of connected device, ensure we change the baud rate on the device first
	if ($familyType eq $Prm{bstk}) {
		$args{baudrate} = 38400 if $args{baudrate} eq 'max';
		return if $args{baudrate} == $self->baudrate; # Desired baudrate is already set
		unless ($args{baudrate} == 9600 || $args{baudrate} == 19200 || $args{baudrate} == 38400) {
			return $self->error("$pkgsub Supported baud rates for $Prm{bstk} = 9600, 19200, 38400");
		}
		$self->print(line => "terminal speed $args{baudrate}", errmode => 'return')
			or return $self->error("$pkgsub Unable to set new baud rate on device\n".$self->errmsg);
	}
	elsif ($familyType eq $Prm{pers}) {
		$args{baudrate} = 115200 if $args{baudrate} eq 'max';
		return if $args{baudrate} == $self->baudrate; # Desired baudrate is already set
		unless ($args{baudrate} == 9600 || $args{baudrate} == 19200 || $args{baudrate} == 38400 ||
			$args{baudrate} == 57600 || $args{baudrate} == 115200) {
			return $self->error("$pkgsub Supported baud rates for $Prm{pers} = 9600, 19200, 38400, 57600, 115200");
		}
		if ($self->attribute('is_nncli')) {
			if ($userExec = $self->last_prompt =~ />\s?$/) {
				$self->_enable($pkgsub, $timeout) or return;
			}
			if ($privExec = $self->last_prompt =~ /[^\)]#\s?$/) {
				$self->_cmd($pkgsub, 0, 1, 'config term', $timeout)
					or return $self->error("$pkgsub Unable to set new baud rate on device\n".$self->errmsg);
			}
			$self->print(line => "boot config sio console baud $args{baudrate}", errmode => 'return')
				or return $self->error("$pkgsub Unable to set new baud rate on device\n".$self->errmsg);
		}
		else {
			$self->print(line => "config bootconfig sio console baud $args{baudrate}", errmode => 'return')
				or return $self->error("$pkgsub Unable to set new baud rate on device\n".$self->errmsg);
		}
	}
	elsif ($familyType eq $Prm{generic}) {} # Do nothing here, so same functionality as Control::CLI
	else { # Other family types not supported
		return;
	}
	if (defined $self->{$Package}{ORIGBAUDRATE}) { # Clear note following restore
		$self->{$Package}{ORIGBAUDRATE} = undef if $self->{$Package}{ORIGBAUDRATE} == $args{baudrate};
	}
	else { # 1st time this method is run, make a note of original baudrate (needed in DESTROY)
		$self->{$Package}{ORIGBAUDRATE} = $self->baudrate;
	}

	$self->SUPER::change_baudrate(baudrate => $args{baudrate}, errmode => 'return')
		or return $self->error($pkgsub.$self->errmsg);

	$self->_cmd($pkgsub, 1, 0, '', $timeout) or return; # Send carriage return + ensure we get valid prompt back
	if ($familyType eq $Prm{pers} && $self->attribute('is_nncli')) {
		if ($privExec) {
			$self->_cmd($pkgsub, 0, 1, 'exit', $timeout)
				or return $self->error("$pkgsub Error while changing baud rate\n".$self->errmsg);
		}
		if ($userExec) {
			$self->_cmd($pkgsub, 0, 1, 'disable', $timeout)
				or return $self->error("$pkgsub Error while changing baud rate\n".$self->errmsg);
		}
	}
	return $args{baudrate};
}


sub enable { # Enter PrivExec mode (handle enable password for WLAN2300)
	my $pkgsub = "${Package}-enable:";
	my $self = shift;
	my %args;
	if (@_ == 1) { # Method invoked with just the command argument
		$args{password} = shift;
	}
	else {
		my @validArgs = ('password', 'prompt_credentials', 'timeout', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	my $promptCredentials = defined $args{prompt_credentials} ? $args{prompt_credentials} : $self->{prompt_credentials};
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	return $self->_enable($pkgsub, $timeout, $args{password}, $promptCredentials);
}


sub device_more_paging { # Enable/Disable more paging on host device
	my $pkgsub = "${Package}-device_more_paging:";
	my $self = shift;
	my (%args, $familyType);
	if (@_ == 1) { # Method invoked with just the command argument
		$args{enable} = shift;
	}
	else {
		my @validArgs = ('enable', 'timeout', 'errmode');
		%args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	}
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	return unless $familyType = $self->{$Package}{ATTRIB}{'family_type'};

	if ($familyType eq $Prm{bstk}) {
		$args{enable} = $args{enable} ? 23 : 0;
		$self->_cmd($pkgsub, 0, 1, "terminal length $args{enable}", $timeout)
			or return $self->error("$pkgsub Failed to set more-paging mode\n".$self->errmsg);
	}
	elsif ($familyType eq $Prm{pers} || $familyType eq $Prm{xlr}) {
		if ($self->attribute('is_nncli')) { # NNCLI
			if (defined $self->attribute('model') && $self->attribute('model') =~ /(Passport|ERS)-83\d\d/) { # 8300 NNCLI
				$args{enable} = $args{enable} ? '' : 'no ';
				$self->_cmdConfig($pkgsub, '', "$args{enable}more", $timeout)
					or return $self->error("$pkgsub Failed to set more-paging mode\n".$self->errmsg);
			}
			else { # NNCLI on 8600 or VSP (or if 'model' is not defined we could be on a Standby CPU of 8600 or VSP or 8300..)
				$args{enable} = $args{enable} ? 'enable' : 'disable';
				$self->_cmd($pkgsub, 0, 1, "terminal more $args{enable}", $timeout) or do {
					if (defined $self->attribute('model')) { # 'model' was set, so we failed on 8600 or VSP Standby CPU
						return $self->error("$pkgsub Failed to set more-paging mode");
					}
					else { # This is to catch Standby CPU on 8300
						$args{enable} = $args{enable} eq 'enable' ? '' : 'no ';
						$self->_cmdConfig($pkgsub, '', "$args{enable}more", $timeout)
							or return $self->error("$pkgsub Failed to set more-paging mode\n".$self->errmsg);
					}
				};
			}
		}
		else { # CLI
			$args{enable} = $args{enable} ? 'true' : 'false';
			$self->_cmd($pkgsub, 0, 1, "config cli more $args{enable}", $timeout)
				or return $self->error("$pkgsub Failed to set more-paging mode\n".$self->errmsg);
		}
	}
	elsif ($familyType eq $Prm{sr}) {
		$args{enable} = $args{enable} ? 23 : 0;
		$self->_cmdConfig($pkgsub, '', "terminal length $args{enable}", $timeout)
			or return $self->error("$pkgsub Failed to set more-paging mode\n".$self->errmsg);
	}
	elsif ($familyType eq $Prm{trpz}) {
		$args{enable} = $args{enable} ? 23 : 0;
		$self->_cmd($pkgsub, 0, 1, "set length $args{enable}", $timeout)
			or return $self->error("$pkgsub Failed to set more-paging mode\n".$self->errmsg);
	}
	else {
		return $self->error("$pkgsub Cannot configure more paging on family type $familyType");
	}
	return 1;
}


sub device_peer_cpu { # Connect to peer CPU on ERS8x00 / VSP9000
	my $pkgsub = "${Package}-device_peer_cpu:";
	my $self = shift;
	my $familyType;
	my @validArgs = ('username', 'password', 'prompt_credentials', 'timeout', 'errmode');
	my %args = parseMethodArgs($pkgsub, \@_, \@validArgs);
	my $username = defined $args{username} ? $args{username} : $self->username;
	my $password = defined $args{password} ? $args{password} : $self->password;
	my $promptCredentials = defined $args{prompt_credentials} ? $args{prompt_credentials} : $self->{prompt_credentials};
	my $timeout = defined $args{timeout} ? $args{timeout} : $self->{timeout};
	my $errmode = defined $args{errmode} ? parse_errmode($pkgsub, $args{errmode}) : undef;
	local $self->{errmode} = $errmode if defined $errmode;

	unless ($familyType = $self->{$Package}{ATTRIB}{'family_type'}) {
		return $self->error("$pkgsub Family type of remote device is not detected");
	}
	return $self->error("$pkgsub No peer CPU on family type $familyType") unless $familyType eq $Prm{pers};
	return $self->error("$pkgsub Username & password required") unless ($username && $password) || $promptCredentials;

	$self->_enable($pkgsub, $timeout) or return; # If in nncli mode, need to be in PrivExec
	$self->print(line => 'peer telnet', errmode => 'return')
		or return $self->error("$pkgsub Unable to send peer telnet command\n".$self->errmsg);
	$self->waitfor(match => 'Login: $', errmode => 'return')
		or return $self->error("$pkgsub Never got peer login prompt\n".$self->errmsg);
	$username = promptClear('Username') unless $username;
	$self->print(line => $username, errmode => 'return')
		or return $self->error("$pkgsub Unable to send username\n".$self->errmsg);
	$self->waitfor(match => 'Password: $', errmode => 'return')
		or return $self->error("$pkgsub Never got peer password prompt\n".$self->errmsg);
	$password = promptHide('Password') unless $password;
	$self->print(line => $password, errmode => 'return')
		or return $self->error("$pkgsub Unable to send password\n".$self->errmsg);
	$self->_cmd($pkgsub, 1, 0, undef, $timeout, 0, $InitPrompt{$self->{$Package}{PROMPTTYPE}}) or return;
	$self->{LASTPROMPT} =~ /$InitPrompt{$self->{$Package}{PROMPTTYPE}}/;
	$self->_setAttrib('cpu_slot', $2);
	$self->_setAttrib('is_master_cpu', $self->{LASTPROMPT} =~ /^@/ ? 0 : 1);
	$self->_setAttrib('is_dual_cpu', 1) if $self->{LASTPROMPT} =~ /^@/;
	return 1;
}


#################################### Methods to set/read Object variables ####################################

sub flush_credentials { # Clear the stored username, password, passphrases, and enable password, if any
	my $self = shift;
	$self->SUPER::flush_credentials;
	$self->{$Package}{ENABLEPWD} = undef;
	return 1;
}


sub prompt { # Read/Set object prompt
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{prompt};
	if (defined $newSetting) {
		$self->_debugMsg(1, "\nPrompt Regex set to:\n$newSetting\n");
		$self->{$Package}{prompt} = $newSetting;
		$self->{$Package}{prompt_qr} = qr/$newSetting/;
	}
	return $currentSetting;
}


sub more_prompt { # Read/Set object more prompt
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{morePrompt};
	if (defined $newSetting) {
		$newSetting =~ s/([\(\)\.])/\\$1/g;
		$self->_debugMsg(1, "More Prompt Regex set to:\n$newSetting\n");
		$self->{$Package}{morePrompt} = $newSetting;
		$self->{$Package}{morePrompt_qr} = $newSetting ? qr/$newSetting/ : undef;
	}
	return $currentSetting;
}


sub more_paging { # Set the number of pages to read in the resence of --more-- prompts from host
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{morePaging};
	$self->{$Package}{morePaging} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub progress_dots { # Enable/disable activity dots
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{progressDots};
	$self->{$Package}{progressDots} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub return_result { # Set/read return_result mode
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{return_result};
	$self->{$Package}{return_result} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub cmd_confirm_prompt { # Read/Set object cmd_confirm_prompt prompt
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{cmd_confirm_prompt};
	if (defined $newSetting) {
		$self->{$Package}{cmd_confirm_prompt} = $newSetting;
		$self->{$Package}{cmd_confirm_prompt_qr} = qr/$newSetting/;
	}
	return $currentSetting;
}


sub cmd_initiated_prompt { # Read/Set object cmd_initiated_prompt prompt
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{cmd_initiated_prompt};
	if (defined $newSetting) {
		$self->{$Package}{cmd_initiated_prompt} = $newSetting;
		$self->{$Package}{cmd_initiated_prompt_qr} = qr/$newSetting/;
	}
	return $currentSetting;
}


sub cmd_feed_timeout { # Read/Set object value of cmd_feed_timeout
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{cmd_feed_timeout};
	$self->{$Package}{cmd_feed_timeout} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub wake_console { # Read/Set object value of wake_console
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{wake_console};
	$self->{$Package}{wake_console} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub last_cmd_success { # Return the result of the last command sent via cmd methods
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{last_cmd_success};
	$self->{$Package}{last_cmd_success} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub last_cmd_errmsg { # Set/read the last generated error message from host
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{last_cmd_errmsg};
	$self->{$Package}{last_cmd_errmsg} = $newSetting if defined $newSetting;
	return $currentSetting;
}


sub debug { # Set debug level
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{debug};
	if (defined $newSetting) {
		$self->{$Package}{debug} = $newSetting;
		$self->SUPER::debug($newSetting >= 3 ? $newSetting - 2 : 0);
	}
	return $currentSetting;
}


sub debug_file { # Set debug output file
	my ($self, $newSetting) = @_;
	my $currentSetting = $self->{$Package}{debugFilename};
	if (defined $newSetting) {
		$self->{$Package}{debugFilename} = $newSetting;
		if (defined $self->{$Package}{debugFilehandle}) {
			close $self->{$Package}{debugFilehandle};
			$self->{$Package}{debugFilehandle} = undef;
		}
		open($self->{$Package}{debugFilehandle}, '>', $newSetting) if length $newSetting;
	}
	return $currentSetting;
}


################################# Methods to read read-only Object variables #################################

sub config_context { # Return the configuration context contained in the last prompt
	my $self = shift;
	return $self->{$Package}{CONFIGCONTEXT};
}


sub enable_password { # Read the enable password (WLAN2300)
	my $self = shift;
	return $self->{$Package}{ENABLEPWD};
}


########################################## Internal Private Methods ##########################################

sub _cmd { # Sends a CLI command to host and returns reference to output data string
# Syntax: $self->_cmd(	 $pkgsub,
#			 $returnRef,
#			 $returnRes,
#			[$cmd,]    if undefined nothing is sent
#			[$timeout,]
#			[$morePages,]
#			[$prompt,]
#			[$progressDots,]
#			[$morePrompt,]
#			[$ynPrompt,]
#			[$cmdPrompt,]
#			[@feedData,]
#		     );
	my $self = shift;
	my $pkgsub = shift;
	my $returnRef = shift;
	my $returnRes = shift;
	my $cmd = shift;
	my $timeout = shift || $self->{timeout};
	my $morePages = shift || 0;
	my $prompt = shift || $self->{$Package}{prompt_qr};
	my $progressDots = shift || 0;
	my $morePrompt = shift || $self->{$Package}{morePrompt_qr};
	my $ynPrompt = shift || '';
	my $cmdPrompt = shift || '';
	my @feedData = @_;
	my $resetPrompt = ($prompt eq $InitPrompt{$self->{$Package}{PROMPTTYPE}});
	my ($output, $outref, $progress, $result, $feed, $alreadyCmdTimeout, $ynPromptCount, $cmdPromptCount, $cmdEchoRemoved, $lastPromptEchoedCmd, $lastLine, $lastOutput);

	if (defined $cmd) {
		# In NNCLI mode, if command ends with ?, append CTRL-X otherwise partial command will appear after next prompt
		if ($cmd =~ /\?\s*$/ && $self->attribute('is_nncli')) {
			if ($self->attribute('family_type') eq $Prm{sr}) { $cmd .= $CTRL_U }
			else { $cmd .= $CTRL_X }
		}
		# Flush any unread data which might be pending
		$self->read(blocking => 0);
		# Send the command
		$self->print(line => $cmd, errmode => 'return')
			or return $self->error("$pkgsub Unable to send CLI command: $cmd\n".$self->errmsg);
	}
	CMDLOOP: while (1) {
		# READ in data
		$outref = $self->read(	blocking => 1,
					timeout => $timeout,
					errmode => 'return',
					return_reference => 1,
		) or do {
			if ($alreadyCmdTimeout
			 || !defined $self->{$Package}{ATTRIB}{'family_type'}
			 || $self->{$Package}{ATTRIB}{'family_type'} eq $Prm{generic}) {
				return $self->error("$pkgsub Timeout after sending command\n".$self->errmsg);
			}
			$self->_debugMsg(1, "\nInitial cmd timeout; attempting reset_prompt\n");
			$self->print(errmode => 'return') # Send a carriage return and we have a 2nd try at catching prompt
				or return $self->error("$pkgsub Unable to send Carriage Return\n".$self->errmsg);
			$outref = $self->read(	blocking => 1,
						timeout => $timeout * $CmdTimeoutRatio,
						return_reference => 1,
						errmode => 'return',
			) or return $self->error("$pkgsub Repeated timeout after sending command\n".$self->errmsg);
			$prompt = $InitPrompt{$self->{$Package}{PROMPTTYPE}};
			$alreadyCmdTimeout = 1;
			$resetPrompt = 1;
		};
		PROCESS:{ # Data
			if ($progressDots) { # Print dots for progress
				_printDot() unless defined $progress;
				if ( ( $progress += length($$outref) ) > $progressDots) {
					_printDot();
					$progress -= $progressDots;
				}
			}

			unless ($cmdEchoRemoved) { # If the echoed cmd was not yet removed
				$output .= $$outref;	# Append to local_buffer
				if ($output =~ s/(^.*\n)//) { # if we can remove it now
					$self->_debugMsg(2,"\ncmd() Stripped echoed command\n");
					$lastPromptEchoedCmd = $self->{LASTPROMPT} . $1;
					$cmdEchoRemoved = 1;
					$$outref = $output;			# Re-prime outref so that we fall through below with what's left
					$output = $lastLine = '';		# Empty local_buffer so that we fall through below
					next CMDLOOP unless length $$outref;	# If we have remaining data, fall through, else do next cycle
				}
				else { # if we can't then no point processing patterns below
					next CMDLOOP;	# Do next read
				}
			}
			# If we get here, it means that the echo-ed cmd has been removed
			# outref will either hold remaining output after removing echoed cmd
			# or it will hold the most recent data read
	
			$lastOutput = $lastLine.$$outref;		# New output appended to previous lastLine
			if (length $lastOutput) { # Clean up patterns
				$lastOutput =~ s/^(?:\x08 \x08)*//;	# Remove backspace chars following a more prompt, if any
				$lastOutput =~ s/^\x0d *\x00\x0d//;	# Remove Secure Router CF+spaces+0+CR sequence following more prompt
				$lastOutput =~ s/^\x0d+//mg;		# Remove spurious CarriageReturns at beginning of line, a BPS/470 special 
				$lastOutput =~ s/\x0d+$//mg;		# Remove spurious CarriageReturns at end of each line, 5500, 4500... 
			}
			$lastLine = _stripLastLine(\$lastOutput);	# We strip a new lastLine from it
	
			# Here we either hold data in $lastOutput or in $lastLine or both
			$self->_debugMsg(2,"\ncmd() Output to process:\n>", \$lastOutput, "<\n") if length $lastOutput;
			$self->_debugMsg(2,"\ncmd() Lastline stripped:\n>", \$lastLine, "<\n") if length $lastLine;
			
			$output .= $lastOutput if length $lastOutput;	# Append to output

			# Since some more prompt pattern matches can include an initial \n newline which needs removing, we need lastLine to hold that \n
			if (length $lastLine && $output =~ s/\n\n$/\n/) { 		# If output had x2 trailing newlines, strip last ...
				$lastLine = "\n" . $lastLine; 	# ... and pre-pend it to lastLine
				$self->_debugMsg(2,"\ncmd() Lastline adjusted:\n>", \$lastLine, "<\n");
			}
			next CMDLOOP unless length $lastLine;

			if ($lastLine =~ s/($prompt)//) {
				($self->{LASTPROMPT} = $1) =~ s/^\x0d//; # Remove initial carriage return if there
				$self->_setDevicePrompts($self->{$Package}{PROMPTTYPE}, $2) if $resetPrompt;
				$self->{$Package}{CONFIGCONTEXT} = $resetPrompt ? $3 : $2;
				$output .= $lastLine;	# In case there was an extra carriage return
				last CMDLOOP;
			}
			if ($morePrompt && $lastLine =~ s/(?:$morePrompt)$//) { # We have a more prompt
				if ($morePages == 0 || $morePages-- > 1) { # We get the next page
					$self->_debugMsg(2,"\ncmd() More prompt detected; feeding 'SPACE'\n");
					$self->put(string => $Space, errmode => 'return')
						or return $self->error("$pkgsub Unable to page at more prompt\n".$self->errmsg);
				}
				else { # We quit here
					$self->_debugMsg(2,"\ncmd() More prompt detected; feeding 'Q'\n");
					$self->put(string => 'q', errmode => 'return')
						or return $self->error("$pkgsub Unable to quit more prompt\n".$self->errmsg);
				}
				next CMDLOOP;
			}
			if ($ynPrompt && $lastLine =~ /$ynPrompt/) { # We have a Y/N prompt
				if (++$ynPromptCount > $self->{$Package}{cmd_feed_timeout}) {
					return $self->error("$pkgsub Y/N confirm prompt timeout");
				}
				$self->_debugMsg(2,"\ncmd() Y/N prompt detected; feeding 'Y'\n");
				$self->print(line => 'y', errmode => 'return')
					or return $self->error("$pkgsub Unable to confirm at Y/N prompt\n".$self->errmsg);
				next CMDLOOP;
			}
			if ($cmdPrompt && $lastLine =~ /$cmdPrompt/) { # We have a prompt for additional input
				# But, this pattern risks matching against transient data; so check if more data coming
				$self->_debugMsg(2,"\ncmd() cmd-prompt detected; forcing readwait\n");
				$outref = $self->readwait(	read_attempts => $CmdPromptReadAttempts,
								blocking => 0,
								timeout => $timeout,
								return_reference => 1,
								errmode => 'return',
				) or return $self->error("$pkgsub Unable to check for more data\n".$self->errmsg);
				redo PROCESS if defined $$outref && length($$outref); # More data => false trigger
				$self->_debugMsg(2,"\ncmd() Detected CMD embedded prompt");
				if ($feed = shift(@feedData)) {
					$self->_debugMsg(2,"cmd()  - Have data to feed:>", \$feed, "<\n");
				}
				else {
					if (++$cmdPromptCount > $self->{$Package}{cmd_feed_timeout}) {
						return $self->error("$pkgsub Command embedded prompt timeout");
					}
					$feed = '';
					$self->_debugMsg(2,"cmd()  - No data to feed!\n");
				}
				$self->print(line => $feed, errmode => 'return')
					or return $self->error("$pkgsub Unable to feed data at cmd prompt\n".$self->errmsg);
			}# PROCESS
			# Having lastLine with \n newline can screw up cleanup patterns above, so after above prompt matching we have it removed here
			$output .= "\n" if $lastLine =~ s/^\n//; # If it's there we take it off
		}# CMDLOOP
	}
	$result = $self->_determineOutcome(\$output, $lastPromptEchoedCmd);
	return $result if $returnRes;
	return $returnRef ? \$output : $output;
}


sub _enable { # Enter PrivExec mode (handle enable password for WLAN2300)
	my $self = shift;
	my $pkgsub = shift;
	my $timeout = shift || $self->{timeout};
	my $enablePwd = shift || $self->{$Package}{ENABLEPWD};
	my $promptCredentials = shift || $self->{prompt_credentials};
	my ($output, $outref, $loginAttempted, $loginFailed);
	my $prompt = $self->{$Package}{prompt_qr};
	my $passwordPrompt = $self->{password_prompt_qr};

	return 1 unless $self->attribute('is_nncli'); # Come out if not in NNCLI mode
	return 1 unless $self->last_prompt =~ />\s?$/; # Come out if not in UserExec mode
	# Flush any unread data which might be pending
	$self->read(blocking => 0);
	# Send enable command
	$self->print(line => 'enable', errmode => 'return')
		or return $self->error("$pkgsub Unable to send CLI command: enable\n".$self->errmsg);
	do {
		$outref = $self->read(	blocking => 1,
					timeout => $timeout,
					return_reference => 1,
					errmode => 'return',
		) or return $self->error("$pkgsub Timeout after enable command\n".$self->errmsg);
		$output .= $$outref;
		$loginFailed++ if $output =~ /error: Access denied/;
		if ($output =~ /$passwordPrompt/) { # Handle password prompt
			$loginAttempted++;
			if ($enablePwd) { # An enable password is supplied
				if ($loginAttempted == 1) {	# First try; use supplied
					$self->_debugMsg(1,"enable(): sending supplied password\n");
					$self->print(line => $enablePwd, errmode => 'return')
						or return $self->error("$pkgsub Unable to send enable password\n".$self->errmsg);
				}
				else {				# Next tries, enter blanks
					$self->_debugMsg(1,"enable(): sending carriage return instead of supplied password\n");
					$self->print(errmode => 'return')
						or return $self->error("$pkgsub Unable to send blank password\n".$self->errmsg);
				}
			}
			else { # No password supplied
				if ($loginAttempted == 1) {	# First try; use blank
					$self->_debugMsg(1,"enable(): sending carriage return for password\n");
					$self->print(errmode => 'return')
						or return $self->error("$pkgsub Unable to send blank password\n".$self->errmsg);
				}
				elsif ($loginAttempted == 2) {	# Second try; use cached login password
					$enablePwd = $self->password || '';
					$self->_debugMsg(1,"enable(): sending login password for enable password\n");
					$self->print(line => $enablePwd, errmode => 'return')
						or return $self->error("$pkgsub Unable to send cached password\n".$self->errmsg);
					$enablePwd = undef;
				}
				else {				# Third try; prompt?
					if ($promptCredentials) {
						$enablePwd = promptHide('Enable Password');
						$self->print(line => $enablePwd, errmode => 'return')
							or return $self->error("$pkgsub Unable to send enable password\n".$self->errmsg);
					}
					else {			# Enter blanks
						$self->_debugMsg(1,"enable(): sending carriage return instead of prompting for password\n");
						$self->print(errmode => 'return')
							or return $self->error("$pkgsub Unable to send blank password\n".$self->errmsg);
					}
				}
			}
			$output = '';
		}
	} until ($output =~ /($prompt)/);
	($self->{LASTPROMPT} = $1) =~ s/^\x0d//; # Remove initial carriage return if there
	$self->{$Package}{CONFIGCONTEXT} = $2;
	return $self->error("$pkgsub Password required") if $loginFailed;
	$self->{$Package}{ENABLEPWD} = $enablePwd if $loginAttempted;
	return 1;
}


sub _cmdPrivExec { # If nncli send command in PrivExec mode and restore mode on exit; if not nncli just sends command; used for show commands
	my ($self, $pkgsub, $cmdcli, $cmdnncli, $morePages) = @_;
	my ($outref, $userExec);
	if ($self->attribute('is_nncli')) {
		if ($userExec = $self->last_prompt =~ />\s?$/) {
			$self->_enable($pkgsub) or return;
		}
		$outref = $self->_cmd($pkgsub, 1, 0, $cmdnncli, undef, $morePages) or return;
		if ($userExec) { $self->_cmd($pkgsub, 0, 1, 'disable') or return }
		return $outref;
	}
	else {
		return $self->_cmd($pkgsub, 1, 0, $cmdcli, undef, $morePages);
	}
}


sub _cmdConfig { # If nncli send command in Config mode and restore mode on exit; if not nncli just sends command; used for config commands
	my ($self, $pkgsub, $cmdcli, $cmdnncli, $timeout) = @_;
	my ($outref, $userExec, $privExec, $result);
	if ($self->attribute('is_nncli')) {
		if ($userExec = $self->last_prompt =~ />\s?$/) {
			$self->_enable($pkgsub, $timeout) or return;
		}
		if ($privExec = $self->last_prompt =~ /[^\)]#\s?$/) {
			$self->_cmd($pkgsub, 0, 1, 'config term', $timeout) or return;
		}
		$outref = $self->_cmd($pkgsub, 1, 0, $cmdnncli, $timeout) or return;
		$result = $self->last_cmd_success;
		if ($privExec) { $self->_cmd($pkgsub, 0, 1, 'end', $timeout) or return }
		if ($userExec) { $self->_cmd($pkgsub, 0, 1, 'disable', $timeout) or return }
		return $result ? $outref : undef;
	}
	else {
		$cmdcli = "config $cmdcli" unless $cmdcli =~ /^config /; # Prepend config if not already there
		return $self->_cmd($pkgsub, 0, 1, $cmdcli, $timeout);
	}
}


sub _setDevicePrompts { # Steps to set the actual device prompt & more prompt
	my ($self, $keyType, $actualPrompt) = @_;
	my $setPrompt;

	$setPrompt = $Prompt{$keyType};
	if ($actualPrompt) { # Generic prompt will skip this
		# If Perl's metacharacters are used in the switch prompt, backslash them not to mess up prompt regex
		$actualPrompt =~ s/([\{\}\[\]\(\)\^\$\.\|\*\+\?\\])/\\$1/g;
		$setPrompt =~ s/SWITCHNAME/$actualPrompt/;
	}
	$self->prompt($setPrompt);
	$self->more_prompt($MorePrompt{$keyType});
	return;
}


sub _setSlotPortAttrib { # Set the Slot & Port attributes
	my ($self, $outref) = @_;
	my (@slots, @ports, $currentSlot);
	# Get current attribute if partly stored
	@slots = @{$self->{$Package}{ATTRIB}{'slots'}} if $self->{$Package}{ATTRIBFLAG}{'slots'};
	@ports = @{$self->{$Package}{ATTRIB}{'ports'}} if $self->{$Package}{ATTRIBFLAG}{'ports'};
	while ($$outref =~ /^(?:\s*|interface    ethernet)?(?:(\d{1,2})\/)?(\d{1,2})/mg) {
		if (defined $1 && (!defined $currentSlot || $1 != $currentSlot)) { # New slot
			$currentSlot = $1;
			push(@slots, $currentSlot);
		}
		if (defined $currentSlot) {
			push(@{$ports[$currentSlot]}, $2);
		}
		else {
			push(@ports, $2);
		}
	}
	$self->_setAttrib('slots', \@slots);
	$self->_setAttrib('ports', \@ports);
	return;
}


sub _setModelAttrib { # Set & re-format the Model attribute
	my ($self, $model) = @_;

	$model =~ s/\s+$//; # Remove trailing spaces
	$model =~ s/^\s+//; # Remove leading spaces

	if ($self->{$Package}{ATTRIB}{'family_type'} eq $Prm{bstk}) {
		# Try and reformat the model number into something like ERS-5510
		$model =~ s/Ethernet Routing Switch /ERS-/;
		$model =~ s/Ethernet Switch /ES-/;
		$model =~ s/Business Policy Switch /BPS-/;
		$model =~ s/Wireless LAN Controller WC/WC-/;
		$model =~ s/Virtual Services Platform /VSP-/;
		$model =~ s/(-\d{3,})([A-Z])/$1-$2/;
	}
	elsif ($self->{$Package}{ATTRIB}{'family_type'} eq $Prm{sr}) {
		# Try and reformat the model number into something like SR-4134
		$model =~ s/SR(\d+)/SR-$1/;		# From show chassis
		$model =~ s/Secure Router /SR-/;	# From banner
	}
	elsif ($self->{$Package}{ATTRIB}{'family_type'} eq $Prm{trpz}) {
		# Try and reformat the model number into something like WSS-2380
		$model = 'WSS-' . $model;
	}
	$self->_setAttrib('model', $model);
	return;
}


sub _setBaseMacAttrib { # Set & re-format the Base_Mac attribute
	my ($self, $mac) = @_;

	$mac =~ s/\s+$//; # Remove trailing spaces
	$mac =~ s/^\s+//; # Remove leading spaces

	# Reformat the MAC from xx:xx:xx:xx:xx:xx to xx-xx-xx-xx-xx-xx
	$mac =~ s/:/-/g;

	# Reformat the MAC from xxxxxxxxxxxx to xx-xx-xx-xx-xx-xx
	$mac =~ s/([\da-f]{2})([\da-f]{2})([\da-f]{2})([\da-f]{2})([\da-f]{2})([\da-f]{2})/$1-$2-$3-$4-$5-$6/;

	$self->_setAttrib('base_mac', $mac);
	return;
}


sub _setAttrib { # Set attribute
	my ($self, $attrib, $value) = @_;
	if ($attrib eq 'is_nncli' || $attrib eq 'is_acli') {
		$self->{$Package}{ATTRIB}{'is_nncli'} = $value;
		$self->{$Package}{ATTRIBFLAG}{'is_nncli'} = 1;
		$self->{$Package}{ATTRIB}{'is_acli'} = $value;
		$self->{$Package}{ATTRIBFLAG}{'is_acli'} = 1;
	}
	else {
		$self->{$Package}{ATTRIB}{$attrib} = $value;
		$self->{$Package}{ATTRIBFLAG}{$attrib} = 1;
	}
	if (defined $value) {
		$self->_debugMsg(1,"\nAttribute - $attrib => $value\n");
	}
	else {
		$self->_debugMsg(1,"\nAttribute - $attrib => undef\n");
	}
	if ($attrib eq 'family_type') {
		if (defined $Attribute{$value}) {
			$self->{$Package}{ATTRIB}{'all'} = [@{$Attribute{Global}}, @{$Attribute{$value}}];
			$self->_debugMsg(1,"Attribute - all = Global + $value attributes\n");
		}
		else {
			$self->{$Package}{ATTRIB}{'all'} = $Attribute{Global};
			$self->_debugMsg(1,"Attribute - all = Global only\n");
		}
		$self->{$Package}{ATTRIBFLAG}{'all'} = 1;
	}
	return;
}


sub _discoverDevice { # Issues CLI commands to host, to determine what family type it belongs to
	my ($self, $pkgsub, $timeout) = @_;
	my ($outref, $prevPrompt);

	$self->_debugMsg(1,"\nATTEMPTING EXTENDED DISCOVERY OF HOST DEVICE !\n");

	# Output from commands below is prone to false triggers on the generic prompt;
	#  so we lock it down to the minimum length required
	$self->last_prompt =~ /(.*)([\?\$%#>]\s?)$/;
	$self->prompt(join('', ".{", length($1), ",}$2\$"));

	# BaystackERS detection command
	$outref = $self->_cmd($pkgsub, 1, 0, 'show ip address', $timeout) or return;
	if ($$outref =~ /\s+Configured\s+In Use\s+Last BootP/) {
		$self->_setAttrib('family_type', $Prm{bstk});
		$self->_setAttrib('is_nncli', 1);
		$self->{$Package}{PROMPTTYPE} = $Prm{bstk};
		$self->_debugMsg(1,"Prompt type = $self->{$Package}{PROMPTTYPE}\n\n");
		$self->{LASTPROMPT} =~ /$InitPrompt{$Prm{bstk}}/;
		$self->_setDevicePrompts($Prm{bstk}, $1);
		return $Prm{bstk};
	}

	# PassportERS-nncli detection command
	$outref = $self->_cmd($pkgsub, 1, 0, 'show basic config', $timeout) or return;
	if ($$outref =~ /^\s+auto-recover-delay :/m) {
		$self->_setAttrib('family_type', $Prm{pers});
		$self->_setAttrib('is_nncli', 1);
		$self->_setAttrib('is_master_cpu', 1);
		$self->{$Package}{PROMPTTYPE} = "$Prm{pers}_nncli";
		$self->_debugMsg(1,"Prompt type = $self->{$Package}{PROMPTTYPE}\n\n");
		$self->{LASTPROMPT} =~ /$InitPrompt{"$Prm{pers}_nncli"}/;
		$self->_setDevicePrompts("$Prm{pers}_nncli", $1);
		return $Prm{pers};
	}

	# PassportERS-cli detection command
	$outref = $self->_cmd($pkgsub, 1, 0, 'show bootconfig info', $timeout) or return;
	if ($$outref =~ /^Version:\s+(?i:v|REL)?(.+)/m) {
		my $fwVersion = $1;
		$self->_setAttrib('family_type', $Prm{pers});
		$self->_setAttrib('is_nncli', 0);
		$self->_setAttrib('fw_version', $fwVersion);
		$self->_setAttrib('is_master_cpu', 1);
		$self->{$Package}{PROMPTTYPE} = "$Prm{pers}_cli";
		$self->_debugMsg(1,"Prompt type = $self->{$Package}{PROMPTTYPE}\n\n");
		$self->{LASTPROMPT} =~ /$InitPrompt{"$Prm{pers}_cli"}/;
		$self->_setDevicePrompts("$Prm{pers}_cli", $1);
		return $Prm{pers};
	}

	# Secure Router detection command
	$outref = $self->_cmd($pkgsub, 1, 0, 'show chassis', $timeout) or return;
	if ($$outref =~ /^Chassis Model: (.+)$/m) {
		my $model = $1;
		$self->_setAttrib('family_type', $Prm{sr});
		$self->_setAttrib('is_nncli', 1);
		$self->_setModelAttrib($model);
		$self->{$Package}{PROMPTTYPE} = $Prm{sr};
		$self->_debugMsg(1,"Prompt type = $self->{$Package}{PROMPTTYPE}\n\n");
		$self->{LASTPROMPT} =~ /$InitPrompt{$Prm{sr}}/;
		$self->_setDevicePrompts($Prm{sr}, $1);
		return $Prm{sr};
	}
	# WLAN 2300 detection command
	$outref = $self->_cmd($pkgsub, 1, 0, 'show system', $timeout) or return;
	if ($$outref =~ /Product Name:\s+(.+)/g) {
		my $model = $1;
		$self->_setAttrib('family_type', $Prm{trpz});
		$self->_setAttrib('is_nncli', 1);
		$self->_setModelAttrib($model);
		$$outref =~ /System Name:\s+(.+)/g && $self->_setAttrib('sysname', $1);
		$$outref =~ /System MAC:\s+(.+)/g && $self->_setBaseMacAttrib($1);
		$self->{$Package}{PROMPTTYPE} = $Prm{trpz};
		$self->_debugMsg(1,"Prompt type = $self->{$Package}{PROMPTTYPE}\n\n");
		$self->{LASTPROMPT} =~ /$InitPrompt{$Prm{trpz}}/;
		$self->_setDevicePrompts($Prm{trpz}, $1);
		return $Prm{trpz};
	}
	# Accelar detection command
	$outref = $self->_cmd($pkgsub, 1, 0, 'show sys perf', $timeout) or return;
	if ($$outref =~ /^\s+NVRamSize:/m) {
		$self->_setAttrib('family_type', $Prm{xlr});
		$self->_setAttrib('is_nncli', 0);
		$self->_setAttrib('is_master_cpu', 1);
		$self->{$Package}{PROMPTTYPE} = $Prm{xlr};
		$self->_debugMsg(1,"Prompt type = $self->{$Package}{PROMPTTYPE}\n\n");
		$self->{LASTPROMPT} =~ /$InitPrompt{$Prm{xlr}}/;
		$self->_setDevicePrompts($Prm{xlr}, $1);
		return $Prm{xlr};
	}
	# We give up; set as generic device
	$self->_setAttrib('family_type', $Prm{generic});
	$self->_setAttrib('is_nncli', 0);
	$self->_setDevicePrompts($Prm{generic});
	return $Prm{generic};
}


sub _determineOutcome { # Determine if an error message was returned by host
	my ($self, $outref, $lastPromptEchoedCmd) = @_;
	my $familyType;

	return unless $familyType = $self->{$Package}{ATTRIB}{'family_type'};
	return if $familyType eq $Prm{generic};
	if ($$outref =~ /$ErrorPatterns{$familyType}/) {
		(my $errmsg = $1) =~ s/\x07//g; # Suppress bell chars if any
		$self->_debugMsg(1,"\nDetected error message from host:\n", \$errmsg, "\n");
		$self->{$Package}{last_cmd_errmsg} = $lastPromptEchoedCmd . $errmsg;
		return $self->{$Package}{last_cmd_success} = 0;
	}
	else {
		return $self->{$Package}{last_cmd_success} = 1;
	}
}


sub _restoreDeviceBaudrate { # Check done in disconnect and DESTROY to restore device baudrate before quiting
	my $self = shift;
	# If change_bauderate() was called and serial connection still up...
	if (defined $self->baudrate && defined (my $origBaud = $self->{$Package}{ORIGBAUDRATE}) ) {
		# ...try and restore original baudrate on device before quiting
		if ($Prm{bstk} eq $self->{$Package}{ATTRIB}{'family_type'}) {
			$self->errmode('return');
			$self->put($CTRL_C);
			$self->print("terminal speed $origBaud");
		}
		elsif ($Prm{pers} eq $self->{$Package}{ATTRIB}{'family_type'}) {
			$self->errmode('return');
			if ($self->attribute('is_nncli')) {
				$self->printlist('enable', 'config term', "boot config sio console baud $origBaud");
			}
			else {
				$self->print("config bootconfig sio console baud $origBaud");
			}
		}
	}
	return 1;
}


sub _debugMsg {
	my $self = shift;
	if (shift() <= $self->{$Package}{debug}) {
		my $string1 = shift();
		my $stringRef = shift() || \"";#" Ultraedit hack!
		my $string2 = shift() || "";
		if ($self->{$Package}{debugFilehandle}) {
			print {$self->{$Package}{debugFilehandle}} $string1, $$stringRef, $string2;
		}
		else {
			print $string1, $$stringRef, $string2;
		}
	}
	return;
}


sub _printDot {
	local $| = 1; # Flush STDOUT buffer
	print '.';
	return;
}


1;
__END__;


######################## User Documentation ##########################
## To format the following documentation into a more readable format,
## use one of these programs: perldoc; pod2man; pod2html; pod2text.

=head1 NAME

Control::CLI::AvayaData - Interact with CLI of Avaya Networking products over any of Telnet, SSH or Serial port

=head1 SYNOPSIS

	use Control::CLI::AvayaData;

=head2 Connecting with Telnet

	# Create the object instance for Telnet
	$cli = new Control::CLI::AvayaData('TELNET');
	# Connect to host
	$cli->connect(	Host		=> 'hostname',
			Username	=> $username,
			Password	=> $password,
		     );

=head2 Connecting with SSH - password authentication

	# Create the object instance for SSH
	$cli = new Control::CLI::AvayaData('SSH');
	# Connect to host
	$cli->connect(	Host		=> 'hostname',
			Username	=> $username,
			Password	=> $password,
		     );

=head2 Connecting with SSH - publickey authentication

	# Create the object instance for SSH
	$cli = new Control::CLI::AvayaData('SSH');
	# Connect to host
	$cli->connect(	Host		=> 'hostname',
			Username	=> $username,
			PublicKey	=> '.ssh/id_dsa.pub',
			PrivateKey	=> '.ssh/id_dsa',
			Passphrase	=> $passphrase,
		     );

=head2 Connecting via Serial port

	# Create the object instance for Serial port e.g. /dev/ttyS0 or COM1
	$cli = new Control::CLI::AvayaData('COM1');
	# Connect to host
	$cli->connect(	BaudRate	=> 9600,
			Parity		=> 'none',
			DataBits	=> 8,
			StopBits	=> 1,
			Handshake	=> 'none',
		     );

=head2 Sending commands once connected and disconnecting

	$cli->enable;
	$cli->return_result(1);
	$cli->cmd('config terminal') or die $cli->last_cmd_errmsg;
	$cli->cmd('no banner') or die $cli->last_cmd_errmsg;
	$cli->cmd('exit') or die $cli->last_cmd_errmsg;
	$cli->return_result(0);
	$cli->device_more_paging(0);
	$config = $cli->cmd('show running-config');
	print $config;
	$cli->disconnect;




=head1 DESCRIPTION

Control::CLI::AvayaData is a sub-class of Control::CLI allowing CLI interaction customized for Avaya (ex Nortel Enterprise) Networking products over any of Telnet, SSH or Serial port.
This class supports all of Avaya Virtual Services Platform (VSP), Ethernet Routing Switch (ERS), Secure Router (SR), WLAN Controller (WC) and WLAN Security Switch (WSS) models as well as most of the legacy data products from Nortel Enterprise (Bay Networks) heritage. Currently supported devices:

=over 2

=item *

VSP 4000, 7000, 8000, 9000

=item *

ERS/Passport models 1600, 8300, 8600, 8800

=item *

ERS models 2500, 3500, 4x00, 5x00

=item *

SR models 2330, 4134

=item *

WLAN(WC) 81x0

=item *

WLAN(WSS) 2350, 236x, 238x

=item *

BPS 2000, ES 460, ES 470

=item *

Baystack models 325, 425

=item *

Accelar/Passport models 1000, 1100, 1200

=back

Avaya has converged the CLI interface of its current range of products into a single unified (Cisco-like) CLI interface (Avaya-CLI or ACLI; previously called NNCLI in the Nortel days).
This module supports the current and latest Avaya Networking products as well as the older product families previously offered by Nortel where a number of different CLI variants exist (e.g. Passport/Accelar CLI which is still widely used).
Hence the devices supported by this module can have an inconsistent CLI (in terms of syntax, login sequences, terminal width-length-paging, prompts) and in some cases two separate CLI syntaxes are available on the same product (ERS8x00 product families support both the new and old CLI modes).
This class is written so that all the above products can be CLI scripted in a consistent way regardless of their underlying CLI variants. Hence a script written to connect and execute some CLI commands can be written in exactly the same way whether the product is an ERS8600 (using old CLI) or an ERS4500 or a SR2330. The CLI commands themselves might still vary across the different products though, even here, for certain common functions (like entering privExec mode or disabling terminal more paging) a generic method is provided by this class.

Control::CLI::AvayaData is a sub-class of Control::CLI (which is required) and therefore the above fuctionality can also be performed in a consistent manner regardless of the underlying connection type which can be any of Telnet, SSH or Serial port connection.

In the syntax layout below, square brackets B<[]> represent optional parameters.
All Control::CLI::AvayaData method arguments are case insensitive.




=head1 OBJECT CONSTRUCTOR

Used to create an object instance of Control::CLI::AvayaData

=over 4

=item B<new()> - create a new Control::CLI::AvayaData object

  $obj = new Control::CLI::AvayaData ('TELNET'|'SSH'|'<COM_port_name>');

  $obj = new Control::CLI::AvayaData (
  	Use			 => 'TELNET'|'SSH'|'<COM_port_name>',
  	[Timeout		 => $secs,]
  	[Connection_timeout	 => $secs,]
  	[Errmode		 => $errmode,]
  	[Return_result		 => $flag,]
  	[Return_reference	 => $flag,]
  	[Prompt			 => $prompt,]
  	[Username_prompt	 => $usernamePrompt,]
  	[Password_prompt	 => $passwordPrompt,]
  	[More_prompt		 => $string,]
  	[More_paging		 => $numberOfPages,]
  	[Cmd_confirm_prompt	 => $string,]
  	[Cmd_initiated_prompt	 => $string,]
  	[Cmd_feed_timeout	 => $value,]
  	[Input_log		 => $fhOrFilename,]
  	[Output_log		 => $fhOrFilename,]
  	[Dump_log		 => $fhOrFilename,]
  	[Blocking		 => $flag,]
  	[Prompt_credentials	 => $flag,]
  	[Read_attempts		 => $numberOfReadAttemps,]
  	[Read_block_size	 => $bytes,]
  	[Wake_console		 => $string,]
  	[Output_record_separator => $ors,]
  	[Debug			 => $debugFlag,]
  	[Debug_file		 => $debugFilename,]
  );

This is the constructor for Control::CLI::AvayaData objects. A new object is returned on success. On failure the error mode action defined by "errmode" argument is performed. If the "errmode" argument is not specified the default is to croak. See errmode() for a description of valid settings.
The first parameter, or "use" argument, is required and should take value either "TELNET" or "SSH" (case insensitive) or the name of the Serial port such as "COM1" or "/dev/ttyS0". The other arguments are optional and are just shortcuts to methods of the same name.

=back




=head1 OBJECT METHODS

Methods which can be run on a previously created Control::CLI::AvayaData instance



=head2 Main I/O Object Methods

=over 4

=item B<connect()> - connect to host

  $ok = $obj->connect($host [$port]);

  ($ok, $output || $outputRef) = $obj->connect($host [$port]);

  $ok = $obj->connect(
  	[Host			=> $host,]
  	[Port			=> $port,]
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[PublicKey		=> $publicKey,]
  	[PrivateKey		=> $privateKey,]
  	[Passphrase		=> $passphrase,]
  	[Prompt_credentials	=> $flag,]
  	[BaudRate		=> $baudRate,]
  	[Parity			=> $parity,]
  	[DataBits		=> $dataBits,]
  	[StopBits		=> $stopBits,]
  	[Handshake		=> $handshake,]
  	[Timeout		=> $secs,]
  	[Connection_timeout	=> $secs,]
  	[Read_attempts		=> $numberOfLoginReadAttemps,]
  	[Wake_console		=> $string,]
  	[Errmode		=> $errmode,]
  );

  ($ok, $output || $outputRef) = $obj->connect(
  	[Host			=> $host,]
  	[Port			=> $port,]
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[PublicKey		=> $publicKey,]
  	[PrivateKey		=> $privateKey,]
  	[Passphrase		=> $passphrase,]
  	[Prompt_credentials	=> $flag,]
  	[BaudRate		=> $baudRate,]
  	[Parity			=> $parity,]
  	[DataBits		=> $dataBits,]
  	[StopBits		=> $stopBits,]
  	[Handshake		=> $handshake,]
  	[Timeout		=> $secs,]
  	[Connection_timeout	=> $secs,]
  	[Return_reference	=> $flag,]
  	[Read_attempts		=> $numberOfLoginReadAttemps,]
  	[Wake_console		=> $string,]
  	[Errmode		=> $errmode,]
  );

This method connects to the host device. The connection will use either Telnet, SSH or Serial port, depending on how the object was created with the new() constructor.
On success a true (1) value is returned. On time-out or other connection failures the error mode action is performed. See errmode().
In the first & third forms only a success/failure value is returned in scalar context, while in the second & fourth forms, in list context, both the success/failure value is returned as well as any output received from the host device during the connect/login sequence; the latter is either the output itself or a reference to that output, depending on the object setting of return_reference or the argument override provided in this method.
The read_attempts argument is simply fed to the login method. See login().

The optional "errmode" argument is provided to override the global setting of the object error mode action.
The optional "connection_timeout" argument can be used to set a connection timeout for Telnet and SSH TCP connections.

This method overrides Control::CLI::connect() and calls both the Control::CLI::connect() method as well as the login() method from this class. This allows the connect() method to seamlessly handle connection and login for both SSH (which normally handles authentication as part of the connection process) and Telnet and Serial port access (for which authentication needs to be dealt with after connection).
Which arguments are used depends on the whether the object was created for Telnet, SSH or Serial port. The "host" argument is required by both Telnet and SSH. The other arguments are optional.
If username/password or SSH Passphrase are not provided but are required and prompt_credentials is true, the method will automatically prompt the user for them; otherwise the error mode action is performed. See errmode().
The optional "prompt_credentials" argument is provided to override the global setting of the parameter by the same name which is by default false. See prompt_credentials().

=over 4

=item *

For Telnet, these arguments are used:

  $ok = $obj->connect($host [$port]);

  $ok = $obj->connect(
  	Host			=> $host,
  	[Port			=> $port,]
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[Prompt_credentials	=> $flag,]
  	[Timeout		=> $secs,]
  	[Connection_timeout	=> $secs,]
  	[Read_attempts		=> $numberOfLoginReadAttemps,]
  	[Wake_console		=> $string,]
  	[Errmode		=> $errmode,]
  );

If not specified, the default port number for Telnet is 23. The wake_console argument is only relevant when connecting to a Telnet port other than 23 (i.e. to a Terminal Server device) in which case, the login() method, which is called by connect(), will automatically send the wake_console string sequence to the attached device to alert it of the connection. The default sequence will work across all Avaya Networking products but can be overridden by using the wake_console argument.

=item *

For SSH, these arguments are used:

  $ok = $obj->connect($host [$port]);

  $ok = $obj->connect(
  	Host			=> $host,
  	[Port			=> $port,]
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[PublicKey		=> $publicKey,]
  	[PrivateKey		=> $privateKey,]
  	[Passphrase		=> $passphrase,]
  	[Prompt_credentials	=> $flag,]
  	[Timeout		=> $secs,]
  	[Connection_timeout	=> $secs,]
  	[Read_attempts		=> $numberOfLoginReadAttemps,]
  	[Errmode		=> $errmode,]
  );

If not specified, the default port number for SSH is 22.
A username must always be provided for all SSH connections. If not provided and prompt_credentials is true then this method will prompt for it.
Once the SSH conection is established, this method will attempt one of two possible authentication types, based on the accepted authentications of the remote host:

=over 4

=item *

B<Publickey authentication> : If the remote host accepts it and the method was supplied with public/private keys. The public/private keys need to be in OpenSSH format. If the private key is protected by a passphrase then this must also be provided or, if prompt_credentials is true, this method will prompt for the passphrase. If publickey authentication fails for any reason and password authentication is possible, then password authentication is attempted next; otherwise the error mode action is performed. See errmode().

=item *

B<Password authentication> : If the remote host accepts it. A password must be provided or, if prompt_credentials is true, this method will prompt for the password. If password authentication fails for any reason the error mode action is performed. See errmode().

=back


=item *

For Serial port, these arguments are used:

  $ok = $obj->connect(
  	[BaudRate		=> $baudRate,]
  	[Parity			=> $parity,]
  	[DataBits		=> $dataBits,]
  	[StopBits		=> $stopBits,]
  	[Handshake		=> $handshake,]
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[Prompt_credentials	=> $flag,]
  	[Timeout		=> $secs,]
  	[Read_attempts		=> $numberOfLoginReadAttemps,]
  	[Wake_console		=> $string,]
  	[Errmode		=> $errmode,]
  );

If arguments "baudrate", "parity", "databits", "stopbits" and "handshake" are not specified, the defaults are: Baud Rate = 9600, Data Bits = 8, Parity = none, Stop Bits = 1, Handshake = none. These default values will work on all Avaya Networking products with default settings.
Allowed values for these arguments are the same allowed by Control::CLI::connect().

For a serial connection, this method - or to be precise the login() method which is called by connect() - will automatically send the wake_console string sequence to the attached device to alert it of the connection. The default sequence will work across all Avaya Networking products but can be overridden by using the wake_console argument.

=back


=item B<login()> - handle login for Telnet / Serial port; also set the host CLI prompt

  $ok = $obj->login(
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[Prompt_credentials	=> $flag,]
  	[Timeout		=> $secs,]
  	[Read_attempts		=> $numberOfLoginReadAttemps,]
  	[Wake_console		=> $string,]
  	[Errmode		=> $errmode,]
  );

  ($ok, $output || $outputRef) = $obj->login(
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[Prompt_credentials	=> $flag,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Read_attempts		=> $numberOfLoginReadAttemps,]
  	[Wake_console		=> $string,]
  	[Errmode		=> $errmode,]
  );

This method handles login authentication for Telnet and Serial port access (also for SSH access in the case of the WLAN2300 WSS controllers, since they use no SSH authentication but instead use an interactive login once the SSH connection is established). For all connection types (including SSH) it also performs all the necessary steps to get to a CLI prompt; for instance on the Baystack / Stackable ERS platforms it will skip the Banner and/or Menu interface. Over a serial port connection or a telnet connection over a port other than default 23 (indicating a Terminal Server connection) it will automatically generate a wake_console sequence to wake up the attached device into producing either a login banner or CLI prompt. This sequence can be overridden by using the wake_console argument; setting this argument to the empty string will disable the wake_console sequence.

On success the method returns a true (1) value. On failure the error mode action is performed. See errmode().
In the first form only a success/failure value is returned in scalar context, while in the second form, in list context, both the success/failure value is returned as well as any output received from the host device during the login sequence; the latter is either the output itself or a reference to that output, depending on the object setting of return_reference or the argument override provided in this method.
This method internally uses the readwait() method and by default sets the read_attemps for it to 10 (which is a safe value to ensure proper connection to any Avaya Networking device); the read_attempts argument provided by login() can be used to override that value.

Once a valid Avaya Networking CLI prompt is detected (using pre-configured pattern match strings), this method records the actual CLI prompt of the host device for the remainder of the session by automatically invoking the prompt() method with a new pattern match string based on the actual device CLI prompt. This ensures a more robust behaviour where the chances of triggering on a fake prompt embedded in the device output data is greatly reduced.
At the same time this method will also set the --more-- prompt used by the device when paging output as well as a number of attributes depending on what family_type was detected for the host device. See attribute().
Note that this method is automatically invoked by the connect() method and therefore should seldom need to be invoked by itself. A possible reason to invoke this method on its own could be if initially connecting to, say, an ERS8800 device and from there initiating a telnet connection onto a Stackable device (i.e. telnet hopping); since we are connecting to a new device the login() method must be invoked to set the new prompts accordingly as well as re-setting all the device attributes. An example follows:

	# Initial connection could use Telnet or SSH, depending on how object was constructed
	# Connect to 1st device, e.g. via out-of-band mgmt
	$cli->connect(
		Host		=> '<ERS8800 IP address>',
		Username	=> 'rwa',
		Password	=> 'rwa',
	);
	# From there connect to another device, perhaps on inband mgmt
	# NOTE: use print() not cmd() as there is no prompt coming back, but the login screen of the stackable
	$cli->print("telnet <Stackable IP address>");
	# Call login() to authenticate, detect the device, reset appropriate attributes 
	$cli->login(
		Username	=> 'RW',
		Password	=> 'RW',
	);
	# Execute commands on target stackable device
	$output = $cli->cmd("show running-config");
	print $output;
	[...]
	# If you want to return to the first device..
	# NOTE: use print() not cmd() as the next prompt will be from the ERS8800, not the stackable anymore
	$cli->print("logout");
	# Call login() to detect the device and reset appropriate attributes (no authentication needed though)
	$cli->login;
	# Now we are back on the 1st device
	$output = $cli->cmd("show sys info");
	print $output;
	[...]
 

=item B<cmd()> - Sends a CLI command to host and returns result or output

  $ok || $output || $outputRef = $obj->cmd($cliCommand);

  $ok || $output || $outputRef = $obj->cmd(
  	[Command		=> $cliCommand,]
  	[Prompt			=> $prompt,]
  	[Reset_prompt		=> $flag,]
  	[More_prompt		=> $morePrompt,]
  	[More_pages		=> $numberOfPages,]
  	[Cmd_confirm_prompt	=> $ynPrompt,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Return_result		=> $flag,]
  	[Progress_dots		=> $bytesPerDot,]
  	[Errmode		=> $errmode,]
  );

This method sends a CLI command to the host and returns once a new CLI prompt is received from the host. The output record separator - which is usually a newline "\n"; see output_record_separator() - is automatically appended to the command string. If no command string is provided then this method will simply send the output record separator and expect a new prompt back.
Before sending the command to the host, any pending input data from host is read and flushed.
The CLI prompt expected by the cmd() method is either the object prompt previously set by any of connect(), login() or prompt(); or it is the override prompt specified by the optional prompt method argument. If the reset_prompt flag is activated then the prompt match pattern is automatically reset using the same initial pattern match used by connect() & login() to match the prompt for the first time; this is useful when executing a CLI command which will cause the CLI prompt to change (such as changing the switch name). If the reset_prompt flag is set any prompt supplied via the argument will be ignored.

When this method is retrieving the output of the command and the output is generated over multiple pages of output, each page paused with a --more-- prompt, the cmd() method will retrieve as many pages as defined globally by more_paging(). If the optional "more_pages" argument is specified then this value will override the global setting of more_paging(). Either way, if a value of 0 is specified, space characters are automatically fed to obtain all output until the next CLI prompt is received. Note that for best script performance it is recommended to disable more paging on the host device using the appropriate CLI command or the device_more_paging() method. The optional 'more_prompt' argument can be used to override the object more_prompt string though this should seldom be necessary as the correct more prompt string is automatically set by connect() & login(). See more_prompt().

If the command produces a Y/N confirmation prompt as certain Avaya Networking device CLI commands do (for example "boot" or "reset") this method will automatically detect the confirmation prompt and feed a 'y' to it as you would expect when scripting the device. If, for some reason, you wanted to feed a 'n' then refer to cmd_prompted() method instead. The optional 'cmd_confirm_prompt' argument can be used to override the object match string defined for this; see also cmd_confirm_prompt().

This method will either return the result of the command or the output. If return_result is set for the object, or it is set via the override "return_result" argument provided in this method, then only the result of the command is returned. In this case a true (1) value is returned if the command was executed without generating any error messages on the host device. While a false (0) value is returned if the command generated some error messages on the host device. The error message can be obtained via the last_cmd_errmsg() method. See last_cmd_errmsg() and last_cmd_success(). This mode of operation is useful when sending configuration commands to the host device.

If instead return_result is not set then this method will return either a hard reference to the output generated by the CLI command or the output itself. This will depend on the setting of return_reference; see return_reference(); the global setting of return_reference can also be overridden using the method argument by the same name.
Passing a refence to the output makes for much faster/efficient code, particularly if the output generated is large (for instance output of "show running-config").
The echoed command is automatically stripped from the output as well as the terminating CLI prompt (the last prompt received from the host device can be obtained with the last_prompt() method).
This mode of operation is useful when sending show commands which retrieve information from the host device.
Note that in this mode (return_result not set), sending a config command will result in either a null string or a reference pointing to a null string being returned, unless that command generated some error message on the host device. In this case the return_result mode should be used instead.

The progress_dots argument is provided as an override of the object method of the same name for the duration of this method; see progress_dots().

On I/O failure to the host device, the error mode action is performed. See errmode().
If, after expiry of the configured timeout - see timeout() -, output is no longer received from host and no valid CLI prompt has been seen, the method will send an additional carriage return character and automatically fall back on the initial generic prompt for a further 10% of the configured timeout. If even that prompt is not seen after this further timeout then the error mode action is performed. See errmode().
So even if the CLI prompt is changed by the issued command (e.g. changing the system-name or quitting the debug shell) this method should be able to recover since it will automatically revert to the initial generic prompt, but this will happen after expiry of the configured timeout. In this case, to avoid waiting expiry of timeout, set the reset_prompt argument. Here is an example showing how to revert to the normal CLI prompt when quitting the shell:

	$obj->cmd('priv');
	# Before entering the shell we need to set the prompt to match the shell prompt
	$obj->prompt('-> $');
	# Now enter the shell
	$obj->cmd('shell');
	$obj->cmd('spyReport');
	[...other shell cmds issued here...]
	# When done, logout from shell, and revert to standard CLI prompt
	$obj->cmd(Command => 'logout', Reset_prompt => 1);

Alternatively, since accessing the shell now requires a priv & shell password, if you only need to execute a few shell commands you can assume that the shell prompt is a prompt belonging to the shell command and use cmd_prompted() instead; the following example does the same thing as the previous example but does not need to change the prompt:

	# Enter the shell and execute shell commands all in one go
	$obj->cmd_prompted(
			Command			=> 'priv',
			Feed			=> $privPassword,
	);
	$obj->cmd_prompted(
			Command			=> 'shell',
			Cmd_confirm_prompt	=> '(:|->) $',
			Feed			=> $shellPassword,
			Feed			=> 'spyReport',
			Feed			=> 'logout',
	);

If the issued command returns no prompt (e.g. logout), consider using print() instead of cmd() or, if logging out, simply use the disconnect() method.

If the issued command produces a Y/N confirmation prompt but does not return a regular prompt (e.g. reset, boot) there are two possible approaches. On some Avaya Networking devices (e.g. PassportERS family_type) you can append '-y' to the command being sent to suppress the Y/N confirmation prompt, in which case you can simply do:

	$cli->print('reset -y');
	$cli->disconnect;

However, other Avaya Networking devices do not accept a '-y' appended to the reset/boot commands (e.g. BaystackERS family_type); on these devices use this sequence:

	$cli->print('reset');
	$cli->waitfor($cli->cmd_confirm_prompt);
	$cli->print('y');
	$cli->disconnect;



=item B<cmd_prompted()> - Sends a CLI command to host, feeds additional requested data and returns result or output

  $ok || $output || $outputRef = $obj->cmd_prompted($cliCommand, @feedData);

  $ok || $output || $outputRef = $obj->cmd_prompted(
  	[Command		=> $cliCommand,]
  	[Feed			=> $feedData1,
  	[Feed			=> $feedData2,
  	[Feed			=> $feedData3, ... ]]]
  	[Prompt			=> $prompt,]
  	[Reset_prompt		=> $flag,]
  	[More_prompt		=> $morePrompt,]
  	[More_pages		=> $numberOfPages,]
  	[Cmd_initiated_prompt	=> $cmdPrompt,]
  	[Timeout		=> $secs,]
  	[Return_reference	=> $flag,]
  	[Return_result		=> $flag,]
  	[Progress_dots		=> $bytesPerDot,]
  	[Errmode		=> $errmode,]
  );

This method is identical to cmd() except that it will not automaticaly feed a 'y' to Y/N confirmation prompts but in a more general manner will detect any prompts generated by the issued CLI command (whether these are Y/N confirmation prompts or simply prompts for additional information the CLI command requires) and will feed whatever data has been provided to the method. In the first form, this data can be provided as an array while in the second form any number of "feed" arguments can be provided. Note that if you want to use the second form, then the "command" argument must be the first argument supplied, otherwise the first form is expected.
The prompt used to detect CLI command prompts can be set via the cmd_initiated_prompt() or via the override method argument by te same name.


=item B<attribute()> - Return device attribute value

  $value = $obj->attribute($attribute);

  $value = $obj->attribute(
  	Attribute		=> $attribute,
  	[Reload			=> $flag,]
  );

When connecting to an Avaya Networking device a certain number of attributes are automatically recorded if the information is readily available and does not require additional CLI commands.
The attribute() method allows to retrieve the value of such attributes.
If the attribute is already set, then the method simply returns its value.
If on the other hand the requested attribute is not yet set, then in this case the method will issue the necessary CLI command to find the relevant information to set the attribute (or multiple attributes since in some cases a CLI command yields information for multiple attributes) and will then return its value. Any subsequent lookup for the same attribute name will no longer need to issue CLI commands.
In the second form, if the "reload" flag is true, then even if the attribute was already set the method will verify the setting on the connected device by re-issuing the necessary commands.
In case of any IO failures while issuing CLI commands the error mode action is performed.

Once a connection is established (including login) the I<family_type> attribute is always set.
As long as it is set to a valid Avaya Networking product type, then all other global attributes are available as well as all the relevant attributes for the family type specified (a full list of available attributes is returned by specifying attribute I<all>). Attributes for other product families different from the current value of I<family_type> will be undefined.
If the I<family_type> attribute is not yet set or is set to B<generic> then all other attributes, including the other Global ones, will be undefined.

Valid attributes and their possible values follow.

Global attributes which apply to any product family type:

=over 4

=item *

I<family_type>:

=over 4

=item *

B<BaystackERS> : Any of Baystack, BPS, ES, Stackable ERS (ERS-2500, ERS-3500, ERS-4x00, ERS-5x00), Stackable VSP (VSP-7000), WLAN8100

=item *

B<PassportERS> : Any of Passport/ERS-1600, Passport/ERS-8x00, VSP-9000, VSP-8000, VSP-4000

=item *

B<SecureRouter> : Any of the Secure Router 2330 & 4134 series

=item *

B<WLAN2300> : WLAN WSS2300 Controllers

=item *

B<Accelar> : Any of the old Accelar 1000, 1100, 1200

=item *

B<generic> : Not an Avaya Networking product; equivalent functionality to Control::CLI

=back


=item *

I<model>: Device model e.g. ERS-8610, ERS-4526-GTX-PWR; The model naming will usually be in the format <VSP|ERS|ES|WC>-<number>-<type>-<subtype>. This attribute will remain undefined if connected to the Standby CPU of a PassportERS device.

=item *

I<sysname>: System name of the device. This attribute will remain undefined if connected to the Standby CPU of a PassportERS device.

=item *

I<base_mac>: Base MAC address of the device in string format xx-xx-xx-xx-xx-xx. This is the base MAC address from which all other device MACs (VLAN, Port, etc) are derived. This attribute is useful for maintaining a unique reference for the device. This attribute will remain undefined if connected to the Standby CPU of a PassportERS device.

=item *

I<is_acli>: Flag; true(1) for Cisco like acli mode which has PrivExec & Config modes; false(0) otherwise.
So for family types B<BaystackERS>, B<SecureRouter>, B<WLAN2300> and B<PassportERS> (the latter in acli mode) this flag is true.
Whereas for family types B<Accelar>, B<generic> and B<PassportERS> (the latter in cli mode) this flag is false.

=item *

I<is_nncli>: Flag; alias for above I<is_acli> attribute as nncli is historically how this CLI mode was called in Nortel days

=item *

I<sw_version>: Run time software version

=item *

I<fw_version>: Boot / Boot Monitor / Firmware verson, if applicable, undef otherwise

=item *

I<slots>: Returns a list (array reference) of all valid slot numbers (or unit numbers in a stack); returns an empty list if the device ports have no slot number associated (e.g. a BaystackERS switch in standalone mode) and undefined if no slot/port information could be retrieved from the device, e.g. if connected to the Standby CPU of a PassportERS device

=item *

I<ports>: If the I<slots> attribute is defined, this attribute returns an array reference where the index is the slot number (valid slot numbers are provided by the I<slots> attribute) and the array elements are a list (array references again) of valid ports for that particular slot. If the I<slots> attribute is defined but empty (i.e. there is no slot number associated to available ports), this attribute returns a list (array reference) of valid port numbers for the device.

=back



Attributes which only apply to B<PassportERS> family type:

=over 4

=item *

I<is_master_cpu>: Flag; true(1) if connected to a Master CPU; false(0) otherwise

=item *

I<is_dual_cpu>: Flag; true(1) if 2 CPUs are present in the chassis; false(0) otherwise

=item *

I<cpu_slot>: Slot number of the CPU we are connected to

=item *

I<is_ha>: Flag; true(1) if HA-mode is enabled; false(0) otherwise; undef if not applicable

=item *

I<stp_mode>: Spanning tree operational mode; possible values: B<stpg>, B<mstp>, B<rstp>

=back



Attributes which only apply to B<BaystackERS> family type:

=over 4

=item *

I<unit_number>: Unit number we are connected to (Generaly the base unit, except when connecting via Serial) if a stack; undef otherwise

=item *

I<base_unit>: Base unit number, if a stack; undef otherwise

=item *

I<switch_mode>:

=over 4

=item *

B<Switch> : Standalone switch

=item *

B<Stack> : Stack of switches

=back

=item *

I<stp_mode>: Spanning tree operational mode; possible values: B<stpg>, B<mstp>, B<rstp>

=back

All available attributes on a given connection

=over 4

=item *

I<all>: Retuns a list (array reference) of all valid attributes for the current connection; this will include all Global attributes as well as all attributes corresponding to the family type specified by I<family_type>. This is useful for iterating through all available attributes in a foreach loop.

=back

=item B<change_baudrate()> - Change baud rate on current serial connection

  $baudrate = $obj->change_baudrate($baudrate);

  $baudrate = $obj->change_baudrate(
  	BaudRate		=> $baudrate,
  	[Timeout		=> $secs,]
  	[Local_side_only	=> $flag,]
  	[Errmode		=> $errmode,]
  );

This method is only applicable to an already established Serial port connection and will return an error if the connection type is Telnet or SSH or if the object type is for Serial but no connection is yet established.

If the 'local_side_only' argument is set this method will simply call the Control::CLI method by the same name which will simply change the baudrate of the current serial connection without trying to also change the baudrate on the device we are connected to.

Without the 'local_side_only' argument set, this method combines the knowledge of the Avaya device type we are connected to by automatically changing the baudrate configuration on the attached device before actually changing the baudrate of the connection. The ability to change the baudrate configuration on the attached device is only available when the attribute family_type is either BaystackERS or PassportERS. If the family_type is 'generic' then this method becomes again identical to Control::CLI::change_baudrate() and will simply change the baudrate of the local connection. For other valid AvayaData values of family_type (SecureRouter & WLAN2300) this method will simply return an undefined value since there is no way to change the baudrate configuration on these devices to a value other than 9600 baud.

When changing the baudrate of the local connection this method calls Control::CLI::change_baudrate() which will restart the object serial connection with the new baudrate (in the background, the serial connection is actually disconnected and then re-connected) without losing the current CLI session.
If there is a problem restarting the serial port connection at the new baudrate then the error mode action is performed - see errmode().
If the baudrate was successfully changed the value of the new baudrate (a true value) is returned.
The advantage of using this method to increase the baudrate to a higher value than 9600 is that when retrieving commands which generate a large amount of output, this can be read in a lot faster if the baudrate is increased.

Remember to restore the baudrate configuration of the attached device to default 9600 when done or anyone connecting to its serial port thereafter will have to guess the baudrate! To minimize the chance of this happening the disconnect & destroy methods for this class will automatically try to restore whatever baudrate was used when initially connecting to the device.

Supported baudrates for this method are:

=over 4

=item *

B<BaystackERS>: 9600, 19200, 38400 or 'max' (where 'max' = 38400)

=item *

B<PassportERS>: 9600, 19200, 38400, 57600, 115200 or 'max' (where 'max' = 115200)

=back

Follows an example:

	use Control::CLI;
	# Create the object instance for Serial port
	$cli = new Control::CLI('COM1');
	# Connect to switch
	$cli->connect(
			Baudrate 	=> 9600,
			Username	=> $username,
			Password	=> $password,
		);
	# Get the config
	$output = $cli->cmd(
			Command		=> "show running-config",
			Progress_dots	=> 100,
		);
	# Increase the baudrate
	$maxBaudrate = $cli->change_baudrate('max');
	print "Baudrate increased to $maxBaudrate" if $maxBaudrate;
	# Get the config a 2nd time (4 times faster on BaystackERS; 12 times faster PassportERS)
	$output = $cli->cmd(
			Command		=> "show running-config",
			Progress_dots	=> 100,
		);
	# Restore the baudrate
	$cli->change_baudrate(9600);
	# Disconnect
	$cli->disconnect;


=item B<enable()> - Enter PrivExec mode

  $ok = $obj->enable($enablePassword);

  $ok = $obj->enable(
  	[Password		=> $enablePassword,]
  	[Prompt_credentials	=> $flag,]
  	[Timeout		=> $secs,]
  	[Errmode		=> $errmode,]
  );

This method checks whether the 'is_acli' attribute is set and, if so, whether the last prompt ends with '>'; if both conditions are true, it will flush any unread pending input from the device and will just send an 'enable' command to enter Priviledge Executive mode. If either of the above conditions are not met then this method will simply return a true (1) value.
The method can take a password argument which only applies to the WLAN2300 series and in some older software versions of the ERS-8300 in NNCLI mode.
If a password is required, but not supplied, this method will try supplying first a blank password, then the same password which was used to connect/login into the WLAN2300 and finally, if prompt_credentials is true for the object, prompt for it. On I/O failure, the error mode action is performed. See errmode().
The optional "prompt_credentials" argument is provided to override the global setting of the parameter by the same name which is by default false. See prompt_credentials().


=item B<device_more_paging()> - Enable/Disable more paging on host device

  $ok = $obj->device_more_paging($flag);

  $ok = $obj->device_more_paging(
  	Enable			=> $flag,
  	[Timeout		=> $secs,]
  	[Errmode		=> $errmode,]
  );

This method issues the necessary CLI commands to turn on/off --more-- paging on the connected device. It relies on the setting of family_type attribute - see attribute() - to send the appropriate commands.
If an error occurs while sending the necessary CLI commands, then the error mode action is performed. See errmode().
Returns a true value (1) on success.


=item B<device_peer_cpu()> - Connect to peer CPU on ERS8x00 / VSP9000

  $ok = $obj->device_peer_cpu(
  	[Username		=> $username,]
  	[Password		=> $password,]
  	[Prompt_credentials	=> $flag,]
  	[Timeout		=> $secs,]
  	[Errmode		=> $errmode,]
  );

This method, only applicable on ERS8x00 and VSP9000, will try to connect to the peer CPU. On success a true (1) value is returned otherwise the error mode action is performed. See errmode().
It should not normally be necessary to provide username/password since the credentials used to connect to the current CPU will automatically be used. If not so, or to override the cached ones, optional "username" & "password" arguments can be provided.
Attributes 'cpu_slot' and 'is_master_cpu' are automatically updated once the connection to the peer CPU succeeds. See attribute().


=back



=head2 Methods to set/read Object variables

=over 4

=item B<flush_credentials> - flush the stored username, password, passphrase and enable password credentials

  $obj->flush_credentials;

The connect(), login() and enable() methods, if successful in authenticating, will automatically store the username/password/enable-password or SSH passphrase supplied to them.
These can be retrieved via the username, password, passphrase and enable_password methods. If you do not want these to persist in memory once the authentication has completed, use this method to flush them. This method always returns 1.


=item B<prompt()> - set the CLI prompt match pattern for this object

  $string = $obj->prompt;

  $prev = $obj->prompt($string);

This method sets the CLI prompt match patterns for this object. In the first form the current pattern match string is returned. In the second form a new pattern match string is set and the previous setting returned.
If no prompt has yet been set (connection not yet established) undef is returned.
The object CLI prompt pattern is automatically set by the connect(), login() and cmd(reset_prompt => 1) methods and normally does not need to be set manually unless the CLI prompt is expected to change.
Once set, the object CLI prompt match pattern is only used by the cmd() and cmd_prompted() methods.


=item B<more_prompt()> - set the CLI --More-- prompt match pattern for this object

  $string = $obj->more_prompt;

  $prev = $obj->more_prompt($string);

This method sets the CLI --More-- prompt match patterns for this object. In the first form the current pattern match string is returned. In the second form a new pattern match string is set and the previous setting returned.
If no prompt has yet been set (connection not yet established) undef is returned.
The object CLI --More-- prompt pattern is automatically set by the connect() and login() methods based upon the device type detected during login. Normally this should not need not be changed manually.
Once set, the object CLI --More-- prompt match patterns is only used by the cmd() and cmd_prompted() methods.


=item B<more_paging()> - sets the number of pages to read when device output is paged by --more-- prompts

  $numberOfPages = $obj->more_paging;

  $prev = $obj->more_paging($numberOfPages);

When issuing CLI commands, using cmd() or cmd_prompted(), which generate large amount of output, the host device will automatically page the output with --more-- prompts where the user can either view the next page, by sending a Space character, or terminate the CLI command, by sending a q character.
This method sets the number of pages of output that both cmd() and cmd_prompted() will retrieve before sending a q character and thus terminating the CLI command. Hence if more_paging is set to 1, only one page of output will be collected and a q character will be sent to the first --more-- prompt received. if more_paging is set to 2, two pages of output will be collected and a q character will be sent to the second --more-- prompt received.
By default more_paging is set to 0, which means that the entire output of any issued command will be retrieved, by always feeding Space characters to every --more-- prompt encountered.
Note however that for best performance, if the entire output of a command is required, it is best to disable --more-- paging direcly on the host device rather than letting cmd() or cmd_prompted() feed a Space to every --more-- prompt encountered; see device_more_paging().
This setting can also be overridden directly in cmd() or cmd_prompted() using the 'more_pages' argument.
In the first form the current setting of more_paging is returned; in the second form a more_paging setting is configured and the previous setting returned.


=item B<progress_dots()> - configure activity dots for cmd() and cmd_prompted() methods

  $prevBytesPerDot = $obj->progress_dots($bytesPerDot);

With this method it is possible to enable cmd() - and cmd_prompted() - to print activity dots (....) as input data is read from the host device. This is useful if the command sent to the host device returns large amount of data (e.g. "show tech") and/or it takes a long time for the host device to complete the command and return a CLI prompt.
To enable the functionality set $bytesPerDot to a non zero value; this value will represent every how many bytes of input data read an activity dot will be printed. For example set a value of 1000.
To disable the functionality simply configure it with a zero value.
By default this functionality is disabled.


=item B<return_result()> - set whether cmd methods should return output or the success/failure of the command 

  $flag = $obj->return_result;

  $prev = $obj->return_result($flag);

This method gets or sets the setting for return_result for the object.
This applies to the cmd() and cmd_prompted() methods and determines whether these methods should return the success or failure of the issued command (i.e. a true/false value) or instead the output generated by the command. By default return_result is false (0) and the output of the command is returned.


=item B<last_cmd_success()> - Returns the result of the last command sent via a cmd method

  $result = $obj->last_cmd_success;

  $prev = $obj->last_cmd_success($result);

This method returns the outcome (true or false) of the last command sent to the host via any of the cmd() or cmd_prompted() methods. If the command generated no error messages on the host, then the command was successful and the result is true (1). If instead an error message was generated by the host, then the command is deemed unsuccesful and the result is false (0). The second form allows the outcome to be manually set.
Note that the same information can be directly obtained from the above mentioned cmd methods by simply enabling the 'return_result' object parameter, or method modifier.
Note also that this functionality is only available if the host is detected as an Avaya Networking product, i.e. the I<family_type> attribute is set to a value other than B<generic> - see attribute(). If the I<family_type> attribute is set to B<generic> then this method will always return undef.


=item B<last_cmd_errmsg()> - returns the last command error message received from connected host

  $msg = $obj->last_cmd_errmsg;

  $prev = $obj->last_cmd_errmsg($msg);

The first calling sequence returns the cmd error message associated with the object. Undef is returned if no error has been encountered yet. The second calling sequence sets the cmd error message for the object.
If the attached device is detected as an Avaya Networking product, i.e. the I<family_type> attribute is set to a value other than B<generic>, and a command is issued to the host via cmd() or cmd_prompted(), and this command generates an error on the host, then the last_cmd_success will be set to false and the actual error message will be available via this method. The string returned will include the device prompt + command echoed back by the device (on the first line) and the error message and pointer on subsequent lines. The error message will be held until a new command generates a new error message. In general, only call this method after checking that the last_cmd_success() method returns a false value.


=item B<cmd_confirm_prompt()> - set the Y/N confirm prompt expected from certain device CLI commands

  $string = $obj->cmd_confirm_prompt;

  $prev = $obj->cmd_confirm_prompt($string);

This method sets the Y/N confirm prompt used by the object instance to match confirmation prompts that Avaya Networking devices will generate on certain CLI commands.
The cmd() method will use this patterm match to detect these Y/N confirmation prompts and automatically feed a 'Y' to them so that the command is executed as you would expect when scripting the device - see cmd(). In the event you want to feed a 'N' instead, refer to cmd_prompted().
The default prompt match pattern used is:

  '[\(\[] *(?:[yY] *[\\\/] *[nN]|[nN] *[\\\/] *[yY]) *[\)\]] *[?:] *$'

The first form of this method allows reading the current setting; the latter will set the new Y/N prompt and return the previous setting.


=item B<cmd_initiated_prompt()> - Set the prompt that certain device CLI commands will generate to request additional info

  $string = $obj->cmd_initiated_prompt;

  $prev = $obj->cmd_initiated_prompt($string);

This method sets the prompt used by the object instance to match the prompt that certain Avaya Networking device CLI commands will generate to request additional info.
This is used exclusively by the cmd_prompted() method which is capable to detect these prompts and feed the required information to them. See cmd_prompted().
The default prompt match pattern used is:

  '[?:=][ \t]*$'

This method can also be used if you wish to feed a 'N' to Y/N prompts, unlike what is automaticaly done by the cmd() method.
The first form of this method allows reading the current setting; the latter will set the new prompt and return the previous setting.


=item B<cmd_feed_timeout()> - Set the number of times we skip command prompts before giving up

  $value = $obj->cmd_feed_timeout;

  $prev = $obj->cmd_feed_timeout($value);

If a CLI command is found to generate a prompt for additional data - i.e. a match was found for string defined by cmd_initiated_prompt() - and no data was provided to feed to the command (either because of insufficient feed data in cmp_promted() or if using cmd() which cannot supply any feed data) the cmd methods will automatically feed a carriage return to such prompts in the hope of getting to the next CLI prompt and return.
If however these command prompts for additional data were indefinite, the cmd methods would never return.
This method sets a limit to the number of times that an empty carriage return is fed to these prompts for more data for which we have no data to feed. When that happens the cmd method will timeout and the error mode action is performed.
The same value will also set an upper limit to how many times a 'y' is fed to Y/N confirm prompts for the same command in the cmd() method. 
The default value is set to 10.


=item B<wake_console()> - Set the character sequence to send to wake up device when connecting to console port

  $string = $obj->wake_console;

  $prev = $obj->wake_console($string);

When connecting to the serial console port of a device it is necessary to send some characters to trigger the device at the other end to respond. These characters can be defined using this method. By default the wake string is "\n" which attempts to ensure that we can recover a CLI prompt or login prompt from the device regardless of whether it was left at the login banner, or in the Menu based CLI, or in the midst of a --more-- prompt paging previous output. The wake string is sent when connecting via Serial port as well as when connecting via Telnet but with a TCP port other than 23 (i.e. via a Terminal Server device). Setting the wake sequence to the empty string, will disable it.


=item B<debug()> - set debugging

  $debugLevel = $obj->debug;

  $prev = $obj->debug($debugLevel);

Enables debugging for the object methods and on underlying modules.
In the first form the current debug level is returned; in the second form a debug level is configured and the previous setting returned.
By default debugging is disabled. To disable debugging set the debug level to 0.
The following debug levels are defined:

=over 4

=item *

0 : No debugging

=item *

1 : Basic debugging

=item *

2 : Extended debugging of login() and cmd() methods

=item *

3 : Turn on debug level 1 on parent Control::CLI

=item *

4 : Turn on debug level 2 on parent Control::CLI

=back


=item B<debug_file()> - set debug output file

  $fileName = $obj->debug_file;

  $prev = $obj->debug_file($fileName);

Opens a file to print debug messages to. An empty string will close the file.


=back




=head2 Methods to access Object read-only variables

=over 4

=item B<config_context> - read configuration context of last prompt

  $configContext = $obj->config_context;

Returns the configuration context included in the last prompt received from the host device.
For example if the last prompt received from the device was 'switch(config-if)#' this method will return 'config-if'.
While if the last prompt was in the form 'switch/config/ip#' this method will return '/config/ip'.
If the device was not in config mode at the last prompt, this method returns undef.


=item B<enable_password> - read enable password provided

  $enablePassword = $obj->enable_password;

Returns the last enable password which was successfully used in the enable() method, or undef otherwise.
Of the supported family types only the WLAN2300 requires a password to access privExec mode. 


=back



=head2 Methods overridden from Control::CLI 

=over 4

=item B<connect()> - connect to host

=item B<login()> - handle login for Telnet / Serial port 

=item B<cmd()> - Sends a CLI command to host and returns output data

=item B<change_baudrate()> - Change baud rate on current serial connection

=item B<prompt()> - set the CLI prompt match pattern for this object

=item B<disconnect> - disconnect from host

=item B<debug()> - set debugging

=back



=head2 Methods inherited from Control::CLI 

=over 4

=item B<read()> - read block of data from object

=item B<readwait()> - read in data initially in blocking mode, then perform subsequent non-blocking reads for more

=item B<waitfor()> - wait for pattern in the input stream

=item B<put()> - write data to object

=item B<print()> - write data to object with trailing output_record_separator

=item B<printlist()> - write multiple lines to object each with trailing output_record_separator

=item B<input_log()> - log all input sent to host

=item B<output_log()> - log all output received from host

=item B<dump_log()> - log hex and ascii for both input and output stream

=item B<eof> - end-of-file indicator

=item B<break> - send the break signal

=item B<close> - disconnect from host

=back


=head2 Error Handling Methods inherited from Control::CLI

=over 4

=item B<errmode()> - define action to be performed on error/timeout 

=item B<errmsg()> - last generated error message for the object 

=item B<error()> - perform the error mode action

=back


=head2 Methods to set/read Object variables inherited from Control::CLI

=over 4

=item B<timeout()> - set I/O time-out interval 

=item B<connection_timeout()> - set Telnet and SSH connection time-out interval 

=item B<read_block_size()> - set read_block_size for either SSH or Serial port 

=item B<blocking()> - set blocking mode for read methods

=item B<read_attempts()> - set number of read attempts used in readwait() method

=item B<return_reference()> - set whether read methods should return a hard reference or not 

=item B<output_record_separator()> - set the Output Record Separator automatically appended by print & cmd methods

=item B<prompt_credentials()> - set whether connect() and login() methods should be able to prompt for credentials 

=item B<username_prompt()> - set the login() username prompt match pattern for this object

=item B<password_prompt()> - set the login() password prompt match pattern for this object

=back


=head2 Methods to access Object read-only variables inherited from Control::CLI

=over 4

=item B<parent> - return parent object

=item B<ssh_channel> - return ssh channel object

=item B<connection_type> - return connection type for object

=item B<port> - return the TCP port / COM port for the connection

=item B<last_prompt> - returns the last CLI prompt received from host

=item B<username> - read username provided

=item B<password> - read password provided

=item B<passphrase> - read passphrase provided

=item B<handshake> - read handshake used by current serial connection

=item B<baudrate> - read baudrate used by current serial connection

=item B<parity> - read parity used by current serial connection

=item B<databits> - read databits used by current serial connection

=item B<stopbits> - read stopbits used by current serial connection

=back




=head1 CLASS METHODS inherited from Control::CLI

Class Methods which are not tied to an object instance.
The Control::CLI::AvayaData class expressly imports all of Control::CLI's class methods into itself.
However by default Control::CLI::AvayaData class does not import anything when it is use-ed.
The following list is a sub-set of those Control::CLI class methods.
These should be called using their fully qualified package name or else they can be expressly imported when loading this module:

	# Import useTelnet, useSsh, useSerial & useIPv6
	use Control::CLI::AvayaData qw(:use);

	# Import all of Control::CLI class methods
	use Control::CLI::AvayaData qw(:all);

=over 4

=item B<useTelnet> - can Telnet be used ?

=item B<useSsh> - can SSH be used ?

=item B<useSerial> - can Serial port be used ?

=item B<useIPv6> - can IPv6 be used with Telnet or SSH ?

=item B<promptClear()> - prompt for username in clear text

=item B<promptHide()> - prompt for password in hidden text

=item B<passphraseRequired()> - check if private key requires passphrase

=item B<parseMethodArgs()> - parse arguments passed to a method against list of valid arguments

=item B<suppressMethodArgs()> - parse arguments passed to a method and suppress selected arguments

=item B<parse_errmode()> - parse a new value for the error mode and return it if valid or undef otherwise

=back




=head1 AUTHOR

Ludovico Stevens <lstevens@cpan.org>

=head1 BUGS

Please report any bugs or feature requests to C<bug-control-cli-avayadata at rt.cpan.org>, or through
the web interface at L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Control-CLI-AvayaData>.  I will be notified, and then you'll automatically be notified of progress on your bug as I make changes.



=head1 DISCLAIMER

Note that this module is in no way supported or endorsed by Avaya Inc.


=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Control::CLI::AvayaData


You can also look for information at:

=over 4

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Control-CLI-AvayaData>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Control-CLI-AvayaData>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Control-CLI-AvayaData>

=item * Search CPAN

L<http://search.cpan.org/dist/Control-CLI-AvayaData/>

=back



=head1 LICENSE AND COPYRIGHT

Copyright 2014 Ludovico Stevens.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.


=cut

# End of Control::CLI::AvayaData
