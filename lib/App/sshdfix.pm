package App::sshdfix;
use strict;
use warnings;
use 5.010; # Newest version supported by CentOS 6
our $VERSION = '0.001';
use Exporter 'import';
our @EXPORT_OK = qw( fix_sshd );

if (sshd_version() >= 6.7) {
  # sshd versions newer than 6.7
  # These will be added if not present
  my $host_keys_yes = (
    '/etc/ssh/ssh_host_ed25519_key',
    '/etc/ssh/ssh_host_rsa_key',
    '/etc/ssh/ssh_host_ecdsa_key',
  );
  my %config_yes = (
    KexAlgorithms => 'curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256',
    Ciphers => 'chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr',
    MACs    => 'hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com',
    UsePrivilegeSeparation => 'sandbox',
  );
}
elsif (sshd_version() >= 5.3) {
  # Old ssh version 5.3 and above
  my @host_keys_yes = (
    '/etc/ssh/ssh_host_rsa_key',
    '/etc/ssh/ssh_host_ecdsa_key',
  );
  my %config_yes = (
    KexAlgorithms => 'diffie-hellman-group-exchange-sha256',
    MACs => 'hmac-sha2-512,hmac-sha2-256',
    Ciphers => 'aes256-ctr,aes192-ctr,aes128-ctr'
  );
}

# These options will be set if the unsafe option is given
my %unsafe_yes = (
  PermitRootLogin        => 'no',
  PasswordAuthentication => 'no',
  AuthenticationMethods  => 'publickey',
);

# fix_sshd(\%opt)
# Fix the sshd settings to use modern ciphers and keys
sub fix_sshd {
  my $opt_ref = shift;
  my $sshd_config_file = $opt_ref->{'config'} //= '/etc/ssh/sshd_config';
  my $config_ref = read_config($sshd_config_file);

  my $lines_ref = read_file_lines($sshd_config_file);
  fix_hostkeys($sshd_config_file, $config_ref, $lines_ref);
  #set_directive('MadeUpName', ['no'], $sshd_config_file, $config_ref, $lines_ref);
  flush_file_lines($sshd_config_file, $lines_ref);
  return;
}

sub sshd_version {
  my $out = `sshd -v 2>&1 </dev/null`;
  if ($out =~ /(OpenSSH.([0-9\.]+))/i) {
	  return $2;
  }
  else {
    die "Could not detect OpenSSH version.";
  }
}

# return an array ref containing the lines of sshd_config, with each line
# in a hash, with name, values, and line number.
sub read_config {
  my ($cf) = @_;
  my $lnum = 0;
  my @rv;
  open(my $CONF,  '<', $cf) or die
    "Could not open $cf: $!";
  while(<$CONF>) {
	  s/\r|\n//g;
	  s/^\s*#.*$//g;
	  my ($name, @values) = split(/\s+/, $_);
	  if ($name) {
		  my $dir = { 'name' => $name,
			            'values' => \@values,
			            'line' => $lnum };
		  push(@rv, $dir);
		}
	  $lnum++;
	}
  close($CONF);
  return \@rv;
}

# set_directive(name, &config, &values, &lines, [before])
sub set_directive {
  my ($name, $values_ref, $config_file, $config_ref, $lines_ref, $before) = @_;
  my @o = find($name, $config_ref);
  my @n = @{$values_ref};
  $before = defined($before) ? find($before, $config_ref) : undef;
  for(my $i=0; $i<@o || $i<@n; $i++) {
    if ($o[$i] && $n[$i]) {
      # Replacing a line
      $lines_ref->[$o[$i]->{'line'}] = "$name $n[$i]";
    }
    elsif ($o[$i]) {
      # Removing a line
      splice(@$lines_ref, $o[$i]->{'line'}, 1);
      foreach my $c (@{$config_ref}) {
        if ($c->{'line'} > $o[$i]->{'line'}) {
          $c->{'line'}--;
        }
      }
    }
    elsif ($n[$i] && !$before) {
      # Adding a line at the end, but before any Match
      my $ll = $config_ref->[@{$config_ref}-1]->{'line'};
      foreach my $m (find("Match", $config_ref)) {
        $ll = $m->{'line'} - 1;
        last;
      }
      splice(@$lines_ref, $ll+1, 0, "$name $n[$i]");
    }
    elsif ($n[$i] && $before) {
      # Adding a line before the first instance of some directive
      splice(@$lines_ref, $before->{'line'}, 0, "$name $n[$i]");
      foreach my $c (@{$config_ref}) {
        if ($c->{'line'} >= $before->{'line'}) {
          $c->{'line'}--;
        }
      }
    }
  }
  return $lines_ref;
}

# find_value(name, &config)
sub find_value {
  my ($name, $config_ref) = @_;
  foreach my $c (@{$config_ref}) {
    if (lc($c->{'name'}) eq lc($name)) {
      return wantarray ? @{$c->{'values'}} : $c->{'values'}->[0];
    }
  }
  return wantarray ? ( ) : undef;
}

# find(name, &config)
sub find {
  my ($name, $config_ref) = @_;
  my @rv;
  foreach my $c (@{$config_ref}) {
    if (lc($c->{'name'}) eq lc($name)) {
      push(@rv, $c);
    }
  }
  return wantarray ? @rv : $rv[0];
}

sub fix_hostkeys {
  my ($config_file, $config_ref, $lines_ref) = @_;

  my @key_config = find('HostKey', $config_ref);
  my @keys;
  # Remove any hostkeys that are considered insecure
  foreach my $key (@key_config) {
    push(@keys, $key->{'values'}[0]);
    unless (grep(/$key->{'values'}[0]/, @host_keys_yes)) {
      splice(@$lines_ref, $key->{'line'}, 1, "#HostKey $key->{'values'}[0]");
    }
  }
  # Enable modern hostkeys, if not already on
  foreach my $enable_key (@host_keys_yes) {
    # is the key already in the file?
    unless (grep (/$enable_key/, @keys)) {
      # find the first HostKey and insert before it
      my $l = find('HostKey', $config_ref);
      splice(@$lines_ref, $l->{'line'}, 0, "HostKey $enable_key");
    }
  }
}

sub read_file_lines {
  my $file = shift;
  open (my $handle, '<', $file) or die "Failed to open $file: $!";
  chomp(my @lines = <$handle>);
  close $handle;
  return \@lines;
}

sub flush_file_lines {
  use File::Temp qw( tempfile );
  use File::Copy qw( cp );
  my ($file, $lines_ref) = @_;
  my ($handle, $tmp) = tempfile(
    DIR    => $ENV{'HOME'},
    UNLINK => 1 ) or
    die "Failed to open tempfile for writing: $!";
  print $handle join("\n", @{$lines_ref}) . "\n" or
    die "Could not write to $tmp: $!";
  close ($handle);
  cp ($tmp, $file);
  return;
}

1;
