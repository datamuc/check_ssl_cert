#!/usr/bin/perl

#    check_ssl_cert
#    Copyright (C) 2023  Danijel Tasov
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.


use Socket;
use Net::SSLeay qw(die_now die_if_ssl_error) ;
use Monitoring::Plugin;
use Data::Dumper;
use POSIX qw/strftime/;
$Data::Dumper::Indent = 1;
$Data::Dumper::Sortkeys = 1;
use Date::Parse;
use 5.10.0;

# Setup SSLeay
Net::SSLeay::load_error_strings();
Net::SSLeay::SSLeay_add_ssl_algorithms();
Net::SSLeay::randomize();

$SIG{ALRM} = sub {
    print "check timed out";
    exit(3);
};

sub main {
    my $np = Monitoring::Plugin->new( shortname => 'CERT', usage=>'' );
    $np->add_arg( spec => 'host|H=s', required => 1, help=>'' );
    $np->add_arg( spec => 'port|p=i' , required => 1, help=>'', default=>443);
    $np->add_arg(
        spec => 'capath|P=s',
        default => '/etc/ssl/certs/ca-certificates.crt',
        help=>'check the chain against this ca bundle'
    );
    $np->add_arg(
        spec => 'warning|C=i',
        default => 10,
        help=>'emit warning if any of the certs in the chain expire within this number of days'
    );
    $np->getopts;
    alarm($np->opts->timeout);

    my $data;
    eval {
        $data = collect($np); 1
    } or do {
        $np->nagios_die($@);
    };

    check($np, $data); # this doesn't return
}

sub check {
    my ($np, $data) = @_;

    # Check the chain
    if(! $data->{verify_success}) {
        $np->nagios_exit(CRITICAL,
            "Certificate chain doesn't validate against ".$np->opts->capath."\n".
            '<pre>'.Dumper($data).'</pre>'
        );
    }

    my $expire_check = 0;
    my @expire_messages = ();
    my $day = 60 * 60 * 24;

    # check notAfter
    for my $m ( @{ $data->{verification_messages} } ) {
        my $remain = $m->{notAfter} - time;
        $remain = sprintf('%.2f', $remain / $day);
        $m->{remain} = $remain;
        if($m->{notAfter} < time ) {
            push @expire_messages,
                "$m->{subject} in chain expired ($m->{notAfterStr})";
            $expire_check = 2 if $expire_check <= 2;
        } elsif ($m->{notAfter} - time < ($np->opts->warning + 1) * ($day)) {
            push @expire_messages,
                "$m->{subject} expires in $remain days ($m->{notAfterStr})";
            $expire_check = 1 if $expire_check <= 1;
        }
    }

    if ($expire_check == 1) {
        $np->nagios_exit(WARNING, join(", ", @expire_messages)."\n<pre>".Dumper($data)."</pre>")
    } elsif($expire_check == 2) {
        $np->nagios_exit(CRITICAL, join(", ", @expire_messages))
    }

    my $peer = $data->{peer};
    $peer->{remain} = sprintf '%.2f', ($peer->{notAfter} - time) / $day;
    $np->nagios_exit(OK,
        "Cert expires in $peer->{remain} days ($peer->{notAfterStr})".
        # FIXME remove this debug output after testing
        "\n<pre>".Dumper($data)."</pre>"
    );
}

sub collect {
    my $np = shift;
    my $data = {};
    my $verify_success = 1;

    my $verify = sub {
        my ($ok, $ctx_store) = @_;
        my ($certname,$cert,$error, $notAfter, $notAfterStr);
        if ($ctx_store) {
            $cert = Net::SSLeay::X509_STORE_CTX_get_current_cert($ctx_store);
            $error = Net::SSLeay::X509_STORE_CTX_get_error($ctx_store);
            $issuer = Net::SSLeay::X509_NAME_oneline(
                Net::SSLeay::X509_get_issuer_name($cert));
            $subject = Net::SSLeay::X509_NAME_oneline(
                Net::SSLeay::X509_get_subject_name($cert));
            $verifyError = Net::SSLeay::X509_verify_cert_error_string($error);
            $error &&= Net::SSLeay::ERR_error_string($error);
            $notAfterStr = Net::SSLeay::P_ASN1_UTCTIME_put2string(
                Net::SSLeay::X509_get_notAfter($cert));
            $notAfter = str2time($notAfterStr);
        }
        push @{ $data->{verification_messages} }, {
            error=>$error,
            ok=>$ok,
            cert=>$cert,
            subject=>$subject,
            issuer=>$issuer,
            notAfter=>$notAfter,
            verifyError=>$verifyError,
            notAfterStr=>strftime "%Y-%m-%d %H:%M:%S", gmtime $notAfter
        };
        $verify_success &&= $ok;
        return 1; # always ok, the result is checked later
    };

    # set up connection
    ($dest_serv, $port) = ($np->opts->host, $np->opts->port);
    $dest_ip = gethostbyname ($dest_serv);
    $dest_serv_params  = sockaddr_in($port, $dest_ip);
    socket  (my $s, &AF_INET, &SOCK_STREAM, 0)  or die "socket: $!";
    connect ($s, $dest_serv_params)             or die "connect: $!";
    select  ($s); $| = 1; select (STDOUT);      # Eliminate STDIO buffering

    # setup ssl and collect data
    $ctx = Net::SSLeay::CTX_new() or nagios_die("Failed to create SSL_CTX $!");

    my $ca = $np->opts->capath;
    my @ca_paths = -d $ca ? ('',$ca) : ($ca,'');
    Net::SSLeay::CTX_load_verify_locations($ctx, $ca_paths[0], $ca_paths[1]);

    Net::SSLeay::CTX_set_options($ctx, &Net::SSLeay::OP_ALL)
         and die_if_ssl_error("ssl ctx set options");
    $ssl = Net::SSLeay::new($ctx) or nagios_die("Failed to create SSL $!");

    Net::SSLeay::set_verify ($ssl, Net::SSLeay::VERIFY_PEER, $verify);
    Net::SSLeay::set_fd($ssl, fileno($s));   # Must use fileno
    $res = Net::SSLeay::connect($ssl) and die_if_ssl_error("ssl connect");

    $data->{cipher}=Net::SSLeay::get_cipher($ssl);
    $data->{verify_success}=$verify_success;

    my $peer = Net::SSLeay::get_peer_certificate($ssl);
    $data->{peer} = {
        ctx => $peer,
        issuer => Net::SSLeay::X509_NAME_oneline(
            Net::SSLeay::X509_get_issuer_name($peer)),
        subject => Net::SSLeay::X509_NAME_oneline(
            Net::SSLeay::X509_get_subject_name($peer)),
        notAfterStr => Net::SSLeay::P_ASN1_UTCTIME_put2string(
            Net::SSLeay::X509_get_notAfter($peer)),
    };
    $data->{peer}->{notAfter} = str2time($data->{peer}->{notAfterStr});

    return $data;
}

main;
