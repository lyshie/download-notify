#!/usr/local/bin/perl -w
#===============================================================================
#
#         FILE:  notify.pl
#
#        USAGE:  ./notify.pl [oz.nthu.edu.tw] [2010-05-27] [oz-2010-05-27.txt]
#
#  DESCRIPTION:  Web Traffic Notification
#
#      OPTIONS:  ---
# REQUIREMENTS:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Shie, Li-Yi (lyshie@mx.nthu.edu.tw)
#      COMPANY:  NTHU
#      VERSION:  1.0
#      CREATED:  05/28/2010 10:02:07 AM
#     REVISION:  ---
#===============================================================================

use strict;
use warnings;

use FindBin qw($Bin);
use MIME::Lite;
use MIME::Words qw(encode_mimeword);
use Data::Dump;

my %VARS = (
    'user'   => '',
    'domain' => '',
    'date'   => '',
    'size'   => '',
    'count'  => '',
    'uri'    => '',
);

my %TOP_USERS     = ();
my %TOP_USERS_URI = ();

my $TEMPLATE_MSG = "";

sub getTemplate {
    open( FH, "$Bin/mesg.tmpl" );
    while (<FH>) {
        $TEMPLATE_MSG .= $_;
    }
    close(FH);
}

sub replaceTemplate {
    my ( $mesg, $ref ) = @_;

    foreach ( keys(%$ref) ) {
        my $key = uc($_);
        $mesg =~ s/#\_$key\_#/$ref->{$_}/g;
    }

    return $mesg;
}

sub setTemplate {
    foreach ( keys(%TOP_USERS) ) {
        $TOP_USERS{$_}{'uri'} = $TOP_USERS_URI{$_};
        my $body = replaceTemplate( $TEMPLATE_MSG, $TOP_USERS{$_} );
        my $msg = MIME::Lite->new(
            From    => 'DO-NO-REPLY <null@cc.nthu.edu.tw>',
            To      => 'lyshie@cc.nthu.edu.tw',
            Bcc     => 'lyshie@cc.nthu.edu.tw',
            Subject => encode_mimeword(
                '[注意] 個人網頁下載量偏高通知 ('
                  . $TOP_USERS{$_}{'date'} . ')',
                'B',
                'utf-8'
            ),
            Encoding => 'base64',
            Type     => 'text/plain',
            Data     => $body,
        );

        $msg->attr( 'content-type.charset' => 'UTF-8' );

        MIME::Lite->send( 'smtp', 'smtp.cc.nthu.edu.tw', Timeout => 60 );
        $msg->send();

        #print $body, "=" x 80, "\n";
    }
}

sub main {
    getTemplate();

    $VARS{'domain'} = $ARGV[0];    # oz
    $VARS{'date'}   = $ARGV[1];    # 2010-05-27
    my $logfile = $ARGV[2];        # oz-2010-05-27.txt

    my ( $flag_size, $flag_count, $flag_uri ) = ( 0, 0, '' );

    open( FH, "$Bin/reports/$logfile" );
    while (<FH>) {
        my $line = $_;
        chomp($line);

        if ( $line =~ m/^===== SHOW_TOP_USER \(BY SIZE\) =====$/ ) {
            $flag_size = 1;
            next;
        }
        elsif ( $line =~ m/^===== SHOW_TOP_USER \(BY COUNT\) =====$/ ) {
            $flag_count = 1;
            next;
        }
        elsif ( $line =~ m/^\[~(.+)\]$/ ) {
            $flag_uri = $1;
            next;
        }
        elsif ( $line eq '' ) {
            $flag_size = $flag_count = 0;
            $flag_uri = '';
            next;
        }

        if ( $flag_size || $flag_count ) {
            if ( index( $line, '*' ) == 0 ) {
                if ( $line =~
m/^\*\s+([\d\.]+)\s+(.+?)\s\(.+?\),\s+(.+)\s\(.+?\)\s\[~(.+?)\]$/
                  )
                {
                    $VARS{'size'}  = $2;
                    $VARS{'count'} = $3;
                    $VARS{'user'}  = $4;

                    $TOP_USERS{$4} = {%VARS};
                }
            }
        }

        if ( $flag_uri ne '' ) {
            $line =~ s/^\s+//g;
            $TOP_USERS_URI{$flag_uri} .=
              "  http://" . $TOP_USERS{$flag_uri}{'domain'} . "$line\n";
        }
    }
    close(FH);

    setTemplate();
}

main();
