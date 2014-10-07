#!/usr/bin/perl -w
#===============================================================================
#
#         FILE:  apache_log.pl
#
#        USAGE:  cat <ARGV> | ./apache_log.pl < <ARGV>
#
#  DESCRIPTION:  Apache Access Log Parser
#
#      OPTIONS:  ---
# REQUIREMENTS:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Shie, Li-Yi (lyshie@mx.nthu.edu.tw)
#      COMPANY:  NTHU
#      VERSION:  1.0
#      CREATED:  西元2010年05月06日 22時31分27秒
#     REVISION:  ---
#===============================================================================

use strict;
use warnings;

use URI;
use URI::Escape;
use URI::Split qw(uri_split);

use Encode;
use Encode::Guess qw(big5);

use Number::Format;

my $NF = new Number::Format(
    -thousands_sep => ',',
    -decimal_point => '.',
);

my $DETAIL      = 1;
my $RANK        = 20;
my $TOTAL_SIZE  = 0;
my $TOTAL_COUNT = 0;
my %URI_SIZE    = ();    # top uri size
my %URI_COUNT   = ();    # top uri count
my %USER_SIZE   = ();    # top user home size
my %USER_COUNT  = ();    # top user home count

my %USER_URI     = ();
my %MARKED_USERS = ();

my $PAT_IPV4 = qr/\d+\.\d+\.\d+\.\d+/;
my $PAT_IPV6 = qr/[\d\:]+/;

my $PAT_SYSLOG      = qr/^.+?\[.+?\]/;
my $PAT_CLIENT      = qr/($PAT_IPV4|$PAT_IPV6)/;    # capture
my $PAT_RFC1413     = qr/(.+?)/;                    # capture
my $PAT_USERID      = qr/(.+?)/;                    # capture
my $PAT_DATETIME    = qr/\[(.+?)\]/;                # capture
my $PAT_REQUEST     = qr/"(.+?)"/;                  # capture
my $PAT_STATUS_CODE = qr/(\d+|\-)/;                 # capture
my $PAT_SIZE        = qr/(\d+|\-)/;                 # capture
my $PAT_REFERER     = qr/"(.+?)"/;                  # capture
my $PAT_UA          = qr/"(.+?)"/;                  # capture

my $PAT_ACCESS_LOG = qr/$PAT_SYSLOG      \s+
                        $PAT_CLIENT      \s+    #1
                        $PAT_RFC1413     \s+    #2
                        $PAT_USERID      \s+    #3
                        $PAT_DATETIME    \s+    #4
                        $PAT_REQUEST     \s+    #5
                        $PAT_STATUS_CODE \s+    #6
                        $PAT_SIZE        \s+    #7
                        ($PAT_REFERER)*  (\s+)* #8 (optional)
                        ($PAT_UA)*              #9 (optional)
                        /xms;

# strip symbol `~` to get username
sub get_username {
    my ($str) = @_;

    my $result = '';

    if ( $str =~ m/^(~.+)$/ ) {
        $result = $1;
    }

    return $result;
}

# strip query parameters to get uri and
# convert all uri to UTF-8 encoding
sub get_uri {
    my ($req_str) = @_;

    my $result = '';

    # GET      /cgi-bin/test.cgi?key=value&key2=value2  HTTP/1.1
    # $method  $resource                                $protocol
    #          $path             $query
    my ( $method, $resource, $protocol ) = split( /\s+/, $req_str );
    $resource = defined($resource) ? $resource : '';

    my ( $scheme, $auth, $path, $query, $frag ) = uri_split($resource);

    if ($path) {
        $result = uri_unescape($path);

        #        $result = encode( 'utf-8', decode( "Guess", $result ) );
    }

    return $result;
}

sub show_top_uri_by_size {
    my ($top) = @_;
    $top = defined($top) ? $top : 10;

    print("\n===== SHOW_TOP_URI (BY SIZE) =====\n");

    my $i = 1;
    foreach my $uri (
        sort {
                 ( $URI_SIZE{$b} <=> $URI_SIZE{$a} )
              || ( $URI_COUNT{$b} <=> $URI_COUNT{$a} )
        }
        keys(%URI_SIZE)
      )
    {
        my $mark = '';
        if ( ( $URI_SIZE{$uri} / $TOTAL_SIZE ) > 0.1 ) {
            if ( $URI_SIZE{$uri} > 1024 * 1024 * 1024 ) {
                $mark = '*';
            }
        }

        printf(
            "%1s%4d. %10s (%4.1f%%), %10s (%4.1f%%) [%s]\n",
            $mark,
            $i,
            $NF->format_bytes( $URI_SIZE{$uri}, mode => "iec" ),
            ( $URI_SIZE{$uri} / $TOTAL_SIZE ) * 100,
            $NF->format_number( $URI_COUNT{$uri} ),
            ( $URI_COUNT{$uri} / $TOTAL_COUNT ) * 100,
            $uri
        );

        $i++;
        last if ( $i > $top );
    }
}

sub show_top_uri_by_count {
    my ($top) = @_;
    $top = defined($top) ? $top : 10;

    print("\n===== SHOW_TOP_URI (BY COUNT) =====\n");

    my $i = 1;
    foreach my $uri (
        sort {
                 ( $URI_COUNT{$b} <=> $URI_COUNT{$a} )
              || ( $URI_SIZE{$b} <=> $URI_SIZE{$a} )
        }
        keys(%URI_SIZE)
      )
    {
        my $mark = '';
        if ( ( $URI_COUNT{$uri} / $TOTAL_COUNT ) > 0.1 ) {
            if ( $URI_COUNT{$uri} > 1000 ) {
                $mark = '*';
            }
        }

        printf(
            "%1s%4d. %10s (%4.1f%%), %10s (%4.1f%%) [%s]\n",
            $mark,
            $i,
            $NF->format_bytes( $URI_SIZE{$uri}, mode => "iec" ),
            ( $URI_SIZE{$uri} / $TOTAL_SIZE ) * 100,
            $NF->format_number( $URI_COUNT{$uri} ),
            ( $URI_COUNT{$uri} / $TOTAL_COUNT ) * 100,
            $uri
        );

        $i++;
        last if ( $i > $top );
    }
}

sub show_top_user_by_size {
    my ($top) = @_;
    $top = defined($top) ? $top : 10;

    print("\n===== SHOW_TOP_USER (BY SIZE) =====\n");

    my $i = 1;
    foreach my $user (
        sort {
                 ( $USER_SIZE{$b} <=> $USER_SIZE{$a} )
              || ( $USER_COUNT{$b} <=> $USER_COUNT{$a} )
        }
        keys(%USER_SIZE)
      )
    {
        my $mark = '';
        if ( ( $USER_SIZE{$user} / $TOTAL_SIZE ) > 0.1 ) {
            if ( $USER_SIZE{$user} > 1024 * 1024 * 1024 ) {
                $mark = '*';
                $MARKED_USERS{$user} = 1;
            }
        }

        printf(
            "%1s%4d. %10s (%4.1f%%), %10s (%4.1f%%) [%s]\n",
            $mark,
            $i,
            $NF->format_bytes( $USER_SIZE{$user}, mode => "iec" ),
            ( $USER_SIZE{$user} / $TOTAL_SIZE ) * 100,
            $NF->format_number( $USER_COUNT{$user} ),
            ( $USER_COUNT{$user} / $TOTAL_COUNT ) * 100,
            $user
        );

        $i++;
        last if ( $i > $top );
    }
}

sub show_top_user_by_count {
    my ($top) = @_;
    $top = defined($top) ? $top : 10;

    print("\n===== SHOW_TOP_USER (BY COUNT) =====\n");

    my $i = 1;
    foreach my $user (
        sort {
                 ( $USER_COUNT{$b} <=> $USER_COUNT{$a} )
              || ( $USER_SIZE{$b} <=> $USER_SIZE{$a} )
        }
        keys(%USER_SIZE)
      )
    {
        my $mark = '';
        if ( ( $USER_COUNT{$user} / $TOTAL_COUNT ) > 0.1 ) {
            if ( $USER_COUNT{$user} > 1000 ) {
                $mark = '*';
                $MARKED_USERS{$user} = 1;
            }
        }

        printf(
            "%1s%4d. %10s (%4.1f%%), %10s (%4.1f%%) [%s]\n",
            $mark,
            $i,
            $NF->format_bytes( $USER_SIZE{$user}, mode => "iec" ),
            ( $USER_SIZE{$user} / $TOTAL_SIZE ) * 100,
            $NF->format_number( $USER_COUNT{$user} ),
            ( $USER_COUNT{$user} / $TOTAL_COUNT ) * 100,
            $user
        );

        $i++;
        last if ( $i > $top );
    }
}

sub show_marked_user_uri {
    foreach my $user ( keys(%MARKED_USERS) ) {
        print "\n[$user]\n";
        my @uris = keys( %{ $USER_URI{$user} } );
        foreach ( sort(@uris) ) {
            print "  $_\n";
        }
    }
}

sub main {
    my $total   = 0;
    my $match   = 0;
    my $unmatch = 0;
    while (<ARGV>) {
        $total++;
        print STDERR "Processing $total lines...\n"
          if ( $total % 10000 == 0 );

        if ( $_ =~ m/$PAT_ACCESS_LOG/ ) {
            $match++;

            my $code = defined($6) ? $6 : '';
            next if ( index( $code, '2' ) != 0 );

            # URI #
            my $uri = get_uri($5);
            my $size = ( $7 eq '-' ) ? 0 : $7;

            $TOTAL_SIZE += $size;
            $TOTAL_COUNT++;

            if ( defined( $URI_SIZE{$uri} ) ) {
                $URI_SIZE{$uri} += $size;
                $URI_COUNT{$uri}++;
            }
            else {
                $URI_SIZE{$uri}  = $size;
                $URI_COUNT{$uri} = 1;
            }

            # USER #
            my $u = URI->new($uri);
            my ( $empty, $top_path ) = $u->path_segments();

            my $username = get_username($top_path);
            if ( $top_path && $username ) {
                $USER_URI{$username}{$uri} = 1;
                if ( defined( $USER_SIZE{$top_path} ) ) {
                    $USER_SIZE{$top_path} += $size;
                    $USER_COUNT{$top_path}++;
                }
                else {
                    $USER_SIZE{$top_path}  = $size;
                    $USER_COUNT{$top_path} = 1;
                }
            }
        }
        else {
            $unmatch++;
            print STDERR "$_\n";
        }
    }

    printf( "%s\n", scalar( localtime( time() ) ) );
    printf(
        "Total %s lines, match %s lines (%.1f%%).\n",
        $NF->format_number($total),
        $NF->format_number($match),
        ( $match / $total ) * 100
    );
    printf(
        "Total size %s, total count %s.\n",
        $NF->format_bytes( $TOTAL_SIZE, mode => "iec" ),
        $NF->format_number($TOTAL_COUNT)
    );
    printf(
        "Total uri %s, total user %s.\n",
        $NF->format_number( scalar( keys(%URI_COUNT) ) ),
        $NF->format_number( scalar( keys(%USER_COUNT) ) )
    );

    show_top_uri_by_size($RANK)  if $DETAIL;
    show_top_uri_by_count($RANK) if $DETAIL;
    show_top_user_by_size($RANK);
    show_top_user_by_count($RANK);

    show_marked_user_uri();
}

main();
