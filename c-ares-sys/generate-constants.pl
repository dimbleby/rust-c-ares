#!/usr/bin/env perl

use strict;
use warnings;

open(ARES_H, 'c-ares/ares.h');
my @lines = <ARES_H>;
close(ARES_H);

print "extern crate libc;\n";
print "\n";
print "use ffi::ares_socket_t;\n";

print "\n";
print "// Library initialization flags\n";
foreach my $line (@lines) {
	if ($line =~ /#define (ARES_LIB_INIT_\w+)\s+(.*)/) {
	    print "pub const $1: libc::c_int = $2;\n";
	}
}

print "\n";
print "// Error codes\n";
print "pub const ARES_SUCCESS: libc::c_int = 0;\n";
foreach my $line (@lines) {
	if ($line =~ /#define (ARES_E\w+)\s+(.*)/) {
	    print "pub const $1: libc::c_int = $2;\n";
	}
}

print "\n";
print "// Flag values\n";
foreach my $line (@lines) {
	if ($line =~ /#define (ARES_FLAG_\w+)\s+(.*)/) {
	    print "pub const $1: libc::c_int = $2;\n";
	}
}

print "\n";
print "// Option mask values\n";
foreach my $line (@lines) {
	if ($line =~ /#define (ARES_OPT_\w+)\s+(.*)/) {
	    print "pub const $1: libc::c_int = $2;\n";
	}
}

print "\n";
print "// Flags for nameinfo queries\n";
foreach my $line (@lines) {
	if ($line =~ /#define (ARES_NI_\w+)\s+(.*)/) {
	    print "pub const $1: libc::c_int = $2;\n";
	}
}

print "\n";
print "// A non-existent file descriptor\n";
print "pub const ARES_SOCKET_BAD: ares_socket_t = -1;\n";

print "\n";
print "// ares_getsock() can return info about this many sockets\n";
print "pub const ARES_GETSOCK_MAXNUM: usize = 16;\n";
