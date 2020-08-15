#!/usr/bin/env perl

use strict;
use warnings;

# Find the values matching a prefix, and print Rust-y versions.
sub print_values {
    my ($prefix, @lines) = @_;
    foreach my $line (@lines) {
        if ($line =~ /#define ($prefix\w+)\s+(.*)/) {
            my $flag = $1;
            my $value = $2;
            $value =~ s/^\(//;
            $value =~ s/\)$//;
            if ($value =~ /1 << 0/) {
                # Sidestep clippy's "identity_op" warning
                print "pub const $flag: c_int = 1;\n";
            } else {
                print "pub const $flag: c_int = $value;\n";
            }
        }
    }
}

open(my $ARES_H, '<', 'c-ares/ares.h');
my @lines = <$ARES_H>;
close($ARES_H);

# Remove line comments.  In principle this is a bit fragile - what about
# quotations that contain text that looks like a comment?  But it's good
# enough.
s#/\*.*?\*/##gs for @lines;

# Trim trailing whitespace.
s/\s+$// for @lines;

print "use crate::ffi::ares_socket_t;\n";
print "use std::os::raw::c_int;\n";

print "\n";
print "// Library initialization flags\n";
print_values("ARES_LIB_INIT_", @lines);

print "\n";
print "// Error codes\n";
print "pub const ARES_SUCCESS: c_int = 0;\n";
print_values("ARES_E", @lines);

print "\n";
print "// Flag values\n";
print_values("ARES_FLAG_", @lines);

print "\n";
print "// Option mask values\n";
print_values("ARES_OPT_", @lines);

print "\n";
print "// Flags for nameinfo queries\n";
print_values("ARES_NI_", @lines);

print "\n";
print "// A non-existent file descriptor\n";
print "#[cfg(windows)]\n";
print "pub const ARES_SOCKET_BAD: ares_socket_t = !0;\n";
print "#[cfg(unix)]\n";
print "pub const ARES_SOCKET_BAD: ares_socket_t = -1;\n";

print "\n";
print "// ares_getsock() can return info about this many sockets\n";
print "pub const ARES_GETSOCK_MAXNUM: usize = 16;\n";
