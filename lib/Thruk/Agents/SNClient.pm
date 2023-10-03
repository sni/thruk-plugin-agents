package Thruk::Agents::SNClient;

use warnings;
use strict;

use Thruk::Base ();
use Thruk::Timer qw/timing_breakpoint/;
use Thruk::Utils::IO ();
use Thruk::Utils::Log qw/:all/;

use Cpanel::JSON::XS qw/decode_json/;

=head1 NAME

Thruk::Agents::SNClient - implements snclient based agent configuration

=cut

my $settings = {
    'type'      => 'snclient',
    'icon'      => 'snclient.png',
    'icon_dark' => 'snclient_dark.png',
};

=head1 METHODS

=cut

##########################################################

=head2 new

    new($c, $host)

returns agent object from livestatus host

=cut
sub new {
    my($class, $host) = @_;
    my $self = {};
    bless $self, $class;
    return($self);
}

##########################################################

=head2 settings

    settings()

returns settings for this agent

=cut
sub settings {
    return($settings);
}

##########################################################

1;
