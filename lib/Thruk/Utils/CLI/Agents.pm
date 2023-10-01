package Thruk::Utils::CLI::Agents;

=head1 NAME

Thruk::Utils::CLI::Agents - Agents CLI module

=head1 DESCRIPTION

The agents command handles agent configs.

=head1 SYNOPSIS

  Usage: thruk [globaloptions] agents [cmd]

=head1 OPTIONS

=over 4

=item B<help>

    print help and exit

=item B<check>

    run checks, ex. inventory

=back

=cut

use warnings;
use strict;

use Thruk::Utils::Agents ();
use Thruk::Utils::CLI ();
use Thruk::Utils::Log qw/:all/;

##############################################

=head1 METHODS

=head2 cmd

    cmd([ $options ])

=cut
sub cmd {
    my($c, $action, $commandoptions, $data, $src, $global_options) = @_;
    $c->stats->profile(begin => "_cmd_actions()");

    if(!$c->check_user_roles('authorized_for_admin')) {
        return("ERROR - authorized_for_admin role required", 1);
    }

    if(scalar @{$commandoptions} == 0) {
        return(Thruk::Utils::CLI::get_submodule_help(__PACKAGE__));
    }

    my $output = "unknown command, see help for available commands";
    my $rc     = 3;

    if(scalar @{$commandoptions} >= 2) {
        if($commandoptions->[0] eq 'check' && $commandoptions->[1] eq 'inventory') {
            my $host = $commandoptions->[1] // '';
            ($output, $rc) = _check_inventory($c, $host);
        }
    }

    eval {
        require Thruk::Controller::agents;
    };
    if($@) {
        _debug($@);
        return("agents plugin is not enabled.\n", 1);
    }

    $c->stats->profile(end => "_cmd_agents()");
    return($output, $rc);
}

##############################################
sub _check_inventory {
    my($c, $host) = @_;
    if(!$host) {
        return("usage: $0 agents check inventory <host>\n", 3);
    }
    my($output, $rc);

    my $checks = Thruk::Utils::Agents::get_agent_checks_for_host($c, $host);
    if(scalar @{$checks->{'new'}} > 0) {
        my @details;
        for my $chk (@{$checks->{'new'}}) {
            push @details, " - ".$chk->{'name'};
        }
        return(sprintf("WARNING - %s new checks found\n".join("\n", @details), scalar @{$checks->{'new'}}), 2);
    }

    return("OK - inventory unchanged\n", 0);
}

##############################################

=head1 EXAMPLES

Run inventory check for host localhost

  %> thruk check inventory localhost


See 'thruk agents help' for more help.

=cut

##############################################

1;
