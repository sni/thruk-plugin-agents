package Thruk::Utils::Agents;

use warnings;
use strict;

use Thruk::Base ();
use Thruk::Timer qw/timing_breakpoint/;
use Thruk::Utils::IO ();
use Thruk::Utils::Log qw/:all/;

=head1 NAME

Thruk::Utils::Agents - Utils for agents

=head1 METHODS

=cut

##########################################################
sub get_checks_checks_for_host {
    my($c, $hostname, $hostobj) = @_;
    # extract checks
    my $checks = Thruk::Base::array_group_by(get_services_checks($c, $hostname, $hostobj), "exists");
    for my $key (qw/new exists obsolete disabled/) {
        $checks->{$key} = [] unless defined $checks->{$key};
    }

    return($checks);
}

##########################################################
sub get_services_checks {
    my($c, $hostname, $hostobj) = @_;
    my $checks   = [];
    return($checks) unless $hostname;
    my $datafile = $c->config->{'tmp_path'}.'/agents/hosts/'.$hostname.'.json';
    if(-r $datafile) {
        my $data = Thruk::Utils::IO::json_lock_retrieve($datafile);
        $checks = _extract_checks($data->{'inventory'}) if $data->{'inventory'};
    }
    _set_checks_category($c, $hostobj, $checks) if $hostobj;

    return($checks);
}

##########################################################
# sets exists attribute for checks, can be:
# - exists: already exists as services
# - new: does not yet exist as services
# - obsolete: exists as services but not in inventory anymore
# - disabled: exists in inventory but is disabled by user config
sub _set_checks_category {
    my($c, $host, $checks) = @_;

    my $services = _host_services($c, $host);

    for my $chk (@{$checks}) {
        my $name = $chk->{'name'};
        # TODO: only use agents generated checks
        if($services->{$name}) {
            $chk->{'exists'} = 'exists';
            $chk->{'_svc'}   = $services->{$name};
        } else {
            $chk->{'exists'} = 'new';
        }
    }
    # TODO: set obsolete and disabled

    return
}

##########################################################
sub _host_services {
    my($c, $hostobj) = @_;
    my $objects = $c->{'obj_db'}->get_services_for_host($hostobj);
    return({}) unless $objects && $objects->{'host'};
    return($objects->{'host'});
}

##########################################################
sub _to_id {
    my($name) = @_;
    $name =~ s/[^a-zA-Z0-9._\-\/]/_/gmx;
    return($name);
}

##########################################################
sub _extract_checks {
    my($inventory) = @_;
    my $checks = [];

    # agent check itself
    push @{$checks}, { 'id' => 'version', 'name' => 'agent version', check => 'check_snclient_version'};
    push @{$checks}, { 'id' => 'inventory', 'name' => 'agent inventory', check => 'inventory', parent => 'agent version'};

    if($inventory->{'cpu'}) {
        push @{$checks}, { 'id' => 'cpu', 'name' => 'cpu', check => 'check_cpu', parent => 'agent version' };
    }

    if($inventory->{'memory'}) {
        push @{$checks}, { 'id' => 'mem', 'name' => 'memory', check => 'check_memory', parent => 'agent version' };
    }

    if($inventory->{'network'}) {
        for my $net (@{$inventory->{'network'}}) {
            push @{$checks}, { 'id' => 'net.'._to_id($net->{'name'}), 'name' => 'net '.$net->{'name'}, check => 'check_network', args => { "name" => $net->{'name'} }, parent => 'agent version' };
        }
    }

    if($inventory->{'drivesize'}) {
        for my $drive (@{$inventory->{'drivesize'}}) {
            push @{$checks}, { 'id' => 'df.'._to_id($drive->{'drive'}), 'name' => 'disk '.$drive->{'drive'}, check => 'check_drivesize', args => { "drive" => $drive->{'drive'} }, parent => 'agent version' };
        }
    }

    # TODO: process, services
    # TODO: move into modules

    return $checks;
}

##########################################################

1;
