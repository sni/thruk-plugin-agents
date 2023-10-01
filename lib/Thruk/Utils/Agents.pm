package Thruk::Utils::Agents;

use warnings;
use strict;

use Thruk::Base ();
use Thruk::Timer qw/timing_breakpoint/;
use Thruk::Utils::IO ();
use Thruk::Utils::Log qw/:all/;

use Cpanel::JSON::XS qw/decode_json/;

=head1 NAME

Thruk::Utils::Agents - Utils for agents

=head1 METHODS

=cut

##########################################################

=head2 get_agent_checks_for_host

    get_agent_checks_for_host($c, $hostname, $hostobj)

returns list of checks for this host grouped by type (new, exists, obsolete, disabled).

=cut
sub get_agent_checks_for_host {
    my($c, $hostname, $hostobj) = @_;
    # extract checks and group by type
    my $checks = Thruk::Base::array_group_by(get_services_checks($c, $hostname, $hostobj), "exists");
    for my $key (qw/new exists obsolete disabled/) {
        $checks->{$key} = [] unless defined $checks->{$key};
    }

    return($checks);
}

##########################################################

=head2 get_services_checks

    get_services_checks($c, $hostname, $hostobj)

returns list of checks as flat list.

=cut
sub get_services_checks {
    my($c, $hostname, $hostobj) = @_;
    my $checks   = [];
    return($checks) unless $hostname;
    my $datafile = $c->config->{'tmp_path'}.'/agents/hosts/'.$hostname.'.json';
    if(-r $datafile) {
        my $data = Thruk::Utils::IO::json_lock_retrieve($datafile);
        $checks = _extract_checks($data->{'inventory'}) if $data->{'inventory'};
    }
    _set_checks_category($c, $hostobj, $checks);

    return($checks);
}

##########################################################
# sets exists attribute for checks, can be:
# - exists: already exists as services
# - new: does not yet exist as services
# - obsolete: exists as services but not in inventory anymore
# - disabled: exists in inventory but is disabled by user config
sub _set_checks_category {
    my($c, $hostobj, $checks) = @_;

    my $services = $hostobj ? get_host_agent_services($c, $hostobj) : {};

    my $settings = $hostobj->{'conf'}->{'_AGENT_CONFIG'} ? decode_json($hostobj->{'conf'}->{'_AGENT_CONFIG'}) : {};

    my $existing = {};
    for my $chk (@{$checks}) {
        my $name = $chk->{'name'};
        $existing->{$chk->{'id'}} = 1;
        my $svc = $services->{$name};
        if($svc && $svc->{'conf'}->{'_AGENT_AUTO_CHECK'}) {
            $chk->{'exists'} = 'exists';
            $chk->{'_svc'}   = $svc;
        } else {
            if($settings && $settings->{'disabled'} && Thruk::Base::array_contains($chk->{'id'}, $settings->{'disabled'})) {
                $chk->{'exists'} = 'disabled';
            } else {
                $chk->{'exists'} = 'new';
            }
        }
    }

    for my $name (sort keys %{$services}) {
        my $svc = $services->{$name};
        my $id  = $svc->{'conf'}->{'_AGENT_AUTO_CHECK'};
        next unless $id;
        next if $existing->{$id};

        push @{$checks}, { 'id' => $id, 'name' => $name, exists => 'obsolete'};
    }

    return
}

##########################################################
sub get_host_agent_services {
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
    push @{$checks}, { 'id' => 'inventory', 'name' => 'agent inventory', check => 'inventory', parent => 'agent version'};
    push @{$checks}, { 'id' => 'version', 'name' => 'agent version', check => 'check_snclient_version'};

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
