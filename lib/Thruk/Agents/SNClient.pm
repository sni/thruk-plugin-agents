package Thruk::Agents::SNClient;

use warnings;
use strict;
use Carp qw/confess/;
use Cpanel::JSON::XS qw/decode_json/;

use Monitoring::Config::Object ();
use Thruk::Controller::conf ();
use Thruk::Timer qw/timing_breakpoint/;
use Thruk::Utils ();
use Thruk::Utils::Agents ();
use Thruk::Utils::Log qw/:all/;

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

=head2 get_config_objects

    get_config_objects($c, $data)

returns list of Monitoring::Objects for the host / services

=cut
sub get_config_objects {
    my($self, $c, $data) = @_;

    my $backend  = $data->{'backend'}  || die("missing backend");
    my $hostname = $data->{'hostname'} || die("missing hostname");
    my $ip       = $data->{'ip'}       // '';
    my $section  = $data->{'section'}  // '';
    my $password = $data->{'password'} // '';
    my $port     = $data->{'port'}     || 8443;

    my $objects = $c->{'obj_db'}->get_objects_by_name('host', $hostname);
    my $hostobj;
    if(!$objects || scalar @{$objects} == 0) {
        # create new one
        $hostobj = Monitoring::Config::Object->new( type    => 'host',
                                                   coretype => $c->{'obj_db'}->{'coretype'},
                                                );
        my $filename = $section ? sprintf('agents/%s/%s.cfg', $section, $hostname) : sprintf('agents/%s.cfg', $hostname);
        my $file = Thruk::Controller::conf::get_context_file($c, $hostobj, $filename);
        die("creating file failed") unless $file;
        $hostobj->set_file($file);
        $hostobj->set_uniq_id($c->{'obj_db'});
        $hostobj->{'conf'}->{'host_name'} = $hostname;
        $hostobj->{'conf'}->{'alias'}     = $hostname;
        $hostobj->{'conf'}->{'use'}       = "generic-host";
        $hostobj->{'conf'}->{'address'}   = $ip || $hostname;
    } else {
        $hostobj = $objects->[0];
    }

    my @list = ($hostobj);

    my $hostdata = $hostobj->{'conf'} // {};
    $hostdata->{'_AGENT'}          = 'snclient';
    $hostdata->{'_AGENT_PASSWORD'} = $password if($password ne ''); # only if changed
    $hostdata->{'_AGENT_SECTION'}  = $section;
    $hostdata->{'_AGENT_PORT'}     = $port;
    my $settings = $hostdata->{'_AGENT_CONFIG'} ? decode_json($hostdata->{'_AGENT_CONFIG'}) : {};

    if(!$c->{'obj_db'}->update_object($hostobj, $hostdata, "", 1)) {
        Thruk::Utils::set_message( $c, 'fail_message', "failed to save changes.");
        return $c->redirect_to($c->stash->{'url_prefix'}."cgi-bin/agents.cgi?action=edit&hostname=".$hostname."&backend=".$backend);
    }

    # save services
    my $checks = Thruk::Utils::Agents::get_services_checks($c, $hostname, $hostobj);
    my $checks_hash = Thruk::Base::array2hash($checks, "id");
    for my $id (sort keys %{$checks_hash}) {
        my $type = $c->req->parameters->{'check.'.$id} // 'off';
        my $chk  = $checks_hash->{$id};
        my $svc = $chk->{'_svc'};
        if(!$svc && $type eq 'on') {
            # create new one
            $svc = Monitoring::Config::Object->new( type     => 'service',
                                                    coretype => $c->{'obj_db'}->{'coretype'},
                                                    );
            my $filename = $section ? sprintf('agents/%s/%s.cfg', $section, $hostname) : sprintf('agents/%s.cfg', $hostname);
            my $file = Thruk::Controller::conf::get_context_file($c, $svc, $filename);
            die("creating file failed") unless $file;
            $svc->set_file($file);
            $svc->set_uniq_id($c->{'obj_db'});
        }

        if($type eq 'off') {
            # remove service
            $c->{'obj_db'}->delete_object($svc) if $svc;
            push @{$settings->{'disabled'}}, $id;
            $settings->{'disabled'} = Thruk::Base::array_uniq($settings->{'disabled'});
        }
        next unless $type eq 'on';

        # TODO: ARGS should be configurable somehow
        my $command = sprintf("check_snclient!-k -p '%s' -u 'https://%s:%s' %s",
                '$_HOSTAGENT_PASSWORD$',
                '$HOSTADDRESS$',
                '$_HOSTAGENT_PORT$',
                $chk->{'check'},
        );
        my $interval = 1; # TODO: make configurable
        if($chk->{'check'} eq 'inventory') {
            $command  = sprintf("check_thruk_agents!agents check inventory '%s'", $hostname);
            $interval = 60;
        }
        if($chk->{'args'}) {
            for my $arg (sort keys %{$chk->{'args'}}) {
                $command .= sprintf(" %s='%s'", $arg, $chk->{'args'}->{$arg});
            }
        }

        confess("no name") unless $chk->{'name'};

        $svc->{'conf'} = {
            'host_name'           => $hostname,
            'service_description' => $chk->{'name'},
            'use'                 => 'generic-service',
            'check_interval'      => $interval,
            'check_command'       => $command,
            '_AGENT_AUTO_CHECK'   => $chk->{'id'},
        };
        $svc->{'conf'}->{'parents'} = $chk->{'parent'} if $chk->{'parent'};

        push @list, $svc;
    }

    my $json = Cpanel::JSON::XS->new->canonical;
    $settings = $json->encode($settings);
    if($settings ne ($hostdata->{'_AGENT_CONFIG'}//"")) {
        $hostdata->{'_AGENT_CONFIG'} = $settings;
    }
    $hostobj->{'conf'} = $hostdata;

    return \@list;
}

##########################################################

=head2 get_services_checks

    get_services_checks($c, $hostname, $hostobj)

returns list of Monitoring::Objects for the host / services

=cut
sub get_services_checks {
    my($self, $c, $hostname, $hostobj) = @_;
    my $datafile = $c->config->{'tmp_path'}.'/agents/hosts/'.$hostname.'.json';
    my $checks = [];
    if(-r $datafile) {
        my $data = Thruk::Utils::IO::json_lock_retrieve($datafile);
        $checks = _extract_checks($data->{'inventory'}) if $data->{'inventory'};
    }
    return($checks);
}

##########################################################

=head2 get_inventory

    get_inventory($c, $c, $address, $hostname, $password, $port)

returns json structure from inventory api call.

=cut
sub get_inventory {
    my($self, $c, $address, $hostname, $password, $port) = @_;

    my $command  = "check_snclient";
    # TODO: make -k and such an option
    my $args     = sprintf("-k -p '%s' -r -u 'https://%s:%d/api/v1/inventory'",
        $password,
        ($address || $hostname),
        $port,
    );

    my $cmd = {
        command_name => 'check_snclient',
        command_line => '$USER1$/check_nsc_web $ARG1$',
    };
    Thruk::Utils::Agents::check_for_check_commands($c, [$cmd]);

    my $output = $c->{'obj_db'}->get_plugin_preview($c,
                                        $command,
                                        $args,
                                        $hostname,
                                        '',
                                    );
    if($output =~ m/^\{/mx) {
        my $data;
        eval {
            $data = decode_json($output);
        };
        my $err = $@;
        if($err) {
            die($err);
        }
        return $data;
    }
    die($output);
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
            push @{$checks}, { 'id' => 'net.'.Thruk::Utils::Agents::to_id($net->{'name'}), 'name' => 'net '.$net->{'name'}, check => 'check_network', args => { "name" => $net->{'name'} }, parent => 'agent version' };
        }
    }

    if($inventory->{'drivesize'}) {
        for my $drive (@{$inventory->{'drivesize'}}) {
            push @{$checks}, { 'id' => 'df.'.Thruk::Utils::Agents::to_id($drive->{'drive'}), 'name' => 'disk '.$drive->{'drive'}, check => 'check_drivesize', args => { "drive" => $drive->{'drive'} }, parent => 'agent version' };
        }
    }

    # TODO: process, services
    # TODO: move into modules

    return $checks;
}

##########################################################

1;
